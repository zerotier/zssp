use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;
use rand_core::OsRng;
use rand_core::RngCore;

use zssp::application::{
    AcceptAction, ApplicationLayer, IncomingSessionAction, RatchetState, RatchetStates, RatchetUpdate, RATCHET_SIZE,
};
use zssp::crypto::P384KeyPair;
use zssp::crypto_impl::*;
use zssp::result::ReceiveError;

const TEST_MTU: usize = 1500;

struct TestApplication {
    time: Instant,
}

/// We have to pool allocations or else variations in the speed of the memory allocator will bias
/// our performance stats.
struct PooledVec(Vec<u8>);
static POOL: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
fn alloc(b: &[u8]) -> PooledVec {
    let mut p = POOL.lock().unwrap();
    let mut v = p.pop().unwrap_or_default();
    v.extend(b);
    PooledVec(v)
}
impl Drop for PooledVec {
    fn drop(&mut self) {
        let mut p = POOL.lock().unwrap();
        let mut v = Vec::new();
        std::mem::swap(&mut self.0, &mut v);
        v.clear();
        p.push(v);
    }
}
impl AsMut<[u8]> for PooledVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl AsRef<[u8]> for PooledVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[allow(unused)]
impl DefaultCrypto for TestApplication {
    type SessionData = ();
    type LookupData = ();
    type IncomingPacketBuffer = PooledVec;
}

type Session = zssp::Session<TestApplication>;

#[allow(unused)]
impl ApplicationLayer<TestApplication> for &TestApplication {
    fn incoming_session(&mut self) -> IncomingSessionAction {
        IncomingSessionAction::Allow
    }

    fn hello_requires_recognized_ratchet(&mut self) -> bool {
        false
    }

    fn initiator_disallows_downgrade(&mut self, session: &Arc<Session>) -> bool {
        false
    }

    fn check_accept_session(
        &mut self,
        remote_static_key: &CrateP384PublicKey,
        identity: &[u8],
        _: Option<&()>,
    ) -> AcceptAction<TestApplication> {
        AcceptAction {
            session_data: Some(()),
            responder_disallows_downgrade: true,
            responder_silently_rejects: false,
        }
    }

    fn restore_by_fingerprint(
        &mut self,
        ratchet_fingerprint: &[u8; RATCHET_SIZE],
    ) -> Result<Option<(RatchetState, ())>, std::io::Error> {
        Ok(None)
    }

    fn restore_by_identity(
        &mut self,
        remote_static_key: &CrateP384PublicKey,
        session_data: &(),
        _: Option<&()>,
    ) -> Result<Option<RatchetStates>, std::io::Error> {
        Ok(None)
    }

    fn save_ratchet_state(
        &mut self,
        remote_static_key: &CrateP384PublicKey,
        session_data: &(),
        update_data: RatchetUpdate<'_>,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn time(&mut self) -> i64 {
        self.time.elapsed().as_millis() as i64
    }
}

#[allow(unused)]
fn alice_main(
    run: &AtomicBool,
    alice_app: &TestApplication,
    alice_out: mpsc::SyncSender<PooledVec>,
    alice_in: mpsc::Receiver<PooledVec>,
    alice_keypair: CrateP384KeyPair,
    bob_pubkey: CrateP384PublicKey,
) {
    let startup_time = std::time::Instant::now();
    let context = zssp::Context::<TestApplication>::new(alice_keypair, OsRng);
    let mut next_service = startup_time.elapsed().as_millis() as i64 + 500;
    let test_data = [1u8; TEST_MTU * 10];
    let mut up = false;
    let mut output_data = ArrayVec::<u8, 15000>::new();

    let result = context.open(
        alice_app,
        |b: &mut [u8]| alice_out.send(alloc(b)).is_ok(),
        TEST_MTU,
        bob_pubkey.clone(),
        (),
        &[],
    );
    let alice_session = Some(result.unwrap().0);
    println!("[alice] opening session");
    while run.load(Ordering::Relaxed) {
        let current_time = startup_time.elapsed().as_millis() as i64;
        loop {
            let pkt = alice_in.try_recv();
            if let Ok(pkt) = pkt {
                use zssp::result::ReceiveOk::*;
                use zssp::result::SessionEvent::*;
                output_data.clear();
                match context.receive(
                    alice_app,
                    |b: &mut [u8]| alice_out.send(alloc(b)).is_ok(),
                    TEST_MTU,
                    |_: &Arc<Session>| Some((|b: &mut [u8]| alice_out.send(alloc(b)).is_ok(), TEST_MTU)),
                    &0,
                    pkt,
                    &mut output_data,
                ) {
                    Ok((Associated(_, event), _)) => match event {
                        Established => {
                            up = true;
                        }
                        Data => {
                            assert!(!output_data.is_empty());
                            //println!("[alice] received {}", data.len());
                        }
                        Control => (),
                        _ => panic!(),
                    },
                    Ok(_) => {}
                    Err(e) => {
                        println!("[alice] ERROR {:?}", e);
                        if let ReceiveError::ByzantineFault(e) = e {
                            assert!(!e.unnatural)
                        }
                    }
                }
            } else {
                break;
            }
        }

        if up {
            context
                .send(
                    alice_session.as_ref().unwrap(),
                    |b: &mut [u8]| alice_out.send(alloc(b)).is_ok(),
                    &mut [0u8; TEST_MTU],
                    &test_data[..1400 + ((OsRng.next_u64() as usize) % (test_data.len() - 1400))],
                )
                .unwrap();
        } else {
            thread::sleep(Duration::from_millis(10));
        }

        if current_time >= next_service {
            next_service = current_time
                + context.service(alice_app, |_: &Arc<Session>| {
                    Some((|b: &mut [u8]| alice_out.send(alloc(b)).is_ok(), TEST_MTU))
                });
        }
    }
}

#[allow(unused)]
fn bob_main(
    run: &AtomicBool,
    bob_app: &TestApplication,
    bob_out: mpsc::SyncSender<PooledVec>,
    bob_in: mpsc::Receiver<PooledVec>,
    bob_keypair: CrateP384KeyPair,
) {
    let startup_time = std::time::Instant::now();
    let context = zssp::Context::<TestApplication>::new(bob_keypair, OsRng);
    let mut last_speed_metric = startup_time.elapsed().as_millis() as i64;
    let mut next_service = last_speed_metric + 500;
    let mut transferred = 0u64;
    let mut output_data = ArrayVec::<u8, 15000>::new();

    let mut bob_session = None;

    while run.load(Ordering::Relaxed) {
        let pkt = bob_in.recv_timeout(Duration::from_millis(100));
        let current_time = startup_time.elapsed().as_millis() as i64;

        if let Ok(pkt) = pkt {
            use zssp::result::ReceiveOk::*;
            use zssp::result::SessionEvent::*;
            output_data.clear();
            match context.receive(
                bob_app,
                |b: &mut [u8]| bob_out.send(alloc(b)).is_ok(),
                TEST_MTU,
                |_: &Arc<Session>| Some((|b: &mut [u8]| bob_out.send(alloc(b)).is_ok(), TEST_MTU)),
                &0,
                pkt,
                &mut output_data,
            ) {
                Ok((Associated(s, event), _)) => match event {
                    NewSession | NewDowngradedSession => {
                        println!("[bob] new session, took {}s", current_time as f32 / 1000.0);
                        let _ = bob_session.replace(s);
                    }
                    Data => {
                        assert!(!output_data.is_empty());
                        //println!("[bob] received {}", output_data.len());
                        transferred += output_data.len() as u64 * 2; // *2 because we are also sending this many bytes back
                        context
                            .send(
                                &s,
                                |b: &mut [u8]| bob_out.send(alloc(b)).is_ok(),
                                &mut [0u8; TEST_MTU],
                                &output_data,
                            )
                            .unwrap();
                    }
                    Control => (),
                    _ => panic!(),
                },
                Ok(_) => {}
                Err(e) => {
                    println!("[bob] ERROR {:?}", e);
                    if let ReceiveError::ByzantineFault(e) = e {
                        assert!(!e.unnatural)
                    }
                }
            }
        }

        let speed_metric_elapsed = current_time - last_speed_metric;
        if speed_metric_elapsed >= 10000 {
            last_speed_metric = current_time;
            println!(
                "[bob] throughput: {} MiB/sec (combined input and output)",
                ((transferred as f64) / 1048576.0) / ((speed_metric_elapsed as f64) / 1000.0)
            );
            transferred = 0;
        }

        if current_time >= next_service {
            next_service = current_time
                + context.service(bob_app, |_: &Arc<Session>| {
                    Some((|b: &mut [u8]| bob_out.send(alloc(b)).is_ok(), TEST_MTU))
                });
        }
    }
}

fn core(time: u64) {
    let run = &AtomicBool::new(true);

    let alice_keypair = CrateP384KeyPair::generate(&mut OsRng);
    let alice_app = TestApplication { time: Instant::now() };
    let bob_keypair = CrateP384KeyPair::generate(&mut OsRng);
    let bob_pubkey = bob_keypair.public_key();
    let bob_app = TestApplication { time: Instant::now() };

    let (alice_out, bob_in) = mpsc::sync_channel::<PooledVec>(256);
    let (bob_out, alice_in) = mpsc::sync_channel::<PooledVec>(256);

    thread::scope(|ts| {
        {
            let alice_out = alice_out.clone();
            ts.spawn(move || alice_main(run, &alice_app, alice_out, alice_in, alice_keypair, bob_pubkey));
        }
        ts.spawn(move || bob_main(run, &bob_app, bob_out, bob_in, bob_keypair));

        thread::sleep(Duration::from_secs(time));

        run.store(false, Ordering::SeqCst);
        println!("finished");
    });
}

fn main() {
    core(20)
}

#[test]
fn test_main() {
    core(2)
}
