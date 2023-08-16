use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;
use rand_core::OsRng;
use rand_core::RngCore;

use zssp::application::{
    AcceptAction, ApplicationLayer, CryptoLayer, IncomingSessionAction, RatchetState, RatchetStates, RatchetUpdate,
    RATCHET_SIZE,
};
use zssp::crypto::P384KeyPair;
use zssp::crypto_impl::*;
use zssp::Session;

const TEST_MTU: usize = 1500;

struct TestApplication {
    time: Instant,
}

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
impl CryptoLayer for TestApplication {
    type Rng = OsRng;
    type PrpEnc = Aes256OpenSSLEnc;
    type PrpDec = Aes256OpenSSLDec;
    type Aead = AesGcmOpenSSL;
    type AeadPool = AesGcmOpenSSLPool;
    type Hash = Sha512Crate;
    type Hmac = HmacSha512Crate;
    type PublicKey = P384CratePublicKey;
    type KeyPair = P384CrateKeyPair;
    type Kem = RustKyber1024PrivateKey;

    type SessionData = ();

    type IncomingPacketBuffer = PooledVec;
}
#[allow(unused)]
impl ApplicationLayer for &TestApplication {
    type Crypto = TestApplication;

    fn incoming_session(&mut self) -> IncomingSessionAction {
        IncomingSessionAction::Allow
    }

    fn hello_requires_recognized_ratchet(&mut self) -> bool {
        false
    }

    fn initiator_disallows_downgrade(&mut self, session: &Arc<Session<TestApplication>>) -> bool {
        false
    }

    fn check_accept_session(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        identity: &[u8],
    ) -> AcceptAction<TestApplication> {
        AcceptAction {
            session_data: Some(()),
            responder_disallows_downgrade: true,
            responder_silently_rejects: false,
        }
    }

    fn restore_by_fingerprint(&mut self, ratchet_fingerprint: &[u8; RATCHET_SIZE]) -> Result<Option<RatchetState>, ()> {
        Ok(None)
    }

    fn restore_by_identity(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        session_data: &(),
    ) -> Result<Option<RatchetStates>, ()> {
        Ok(None)
    }

    fn save_ratchet_state(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        session_data: &(),
        update_data: RatchetUpdate<'_>,
    ) -> Result<(), ()> {
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
    alice_keypair: P384CrateKeyPair,
    bob_pubkey: P384CratePublicKey,
) {
    let startup_time = std::time::Instant::now();
    let context = zssp::Context::<TestApplication>::new(alice_keypair, OsRng);
    let mut next_service = startup_time.elapsed().as_millis() as i64 + 500;
    let test_data = [1u8; TEST_MTU * 10];
    let mut up = false;
    let mut output_data = ArrayVec::<u8, 15000>::new();

    let alice_session = Some(
        context
            .open(
                alice_app,
                |b| alice_out.send(alloc(b)).is_ok(),
                TEST_MTU,
                bob_pubkey.clone(),
                (),
                &[],
            )
            .unwrap(),
    );
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
                    |b| alice_out.send(alloc(b)).is_ok(),
                    TEST_MTU,
                    |_| Some((|b: &mut [u8]| alice_out.send(alloc(b)).is_ok(), TEST_MTU)),
                    &0,
                    pkt,
                    &mut output_data,
                ) {
                    Ok(Unassociated) => {
                        //println!("[alice] ok");
                    }
                    Ok(Session(_, event)) => match event {
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
                    Err(e) => {
                        //println!("[alice] ERROR {:?}", e);
                        //if let ReceiveError::ByzantineFault { unnatural, .. } = e {
                        //    assert!(!unnatural)
                        //}
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
                    |b| alice_out.send(alloc(b)).is_ok(),
                    &mut [0u8; TEST_MTU],
                    &test_data[..1400 + ((OsRng.next_u64() as usize) % (test_data.len() - 1400))],
                )
                .unwrap();
        } else {
            thread::sleep(Duration::from_millis(10));
        }

        if current_time >= next_service {
            next_service = current_time
                + context.service(alice_app, |_| {
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
    bob_keypair: P384CrateKeyPair,
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
                |b| bob_out.send(alloc(b)).is_ok(),
                TEST_MTU,
                |_| Some((|b: &mut [u8]| bob_out.send(alloc(b)).is_ok(), TEST_MTU)),
                &0,
                pkt,
                &mut output_data,
            ) {
                Ok(Unassociated) => {}
                Ok(Session(s, event)) => match event {
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
                                |b| bob_out.send(alloc(b)).is_ok(),
                                &mut [0u8; TEST_MTU],
                                &output_data,
                            )
                            .unwrap();
                    }
                    Control => (),
                    _ => panic!(),
                },
                Err(e) => {
                    //println!("[bob] ERROR {:?}", e);
                    //if let ReceiveError::ByzantineFault { unnatural, .. } = e {
                    //    assert!(!unnatural)
                    //}
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
                + context.service(bob_app, |_| {
                    Some((|b: &mut [u8]| bob_out.send(alloc(b)).is_ok(), TEST_MTU))
                });
        }
    }
}

fn core(time: u64) {
    let run = &AtomicBool::new(true);

    let alice_keypair = P384CrateKeyPair::generate(&mut OsRng);
    let alice_app = TestApplication { time: Instant::now() };
    let bob_keypair = P384CrateKeyPair::generate(&mut OsRng);
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
