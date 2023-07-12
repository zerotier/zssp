/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use std::iter::ExactSizeIterator;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use zerotier_crypto::p384::{P384KeyPair, P384PublicKey};
use zerotier_crypto::{random, secure_eq};
use zssp::{
    AcceptSessionAction, GetRatchetAction, IncomingSessionAction, LogEvent, SaveRatchetAction, Session, RATCHET_FINGERPRINT_SIZE, RATCHET_KEY_SIZE,
};

const TEST_MTU: usize = 1500;

struct TestApplication {
    name: &'static str,
    identity_key: P384KeyPair,
    ratchets: Mutex<(u64, [(u64, [u8; RATCHET_FINGERPRINT_SIZE], [u8; RATCHET_KEY_SIZE]); 2])>,
}

impl zssp::ApplicationLayer for TestApplication {
    const REKEY_AFTER_TIME_MS: i64 = 4000;
    const REKEY_AFTER_TIME_MAX_JITTER_MS: i64 = 2000;

    const RETRY_INTERVAL_MS: i64 = 250;
    const INITIAL_OFFER_TIMEOUT_MS: i64 = 2000;
    const EXPIRATION_TIMEOUT_MS: i64 = 60000;

    type Data = ();
    type IncomingPacketBuffer = Vec<u8>;
    type LocalIdentityBlob = [u8; 0];

    fn local_s_keypair(&self) -> &P384KeyPair {
        &self.identity_key
    }
    fn save_ratchet_state(
        &self,
        _: &P384PublicKey,
        _: &Self::Data,
        action: SaveRatchetAction,
        ratchet_number: u64,
        ratchet_fingerprint: &[u8; RATCHET_FINGERPRINT_SIZE],
        ratchet_key: &[u8; RATCHET_KEY_SIZE],
        _: i64,
    ) -> Result<(), ()> {
        let latest_idx = ratchet_number as usize % 2;
        let mut ratchets = self.ratchets.lock().unwrap();
        if action.save_latest() {
            ratchets.1[latest_idx] = (ratchet_number, *ratchet_fingerprint, *ratchet_key);
        }
        if action.confirm_latest() {
            ratchets.0 = ratchet_number;
        }
        if action.delete_previous() {
            ratchets.1[latest_idx ^ 1] = (0, [0; RATCHET_FINGERPRINT_SIZE], [0; RATCHET_KEY_SIZE]);
        }
        Ok(())
    }
    fn lookup_ratchet(&self, ratchet_fingerprint: &[u8; RATCHET_FINGERPRINT_SIZE], _: i64) -> Result<GetRatchetAction, ()> {
        let r = self.ratchets.lock().unwrap();
        for state in &r.1 {
            if secure_eq(&state.1, ratchet_fingerprint) {
                return Ok(GetRatchetAction::Found(state.0, state.2));
            }
        }
        panic!()
    }
    fn allow_zero_ratchet(&self, _: i64) -> bool {
        true
    }
    fn allow_downgrade(&self, _: &Arc<Session<Self>>, _: i64) -> bool {
        true
    }
    fn event_log(&self, event: LogEvent<'_, Self>, _: i64) {
        println!("> [{}] {:?}", self.name, event);
        match event {
            LogEvent::ServiceKKTimeout(_) => panic!(),
            _ => (),
        }
    }
}

fn alice_main(
    run: &AtomicBool,
    packet_success_rate: u32,
    alice_app: &TestApplication,
    bob_app: &TestApplication,
    alice_out: mpsc::SyncSender<Vec<u8>>,
    alice_in: mpsc::Receiver<Vec<u8>>,
) {
    let startup_time = std::time::Instant::now();
    let context = zssp::Context::<TestApplication>::new();
    let mut data_buf = [0u8; 65536];
    let mut next_service = startup_time.elapsed().as_millis() as i64 + 500;
    let test_data = [1u8; TEST_MTU * 10];
    let mut up = false;
    let mut alice_session = None;

    while run.load(Ordering::Relaxed) {
        if alice_session.is_none() {
            up = false;
            let ratchets = alice_app.ratchets.lock().unwrap();
            let ratchet_state = ratchets.1[ratchets.0 as usize % 2];
            alice_session = Some(
                context
                    .open(
                        alice_app,
                        |b| alice_out.send(b.to_vec()).is_ok(),
                        TEST_MTU,
                        bob_app.identity_key.to_public_key(),
                        (),
                        Some(ratchet_state),
                        [],
                        startup_time.elapsed().as_millis() as i64,
                    )
                    .unwrap(),
            );
            println!("[alice] opening session");
        }
        let current_time = startup_time.elapsed().as_millis() as i64;
        loop {
            let pkt = alice_in.try_recv();
            if let Ok(pkt) = pkt {
                if (random::xorshift64_random() as u32) <= packet_success_rate {
                    use zssp::SessionEvent::*;
                    match context.receive(
                        alice_app,
                        || panic!(),
                        |_, _, _| panic!(),
                        |b| alice_out.send(b.to_vec()).is_ok(),
                        TEST_MTU,
                        |_| Some((|b: &mut [u8]| alice_out.send(b.to_vec()).is_ok(), TEST_MTU)),
                        &0,
                        &mut data_buf,
                        pkt,
                        current_time,
                    ) {
                        Ok(zssp::ReceiveResult::Unassociated) => {
                            //println!("[alice] ok");
                        }
                        Ok(zssp::ReceiveResult::Session(_, event)) => match event {
                            Established(ratchet_number) => {
                                up = true;
                                println!("[alice] new ratchet key #{}", ratchet_number);
                            }
                            Data(data) => {
                                assert!(!data.is_empty());
                                //println!("[alice] received {}", data.len());
                            }
                            NewSession(..) => panic!(),
                            Ratchet(ratchet_number) => {
                                println!("[alice] new ratchet key #{}", ratchet_number);
                            }
                            Rejected => panic!(),
                            Control => (),
                        },
                        Ok(zssp::ReceiveResult::Rejected) => {}
                        Err(e) => {
                            println!("[alice] ERROR {:?}", e);
                            if let zssp::error::ReceiveError::ByzantineFault { is_naturally_occurring, .. } = e {
                                assert!(is_naturally_occurring)
                            }
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
                    |b| alice_out.send(b.to_vec()).is_ok(),
                    &mut data_buf[..TEST_MTU],
                    &test_data[..1400 + ((random::xorshift64_random() as usize) % (test_data.len() - 1400))],
                    current_time,
                )
                .unwrap();
        } else {
            thread::sleep(Duration::from_millis(10));
        }
        // TODO: we need to more comprehensively test if re-opening the session works
        if (random::xorshift64_random() as u32) <= ((u32::MAX as f64) * 0.00000025) as u32 {
            alice_session = None;
        }

        if current_time >= next_service {
            next_service = current_time
                + context.service(
                    alice_app,
                    |_| Some((|b: &mut [u8]| alice_out.send(b.to_vec()).is_ok(), TEST_MTU)),
                    current_time,
                );
        }
    }
}

fn bob_main(
    run: &AtomicBool,
    packet_success_rate: u32,
    _alice_app: &TestApplication,
    bob_app: &TestApplication,
    bob_out: mpsc::SyncSender<Vec<u8>>,
    bob_in: mpsc::Receiver<Vec<u8>>,
) {
    let startup_time = std::time::Instant::now();
    let context = zssp::Context::<TestApplication>::new();
    let mut data_buf = [0u8; 65536];
    let mut data_buf_2 = [0u8; TEST_MTU];
    let mut last_speed_metric = startup_time.elapsed().as_millis() as i64;
    let mut next_service = last_speed_metric + 500;
    let mut transferred = 0u64;

    let mut bob_session = None;

    while run.load(Ordering::Relaxed) {
        let pkt = bob_in.recv_timeout(Duration::from_millis(100));
        let current_time = startup_time.elapsed().as_millis() as i64;

        if let Ok(pkt) = pkt {
            if (random::xorshift64_random() as u32) <= packet_success_rate {
                use zssp::SessionEvent::*;
                match context.receive(
                    bob_app,
                    || IncomingSessionAction::Allow,
                    |_, _, _| AcceptSessionAction::Accept(()),
                    |b| bob_out.send(b.to_vec()).is_ok(),
                    TEST_MTU,
                    |_| Some((|b: &mut [u8]| bob_out.send(b.to_vec()).is_ok(), TEST_MTU)),
                    &0,
                    &mut data_buf,
                    pkt,
                    current_time,
                ) {
                    Ok(zssp::ReceiveResult::Unassociated) => {}
                    Ok(zssp::ReceiveResult::Session(s, event)) => match event {
                        NewSession(ratchet_number) => {
                            println!("[bob] new session, took {}s", current_time as f32 / 1000.0);
                            let _ = bob_session.replace(s);
                            println!("[bob] new ratchet key #{}", ratchet_number);
                        }
                        Data(data) => {
                            assert!(!data.is_empty());
                            //println!("[bob] received {}", data.len());
                            context
                                .send(&s, |b| bob_out.send(b.to_vec()).is_ok(), &mut data_buf_2, data.as_mut(), current_time)
                                .unwrap();
                            transferred += data.len() as u64 * 2; // *2 because we are also sending this many bytes back
                        }
                        Established(_) => panic!(),
                        Rejected => panic!(),
                        Ratchet(ratchet_number) => {
                            println!("[bob] new ratchet key #{}", ratchet_number);
                        }
                        Control => (),
                    },
                    Ok(zssp::ReceiveResult::Rejected) => {}
                    Err(e) => {
                        println!("[bob] ERROR {:?}", e);
                        if let zssp::error::ReceiveError::ByzantineFault { is_naturally_occurring, .. } = e {
                            assert!(is_naturally_occurring)
                        }
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
                + context.service(
                    bob_app,
                    |_| Some((|b: &mut [u8]| bob_out.send(b.to_vec()).is_ok(), TEST_MTU)),
                    current_time,
                );
        }
    }
}

fn main() {
    let run = AtomicBool::new(true);

    let alice_app = TestApplication {
        name: "alice",
        identity_key: P384KeyPair::generate(),
        ratchets: Mutex::new((0, std::array::from_fn(|_| (0, [0u8; RATCHET_FINGERPRINT_SIZE], [0u8; RATCHET_KEY_SIZE])))),
    };
    let bob_app = TestApplication {
        name: "bob",
        identity_key: P384KeyPair::generate(),
        ratchets: Mutex::new((0, std::array::from_fn(|_| (0, [0u8; RATCHET_FINGERPRINT_SIZE], [0u8; RATCHET_KEY_SIZE])))),
    };

    let (alice_out, bob_in) = mpsc::sync_channel::<Vec<u8>>(256);
    let (bob_out, alice_in) = mpsc::sync_channel::<Vec<u8>>(256);

    let args = std::env::args();
    let packet_success_rate = if args.len() <= 1 {
        let default_success_rate = 1.0;
        ((u32::MAX as f64) * default_success_rate) as u32
    } else {
        ((u32::MAX as f64) * f64::from_str(args.last().unwrap().as_str()).unwrap()) as u32
    };

    thread::scope(|ts| {
        ts.spawn(|| alice_main(&run, packet_success_rate, &alice_app, &bob_app, alice_out, alice_in));
        ts.spawn(|| bob_main(&run, packet_success_rate, &alice_app, &bob_app, bob_out, bob_in));

        thread::sleep(Duration::from_secs(60 * 60));

        run.store(false, Ordering::SeqCst);
        println!("finished");
    });
}
