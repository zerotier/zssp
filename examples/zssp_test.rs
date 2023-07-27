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
use zerotier_crypto::random;
use zssp::{IncomingSessionAction, LogEvent, RatchetState, Session, RATCHET_SIZE};

const TEST_MTU: usize = 1500;

struct TestApplication {
    name: &'static str,
    ratchets: Mutex<[RatchetState; 2]>,
}

impl zssp::ApplicationLayer for TestApplication {
    type PrpEnc = zerotier_crypto::aes::Aes<true>;
    type PrpDec = zerotier_crypto::aes::Aes<false>;

    type AeadEnc = zerotier_crypto::aes::AesGcm<true>;
    type AeadDec = zerotier_crypto::aes::AesGcm<false>;

    type Hash = zerotier_crypto::hash::SHA512;
    type HmacHash = zerotier_crypto::hash::HMACSHA512;

    type KeyPair = zerotier_crypto::p384::P384KeyPair;
    type PublicKey = zerotier_crypto::p384::P384PublicKey;

    type Rng = zerotier_crypto::random::SecureRandom;
    type IoError = ();

    const REKEY_AFTER_TIME_MS: i64 = 1500;
    const REKEY_AFTER_TIME_MAX_JITTER_MS: i64 = 1000;

    const RETRY_INTERVAL_MS: i64 = 30;
    const INITIAL_OFFER_TIMEOUT_MS: i64 = 300;
    const EXPIRATION_TIMEOUT_MS: i64 = 10000;

    type Data = ();
    type IncomingPacketBuffer = Vec<u8>;
    type LocalIdentityBlob = [u8; 0];

    fn save_ratchet_state(
        &self,
        _: &P384PublicKey,
        _: &Self::Data,
        pre_ratchet_states: [&RatchetState; 2],
        new_ratchet_states: [&RatchetState; 2],
        _: i64,
    ) -> Result<(), ()> {
        let mut ratchets = self.ratchets.lock().unwrap();
        ratchets[0] = new_ratchet_states[0].clone();
        ratchets[1] = new_ratchet_states[1].clone();
        let chain_len = new_ratchet_states[0].chain_len();
        if chain_len > pre_ratchet_states[0].chain_len() {
            println!("[{}] new ratchet #{}", self.name, chain_len);
        }
        Ok(())
    }
    fn restore_by_fingerprint(&self, ratchet_fingerprint: &[u8; RATCHET_SIZE], _: i64) -> Result<RatchetState, ()> {
        let ratchets = self.ratchets.lock().unwrap();
        for rs in ratchets.iter() {
            if rs.nonempty().map_or(false, |rs| rs.fingerprint.eq_bytes(ratchet_fingerprint)) {
                return Ok(rs.clone());
            }
        }
        Ok(RatchetState::Null)
    }
    fn restore_by_identity(&self, _: &Self::PublicKey, _: &Self::Data, _: i64) -> Result<[RatchetState; 2], ()> {
        Ok(self.ratchets.lock().unwrap().clone())
    }
    fn hello_requires_recognized_ratchet(&self, _: i64) -> bool {
        false
    }
    fn initiator_disallows_downgrade(&self, _: &Arc<Session<Self>>, _: i64) -> bool {
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
    alice_out: mpsc::SyncSender<Vec<u8>>,
    alice_in: mpsc::Receiver<Vec<u8>>,
    alice_keypair: P384KeyPair,
    bob_pubkey: P384PublicKey,
) {
    let startup_time = std::time::Instant::now();
    let context = zssp::Context::<TestApplication>::new(alice_keypair, random::SecureRandom);
    let mut data_buf = [0u8; 65536];
    let mut next_service = startup_time.elapsed().as_millis() as i64 + 500;
    let test_data = [1u8; TEST_MTU * 10];
    let mut up = false;
    let mut alice_session = None;

    while run.load(Ordering::Relaxed) {
        if alice_session.is_none() {
            up = false;
            alice_session = Some(
                context
                    .open(
                        alice_app,
                        |b| alice_out.send(b.to_vec()).is_ok(),
                        TEST_MTU,
                        bob_pubkey.clone(),
                        (),
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
                            Established => {
                                up = true;
                            }
                            Data(data) => {
                                assert!(!data.is_empty());
                                //println!("[alice] received {}", data.len());
                            }
                            NewSession => panic!(),
                            Rejected => panic!(),
                            Control => (),
                        },
                        Ok(zssp::ReceiveResult::Rejected) => panic!(),
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
        if (random::xorshift64_random() as u32) <= ((u32::MAX as f64) * 0.0000025) as u32 {
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
    bob_app: &TestApplication,
    bob_out: mpsc::SyncSender<Vec<u8>>,
    bob_in: mpsc::Receiver<Vec<u8>>,
    bob_keypair: P384KeyPair,
) {
    let startup_time = std::time::Instant::now();
    let context = zssp::Context::<TestApplication>::new(bob_keypair, random::SecureRandom);
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
                    |_, _, _| (Some((true, ())), false),
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
                        NewSession => {
                            println!("[bob] new session, took {}s", current_time as f32 / 1000.0);
                            let _ = bob_session.replace(s);
                        }
                        Data(data) => {
                            assert!(!data.is_empty());
                            //println!("[bob] received {}", data.len());
                            context
                                .send(&s, |b| bob_out.send(b.to_vec()).is_ok(), &mut data_buf_2, data.as_mut(), current_time)
                                .unwrap();
                            transferred += data.len() as u64 * 2; // *2 because we are also sending this many bytes back
                        }
                        Established => panic!(),
                        Rejected => panic!(),
                        Control => (),
                    },
                    Ok(zssp::ReceiveResult::Rejected) => panic!(),
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

fn core(time: u64, packet_success_rate: u32) {
    let run = &AtomicBool::new(true);

    let shared_ratchet_states = RatchetState::new_initial_states();
    let alice_keypair = P384KeyPair::generate();
    let alice_app = TestApplication {
        name: "alice",
        ratchets: Mutex::new(shared_ratchet_states.clone()),
    };
    let bob_keypair = P384KeyPair::generate();
    let bob_pubkey = bob_keypair.to_public_key();
    let bob_app = TestApplication { name: "bob", ratchets: Mutex::new(shared_ratchet_states) };

    let (alice_out, bob_in) = mpsc::sync_channel::<Vec<u8>>(256);
    let (bob_out, alice_in) = mpsc::sync_channel::<Vec<u8>>(256);

    thread::scope(|ts| {
        ts.spawn(move || alice_main(run, packet_success_rate, &alice_app, alice_out, alice_in, alice_keypair, bob_pubkey));
        ts.spawn(move || bob_main(run, packet_success_rate, &bob_app, bob_out, bob_in, bob_keypair));

        thread::sleep(Duration::from_secs(time));

        run.store(false, Ordering::SeqCst);
        println!("finished");
    });
}

fn main() {
    let args = std::env::args();
    let packet_success_rate = if args.len() <= 1 {
        let default_success_rate = 1.0;
        ((u32::MAX as f64) * default_success_rate) as u32
    } else {
        ((u32::MAX as f64) * f64::from_str(args.last().unwrap().as_str()).unwrap()) as u32
    };

    core(60 * 60, packet_success_rate)
}

#[test]
fn test_main() {
    core(2, u32::MAX / 2)
}
