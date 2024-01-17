/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::iter::ExactSizeIterator;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rand_core::OsRng;
use rand_core::RngCore;

use zssp_proto::application::{
    AcceptAction, ApplicationLayer, CompareAndSwap, CryptoLayer, RatchetState, RatchetStates, Settings, RATCHET_SIZE,
};
use zssp_proto::crypto::P384KeyPair;
use zssp_proto::crypto_impl::{
    Aes256Crate, AesGcmCrate, Kyber1024CratePrivateKey, P384CrateKeyPair, P384CratePublicKey, Sha512Crate,
};
use zssp_proto::Session;

const TEST_MTU: usize = 1500;

struct TestApplication {
    time: Instant,
    name: &'static str,
    ratchets: Ratchets,
}

struct Ratchets {
    rf_map: HashMap<[u8; RATCHET_SIZE], RatchetState>,
    peer_map: HashMap<u128, RatchetStates>,
}
impl Ratchets {
    fn new() -> Self {
        Self { rf_map: HashMap::new(), peer_map: HashMap::new() }
    }
}

impl CryptoLayer for TestApplication {
    const SETTINGS: Settings = Settings {
        initial_offer_timeout: Settings::INITIAL_OFFER_TIMEOUT_MS,
        rekey_timeout: 60 * 1000,
        rekey_after_time: 3000,
        rekey_time_max_jitter: 1000,
        rekey_after_key_uses: Settings::REKEY_AFTER_KEY_USES,
        resend_time: 250,
        fragment_assembly_timeout: Settings::FRAGMENT_ASSEMBLY_TIMEOUT_MS,
    };
    type Rng = OsRng;
    type Prp = Aes256Crate;
    type Aead = AesGcmCrate;
    type Hash = Sha512Crate;
    type PublicKey = P384CratePublicKey;
    type KeyPair = P384CrateKeyPair;
    type Kem = Kyber1024CratePrivateKey;

    type SessionData = u128;
}
#[allow(unused)]
impl ApplicationLayer<TestApplication> for &mut TestApplication {
    fn hello_requires_recognized_ratchet(&mut self) -> bool {
        false
    }

    fn initiator_disallows_downgrade(&mut self, session: &Arc<Session<TestApplication>>) -> bool {
        true
    }

    fn check_accept_session(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        identity: &[u8],
    ) -> AcceptAction<TestApplication> {
        AcceptAction {
            session_data: Some(1),
            responder_disallows_downgrade: true,
            responder_silently_rejects: false,
        }
    }

    fn restore_by_fingerprint(
        &mut self,
        ratchet_fingerprint: &[u8; RATCHET_SIZE],
    ) -> Result<Option<RatchetState>, std::io::Error> {
        Ok(self.ratchets.rf_map.get(ratchet_fingerprint).cloned())
    }

    fn restore_by_identity(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        session_data: &u128,
    ) -> Result<Option<RatchetStates>, std::io::Error> {
        Ok(self.ratchets.peer_map.get(session_data).cloned())
    }

    fn save_ratchet_state(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        session_data: &u128,
        update_data: CompareAndSwap<'_>,
    ) -> Result<bool, std::io::Error> {
        let mut ratchets = &mut self.ratchets;
        match ratchets.peer_map.entry(*session_data) {
            Entry::Occupied(mut entry) => {
                if update_data.compare(&entry.get()) {
                    entry.insert(update_data.to_new_states());
                } else {
                    return Ok(false);
                }
            }
            Entry::Vacant(entry) => {
                if update_data.cur_is_initial_states() {
                    entry.insert(update_data.to_new_states());
                } else {
                    return Ok(false);
                }
            }
        }

        if let Some(rf) = update_data.added_fingerprint() {
            ratchets.rf_map.insert(*rf, update_data.new_state1.clone());
            println!("[{}] new ratchet #{}", self.name, update_data.new_state1.chain_len());
        }
        if let Some(rf) = update_data.deleted_fingerprint1() {
            ratchets.rf_map.remove(rf);
        }
        if let Some(rf) = update_data.deleted_fingerprint2() {
            ratchets.rf_map.remove(rf);
        }
        Ok(true)
    }

    fn time(&mut self) -> i64 {
        self.time.elapsed().as_millis() as i64
    }

    fn event_log(&mut self, event: zssp_proto::LogEvent<TestApplication>) {
        println!(">[{}] {:?}", self.name, event);
    }
}

fn alice_main(
    run: &AtomicBool,
    packet_success_rate: u32,
    mut alice_app: TestApplication,
    alice_out: mpsc::SyncSender<Vec<u8>>,
    alice_in: mpsc::Receiver<Vec<u8>>,
    recursive_out: mpsc::SyncSender<Vec<u8>>,
    alice_keypair: P384CrateKeyPair,
    bob_pubkey: P384CratePublicKey,
) {
    let startup_time = std::time::Instant::now();
    let mut context = zssp_proto::Context::<TestApplication>::new(alice_keypair, OsRng);
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
                        &mut alice_app,
                        |b| alice_out.send(b).is_ok(),
                        TEST_MTU,
                        bob_pubkey,
                        0,
                        Vec::new(),
                    )
                    .unwrap(),
            );
            println!("[alice] opening session");
        }
        let current_time = startup_time.elapsed().as_millis() as i64;
        loop {
            let pkt = alice_in.try_recv();
            if let Ok(pkt) = pkt {
                if OsRng.next_u32() <= packet_success_rate {
                    use zssp_proto::result::ReceiveError::*;
                    use zssp_proto::result::ReceiveOk::*;
                    use zssp_proto::result::SessionEvent::*;
                    match context.receive(
                        &mut alice_app,
                        |b| alice_out.send(b).is_ok(),
                        TEST_MTU,
                        |_| Some((|b| alice_out.send(b).is_ok(), TEST_MTU)),
                        &0,
                        pkt,
                    ) {
                        Ok(Unassociated) => {
                            //println!("[alice] ok");
                        }
                        Ok(Session(_, event)) => match event {
                            Established => {
                                up = true;
                            }
                            Data(data) => {
                                assert!(!data.is_empty());
                                //println!("[alice] received {}", data.len());
                            }
                            Control => (),
                            _ => panic!(),
                        },
                        Err(e) => {
                            println!("[alice] ERROR {:?}", e);
                            if let ByzantineFault(e) = e {
                                assert!(!e.unnatural())
                            }
                        }
                    }
                } else if OsRng.next_u32() | 1 > 0 {
                    let _ = recursive_out.send(pkt);
                }
            } else {
                break;
            }
        }

        if up {
            context
                .send(
                    alice_session.as_ref().unwrap(),
                    |b| alice_out.send(b).is_ok(),
                    TEST_MTU,
                    test_data[..1400 + ((OsRng.next_u64() as usize) % (test_data.len() - 1400))].to_vec(),
                )
                .unwrap();
        } else {
            thread::sleep(Duration::from_millis(10));
        }
        // TODO: we need to more comprehensively test if re-opening the session works
        if OsRng.next_u32() <= ((u32::MAX as f64) * 0.000005) as u32 {
            alice_session = None;
        }

        if current_time >= next_service {
            next_service =
                current_time + context.service(&mut alice_app, |_| Some((|b| alice_out.send(b).is_ok(), TEST_MTU)));
        }
    }
}

fn bob_main(
    run: &AtomicBool,
    packet_success_rate: u32,
    mut bob_app: TestApplication,
    bob_out: mpsc::SyncSender<Vec<u8>>,
    bob_in: mpsc::Receiver<Vec<u8>>,
    recursive_out: mpsc::SyncSender<Vec<u8>>,
    bob_keypair: P384CrateKeyPair,
) {
    let startup_time = std::time::Instant::now();
    let mut context = zssp_proto::Context::<TestApplication>::new(bob_keypair, OsRng);
    let mut last_speed_metric = startup_time.elapsed().as_millis() as i64;
    let mut next_service = last_speed_metric + 500;
    let mut transferred = 0u64;

    let mut bob_session = None;

    while run.load(Ordering::Relaxed) {
        let pkt = bob_in.recv_timeout(Duration::from_millis(100));
        let current_time = startup_time.elapsed().as_millis() as i64;

        if let Ok(pkt) = pkt {
            if OsRng.next_u32() <= packet_success_rate {
                use zssp_proto::result::ReceiveError::*;
                use zssp_proto::result::ReceiveOk::*;
                use zssp_proto::result::SessionEvent::*;
                match context.receive(
                    &mut bob_app,
                    |b| bob_out.send(b).is_ok(),
                    TEST_MTU,
                    |_| Some((|b| bob_out.send(b).is_ok(), TEST_MTU)),
                    &0,
                    pkt,
                ) {
                    Ok(Unassociated) => {}
                    Ok(Session(s, event)) => match event {
                        NewSession | NewDowngradedSession => {
                            println!("[bob] new session, took {}s", current_time as f32 / 1000.0);
                            let _ = bob_session.replace(s);
                        }
                        Data(data) => {
                            assert!(!data.is_empty());
                            //println!("[bob] received {}", data.len());
                            transferred += data.len() as u64 * 2; // *2 because we are also sending this many bytes back
                            context.send(&s, |b| bob_out.send(b).is_ok(), TEST_MTU, data).unwrap();
                        }
                        Control => (),
                        _ => panic!(),
                    },
                    Err(e) => {
                        println!("[bob] ERROR {:?}", e);
                        if let ByzantineFault(e) = e {
                            assert!(!e.unnatural())
                        }
                    }
                }
            } else if OsRng.next_u32() | 1 > 0 {
                let _ = recursive_out.try_send(pkt);
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
            next_service =
                current_time + context.service(&mut bob_app, |_| Some((|b| bob_out.send(b).is_ok(), TEST_MTU)));
        }
    }
}

fn core(time: u64, packet_success_rate: u32) {
    let run = &AtomicBool::new(true);

    let alice_keypair = P384CrateKeyPair::generate(&mut OsRng);
    let alice_app = TestApplication {
        time: Instant::now(),
        name: "alice",
        ratchets: Ratchets::new(),
    };
    let bob_keypair = P384CrateKeyPair::generate(&mut OsRng);
    let bob_pubkey = bob_keypair.public_key();
    let bob_app = TestApplication { time: Instant::now(), name: "bob", ratchets: Ratchets::new() };

    let (alice_out, bob_in) = mpsc::sync_channel::<Vec<u8>>(256);
    let (bob_out, alice_in) = mpsc::sync_channel::<Vec<u8>>(256);

    thread::scope(|ts| {
        {
            let alice_out = alice_out.clone();
            let bob_out = bob_out.clone();
            ts.spawn(move || {
                alice_main(
                    run,
                    packet_success_rate,
                    alice_app,
                    alice_out,
                    alice_in,
                    bob_out,
                    alice_keypair,
                    bob_pubkey,
                )
            });
        }
        ts.spawn(move || {
            bob_main(
                run,
                packet_success_rate,
                bob_app,
                bob_out,
                bob_in,
                alice_out,
                bob_keypair,
            )
        });

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
