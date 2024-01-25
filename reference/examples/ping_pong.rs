/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https://mozilla.org/MPL/2.0/.
*
* (c) ZeroTier, Inc.
* https://www.zerotier.com/
*/

use std::cell::RefCell;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Instant;

use zssp_proto::application::{
    AcceptAction, ApplicationLayer, CompareAndSwap, CryptoLayer, RatchetState, RatchetStates, RATCHET_SIZE,
};
use zssp_proto::crypto::{rand_core::OsRng, P384KeyPair};
use zssp_proto::crypto_impl::{
    Aes256Crate, AesGcmCrate, Kyber1024CratePrivateKey, P384CrateKeyPair, P384CratePublicKey, Sha512Crate,
};
use zssp_proto::{Context, Session};

/// The MTU can go as low as 128 bytes, and it does not have to be constant either!
const TEST_MTU: usize = 512;

struct MyApp {
    time: Instant,
    remote_peers_session: Option<Arc<Session<Self>>>,
}

/// We specify which crypto implementations to use here, you can use those provided by the
/// `crypto_impl` module or provide your own.
impl CryptoLayer for MyApp {
    type Rng = OsRng;
    type Prp = Aes256Crate;
    type Aead = AesGcmCrate;
    type Hash = Sha512Crate;
    type PublicKey = P384CratePublicKey;
    type KeyPair = P384CrateKeyPair;
    type Kem = Kyber1024CratePrivateKey;

    type SessionData = ();
}
/// In this example for simplicity we won't be hooking up ratchet keys to a filesystem backend.
/// They are dropped and peers ignore if they are missing.
#[allow(unused)]
impl ApplicationLayer<MyApp> for &mut MyApp {
    fn hello_requires_recognized_ratchet(&mut self) -> bool {
        false
    }

    fn initiator_disallows_downgrade(&mut self, session: &Arc<Session<MyApp>>) -> bool {
        false
    }

    fn check_accept_session(&mut self, remote_static_key: &P384CratePublicKey, identity: &[u8]) -> AcceptAction<MyApp> {
        self.remote_peers_session.take();
        AcceptAction {
            session_data: Some(()),
            responder_disallows_downgrade: false,
            responder_silently_rejects: false,
        }
    }

    fn restore_by_fingerprint(
        &mut self,
        ratchet_fingerprint: &[u8; RATCHET_SIZE],
    ) -> Result<Option<RatchetState>, std::io::Error> {
        Ok(None)
    }

    fn restore_by_identity(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        session_data: &(),
    ) -> Result<Option<RatchetStates>, std::io::Error> {
        Ok(None)
    }

    fn save_ratchet_state(
        &mut self,
        remote_static_key: &P384CratePublicKey,
        session_data: &(),
        update_data: CompareAndSwap<'_>,
    ) -> Result<bool, std::io::Error> {
        Ok(true)
    }

    fn time(&mut self) -> i64 {
        self.time.elapsed().as_millis() as i64
    }
}

/// In this example protocol the two peers simply bounce the message "ping" and "pong" back and
/// forth forever.
fn process_message(decrypted_message: &[u8], peer_name: &'static str) -> Option<Vec<u8>> {
    match decrypted_message {
        b"ping" => {
            println!("[{}]: pong", peer_name);
            Some(b"pong".to_vec())
        }
        b"pong" => {
            println!("[{}]: ping", peer_name);
            Some(b"ping".to_vec())
        }
        _ => None,
    }
}

/// For simplicity's sake this function assumes there is only one remote peer we can talk to.
fn receive(
    context: &mut Context<MyApp>,
    app: &RefCell<MyApp>,
    peer_name: &'static str,
    recv_queue: &RefCell<Vec<Vec<u8>>>,
    send_queue: &RefCell<Vec<Vec<u8>>>,
) {
    if let Some(recv_packet) = recv_queue.borrow_mut().pop() {
        let push_onto_send_queue = |packet: Vec<u8>| {
            assert!(packet.len() <= TEST_MTU);
            send_queue.borrow_mut().push(packet);
            true
        };

        use zssp_proto::result::ReceiveOk::*;
        use zssp_proto::result::SessionEvent::*;
        let result = context.receive(
            app.borrow_mut().deref_mut(),
            push_onto_send_queue,
            TEST_MTU,
            |_| Some((push_onto_send_queue, TEST_MTU)),
            &0,
            recv_packet,
        );
        let (session, reply_message) = match result {
            Ok(Unassociated) => return,
            Ok(Session(session, event)) => match event {
                NewSession | NewDowngradedSession => {
                    println!("[{}]: session received", peer_name);
                    app.borrow_mut().remote_peers_session = Some(session);
                    return;
                }
                Data(data) => {
                    if let Some(reply) = process_message(&data, peer_name) {
                        (session, reply)
                    } else {
                        return;
                    }
                }
                Control => return,
                Established => {
                    println!("[{}]: ping", peer_name);
                    (session, b"ping".to_vec())
                }
                Rejected => return,
                DowngradedRatchetKey => return,
            },
            Err(e) => {
                println!("ERROR {:?}", e);
                return;
            }
        };

        context
            .send(&session, push_onto_send_queue, TEST_MTU, reply_message)
            .unwrap();

        // This example does not properly track time so we just call service on every update.
        context.service(app.borrow_mut().deref_mut(), |_| Some((push_onto_send_queue, TEST_MTU)));
    }
}

/// We create two peers, Alice and Bob, then we have Alice initiate a ZSSP session with Bob, and
/// then we have Alice send the message "ping" to Bob.
/// Bob replies with the message "pong", which Alice replies to with "ping" and so on forever.
fn main() {
    let alice_keypair = P384CrateKeyPair::generate(&mut OsRng);
    let alice_app = RefCell::new(MyApp { time: Instant::now(), remote_peers_session: None });
    let alice_send_queue = RefCell::new(Vec::<Vec<u8>>::new());
    let mut alice_context = Context::<MyApp>::new(alice_keypair, OsRng);

    let bob_keypair = P384CrateKeyPair::generate(&mut OsRng);
    let bob_pubkey = bob_keypair.public_key();
    let bob_app = RefCell::new(MyApp { time: Instant::now(), remote_peers_session: None });
    let bob_send_queue = RefCell::new(Vec::<Vec<u8>>::new());
    let mut bob_context = Context::<MyApp>::new(bob_keypair, OsRng);

    let result = alice_context.open(
        alice_app.borrow_mut().deref_mut(),
        |packet| {
            assert!(packet.len() <= TEST_MTU);
            alice_send_queue.borrow_mut().push(packet);
            true
        },
        TEST_MTU,
        bob_pubkey,
        (),
        Vec::new(),
    );
    alice_app.borrow_mut().remote_peers_session = Some(result.unwrap());
    println!("[Alice]: session opened");

    for _ in 0..16 {
        receive(&mut bob_context, &bob_app, "Bob", &alice_send_queue, &bob_send_queue);

        receive(
            &mut alice_context,
            &alice_app,
            "Alice",
            &bob_send_queue,
            &alice_send_queue,
        );
    }
}
