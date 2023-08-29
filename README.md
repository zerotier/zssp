ZeroTier Secure Session Protocol
======

*NOTICE: ZSSP has not yet completed peer review or code audit, so use at your own risk for now. This will be updated as the project matures.*

## Introduction

ZeroTier Secure Session Protocol (ZSSP) is a [Noise](http://noiseprotocol.org) protocol implementation using NIST/FIPS/CfSC compliant cryptographic primitives plus post-quantum forward secrecy via [Kyber1024](https://pq-crystals.org/kyber/). It also includes built-in support for fragmentation and defragmentation of large messages with the fragmentation protocol being hardened against the usual denial of service attacks that plague most packet fragmentation and re-assembly protocols.

ZSSP implements the [Noise XK](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) interactive handshake pattern which provides strong forward secrecy not only for data but for the identities of the two participants in the session. The XK pattern was chosen instead of the IK pattern used in most Noise implementations (e.g. Wireguard) due to ZeroTier identities being long lived and potentially tied to the real world identity of the user. As a result a Noise pattern providing identity forward secrecy was considered preferable as it offers some level of deniability for recorded traffic even after secret key compromise. Post-quantum forward secrecy is negotiated alongside Noise XK using a [hybrid forward secrecy model suggested by the Noise protocol authors](https://github.com/noiseprotocol/noise_wiki/wiki/Hybrid-Forward-Secrecy).

Periodic session re-keying uses the [Noise KK](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) pattern with key ratcheting based in part on the methods used by the [Signal protocol](https://signal.org/docs/specifications/doubleratchet/). Unlike Signal ratcheting is performed only on re-key events and not on every message as this would be prohibitively costly for a protocol designed for high throughput applications.

Re-keying does not employ a hybrid exchange. Post-quantum forward secrecy is negotiated only on session startup since the threat model underpinning its use is to protect against very long term data storage and future decryption with quantum computers. Ratcheting causes the result of the initial ephemeral PQ exchange to be mixed into all subsequent session keys, protecting the entire session against a future attacker able to break elliptic curve cryptography.

An in-depth guide to the full protocol specification can be found in the [protocol whitepaper](whitepaper/main.pdf) provided in this repository.

ZSSP was designed for use in [ZeroTier](https://www.zerotier.com/) but is payload agnostic and open source and can easily be used by other projects. The implementations here are based around generic cryptographic traits that a user can implement in terms of any cryptographic library of API they wish to use. Default implementations in terms of popular Rust cryptography crates are included but can be disabled via feature selection if alternatives are to be used.

This repository includes both a simpler [reference](reference/) implementation that follows the whitepaper very explicitly and a more complex [high performance](performance/) implementation designed for high throughput or use in systems that will manage very large numbers of ZSSP sessions.

See the [ZSSP whitepaper](whitepaper/main.pdf) for extensive documentation and proofs of security.

## Cryptographic Primitives Used in ZSSP

 - **NIST P-384 ECDH**: Elliptic curve used in initial Noise XK and subsequent Noise KK key exchanges
 - **Kyber1024**: Quantum attack resistant lattice-based key exchange during initial handshake
 - **SHA-512**: Used to construct KBKDF, also used in a proof of work and IP ownership DOS mitigation scheme
 - **KBKDF**: Key mixing, sub-key derivation
 - **AES-256**: Single block encryption of header to harden packet fragmentation protocol
 - **AES-256-GCM**: Authenticated encryption

## Comparison With A Few Other Protocols

*Note that ZSSP can be used in two modes: persistent and opportunistic. Persistent mode persists the key ratcheting state of sessions while opportunistic mode will automatically reset if key ratcheting information is lost. The latter is designed for cases where persistent storage is unavailable or unreliable or when the user wishes to prioritize unattended reliability over the additional security provided by persistent mode.*

| | Persistent ZSSP | Opportunistic ZSSP| WireGuard | ZeroTier Legacy Transport |
| --- | --- | --- | --- | --- |
|**Construction**|Noise\_XKhfs+psk2|Noise\_XKhfs+psk2|Noise\_IKpsk2|Static Diffie-Helman|
|**Perfect Forward Secrecy**|Yes|Yes|Yes|No|
|**Forward Secret Identity Hiding**|Yes|Yes|No|No|
|**Quantum Forward Secret**|Yes|Yes|No|No|
|**Ratcheted Forward Secrecy**|Yes|Yes|No|No|
|**Silence is a Virtue**|Yes|No|Yes|No|
|**Key-Compromise Impersonation**|Resistant|Resistant|Resistant|Vulnerable|
|**Compromise-and-Impersonate**|Resistant|Detectable|Vulnerable|Vulnerable|
|**Single Key-Compromise MitM**|Resistant|Resistant|Resistant|Vulnerable|
|**Double Key-Compromise MitM**|Resistant|Detectable|Vulnerable|Vulnerable|
|**DOS Mitigation**|Yes|Yes|Yes|No|
|**Supports Fragmentation**|Yes|Yes|No|Yes|
|**FIPS Compliant**|Yes|Yes|No|No|
|**Small Code Footprint**|Yes|Yes|Yes|No|
|**RTT**|2|2|1|Stateless|

## Definitions

* **Construction**: The mathematical construction the protocol is based upon.
* **Perfect Forward Secrecy**: An attacker with the static private keys of both party cannot decrypt recordings of messages sent between those parties.
* **Forward Secret Identity Hiding**: An attacker with the static private key of one or more parties cannot determine the identity of everyone they have previously communicated with.
* **Quantum Forward Secret**: A quantum computer powerful enough to break Elliptic-curve cryptography is not sufficient in order to decrypt recordings of messages sent between parties.
* **Ratcheted Forward Secrecy**: In order to break forward secrecy an attacker must record and break every single key exchange two parties perform, in order, starting from the first time they began communicating. Improves secrecy under weak or compromised RNG.
* **Silence is a Virtue**: A server running the protocol can be configured in such a way that it will not respond to an unauthenticated, anonymous or replayed message.
* **Key-Compromise Impersonation**: The attacker has a memory image of a single party, and attempts to create a brand new session with that party, pretending to be someone else.
* **Compromise-and-Impersonate**: The attacker has a memory image of a single party, and attempts to impersonate them on a brand new session with the other party.
* **Single Key-Compromise MitM**: The attacker has a memory image of a single party, and attempts to become a Man-in-the-Middle between them and any other party.
* **Double Key-Compromise MitM**: The attacker has a memory image of both parties, and attempts to become a Man-in-the-Middle between them.
* **Supports Fragmentation**: Transmission data can be fragmented into smaller units to support small physical MTUs.
* **FIPS Compliant**: The cryptographic algorithms used are compliant with NIST/FIPS-140 requirements.
* **CSfC**: The cryptographic algorithms used are compliant with the [NSA Commercial Solutions for Classified (CSfC)](https://www.nsa.gov/Resources/Commercial-Solutions-for-Classified-Program/) program.
* **Small Code Footprint**: The code implementing the protocol is separate from other concerns, is concise, and is therefore easy to audit.
* **RTT**: "Round-Trip-Time" - How many round trips from initiator to responder it takes to establish a session.
