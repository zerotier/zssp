ZeroTier Secure Sessions Protocol
======

## Introduction

ZeroTier Secure Socket Protocol (ZSSP) is a [Noise](http://noiseprotocol.org) protocol implementation using NIST/FIPS/CfSC compliant cryptographic primitives plus post-quantum forward secrecy via [Kyber1024](https://pq-crystals.org/kyber/). It also includes built-in support for fragmentation and defragmentation of large messages with strong resistance against denial of service attacks targeted against the fragmentation protocol.

Specifically ZSSP implements the [Noise XK](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) interactive handshake pattern which provides strong forward secrecy not only for data but for the identities of the two participants in the session. The XK pattern was chosen instead of the more popular IK pattern used in popular Noise implementations like Wireguard due to ZeroTier identities being long lived and potentially tied to the real world identity of the user. As a result a Noise pattern providing identity forward secrecy was considered preferable as it offers some level of deniability for recorded traffic even after secret key compromise.

Hybrid post-quantum forward secrecy using Kyber1024 is performed alongside Noise with the result being mixed in alongside an optional pre-shared key at the end of session negotiation.

ZSSP is designed for use in ZeroTier but is payload-agnostic and could easily be adapted for use in other projects.

Further information can be found in the ZSSP whitepaper (pending official release).

## Cryptographic Primitives Used

 - **NIST P-384 ECDH**: Elliptic curve key exchange during initial handshake and for periodic re-keying during the session
 - **Kyber1024**: Quantum attack resistant lattice-based key exchange during initial handshake
 - **SHA-512**: Used to construct KBKDF, also used in a proof of work and IP ownership DOS mitigation scheme
 - **KBKDF**: Key mixing, sub-key derivation
 - **AES-256**: 128-bit PRP for AES-256-GCM and for authenticated encryption of header to harden fragmentation against DOS (see section on header protection)
 - **AES-256-GCM**: Authenticated encryption

## Security Properties

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
|**RTT**|2|2|1|1|

### Definitions

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
* **Supports Fragmentation**: Transmission data can be fragmented into smaller units to support jumbo-sized data or MTU discovery.
* **FIPS Compliant**: The protocol uses FIPS approved cryptographic algorithms.
* **Small Code Footprint**: The Codebase implementing the protocol can be easily audited by anyone on the internet.
* **RTT**: "Round-Trip-Time" - How many round trips from initiator to responder it takes to establish a session.
