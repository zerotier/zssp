| | Persistent ZSSP | Opportunistic ZSSP | Non-persistent ZSSP | WireGuard | ZeroTier V1 Transport |
| --- | --- | --- | --- | --- | --- |
|**Construction**|Noise XKhfs+psk2|Noise XKhfs+psk2|Noise XKhfs|Noise IKpsk2|Static Diffie-Helman|
|**Perfect Forward Secrecy**|Yes|Yes|Yes|Yes|No|
|**Forward Secret Identity Hiding**|Yes|Yes|Yes|No|No|
|**Identity Testing**|Resistant|Resistant|Resistant|Vulnerable|Vulnerable|
|**Forward Secrecy Automatically Heals**|Yes|Yes|Yes|Yes|No|
|**Ratcheted Forward Secrecy**|Yes|Yes|No|No|No|
|**Quantum Forward Secret**|Yes|Yes|Yes|No|No|
|**Key-Compromise Impersonation**|Resistant|Resistant|Resistant|Resistant|Vulnerable|
|**Compromise-and-Impersonate**|Resistant after ratchet|Detectable after ratchet|Vulnerable|Vulnerable|Vulnerable|
|**Single Key-Compromise MitM**|Resistant|Resistant|Resistant|Resistant|Vulnerable|
|**Double Key-Compromise MitM**|Resistant after ratchet|Detectable after ratchet|Vulnerable|Vulnerable|Vulnerable|
|**Silence is Golden**|Yes|No|No|Yes|No|
|**DOS Mitigation**|Yes|Yes|Yes|Yes|No|
|**Supports Fragmentation**|Yes|Yes|Yes|No|Yes|
|**FIPS Compliant**|Yes|Yes|Yes|No|No|
|**Small Code Footprint**|Yes|Yes|Yes|Yes|No|
|**RTT**|2|2|2|1|1|
|**Kernel Implementation**|No|No|No|Yes|No|


* **Construction**: The mathematical construction the protocol is based upon.
* **Perfect Forward Secrecy**: An attacker with the static private keys of both party cannot decrypt recordings of messages sent between those parties.
* **Forward Secret Identity Hiding**: An attacker with the static private key of one or more parties cannot determine the identity of everyone they have previously communicated with.
* **Identity Testing**: The attacker has the static public key of a single party, and attempts to test whether they participated in a given session.
* **Forward Secrecy Automatically Heals**: Forward secrecy will be automatically re-established between communicating parties in the event a session key is compromised.
* **Ratcheted Forward Secrecy**: In order to break forward secrecy an attacker must record and break every single key exchange two parties perform, in order, starting from the first time they began communicating. Improves secrecy under weak or compromised RNG.
* **Quantum Forward Secret**: A quantum computer powerful enough to break Elliptic-curve cryptography is not sufficient in order to decrypt recordings of messages sent between parties.
* **Key-Compromise Impersonation**: The attacker has a memory image of a single party, and attempts to create a brand new session with that party, pretending to be someone else.
* **Compromise-and-Impersonate**: The attacker has a memory image of a single party, and attempts to impersonate them on a brand new session with the other party.
* **Single Key-Compromise MitM**: The attacker has a memory image of a single party, and attempts to become a Man-in-the-Middle between them and any other party.
* **Double Key-Compromise MitM**: The attacker has a memory image of both parties, and attempts to become a Man-in-the-Middle between them.
* **Silence is Golden**: A server running the protocol can be configured in such a way that it will not respond to an unauthenticated, anonymous or replayed message.
* **Supports Fragmentation**: Transmission data can be fragmented into smaller units to support jumbo-sized data or MTU discovery.
* **FIPS Compliant**: The protocol uses FIPS approved cryptographic algorithms.
* **Small Code Footprint**: The Codebase implementing the protocol can be easily audited by anyone on the internet.
* **RTT**: "Round-Trip-Time" - How many round trips from initiator to responder it takes to establish a session.
