# APK Sentinel protected receiver contract

The repository includes an explicit JDK 17 receiver module under
`tools/remote-receiver`. It is still an advanced, user-started feature: the
app must not discover a receiver, open a listener, or claim general Wireshark
coverage. Only the exact reviewed literal destination and enrolled identities
may be used.

Any future receiver must be independently reviewed and implement all of this
exact contract before `ReceiverAttestationWireV1.isInstalled` can be enabled:

1. Listen only after an administrator explicitly configures it. There is no
   discovery, broadcast, UDP, cloud relay, hostname, or fallback endpoint.
2. Use TLS 1.2 or TLS 1.3 with mutual authentication. The app connects only to
   the user-reviewed literal IPv4/IPv6 address and port. The receiver TLS leaf
   certificate's P-256 SubjectPublicKeyInfo must exactly equal the paired
   Base64 X.509 public key; its SHA-256 fingerprint must match the review.
3. Trust the app-owned Android-Keystore P-256 client certificate only after the
   receiver operator has independently enrolled its public certificate. The
   private key never leaves Android Keystore. The app may export only the
   public client certificate for operator enrollment. Rotation/revocation must
   stop access, not fall back to an unauthenticated path.
4. Immediately after mTLS, accept `APS1` version 1: four-byte magic, one-byte
   version, 32-byte nonce, unsigned 16-bit client ephemeral P-256 SPKI length,
   then that SPKI. Return `APSA` version 1 followed by exactly the same
   32-byte nonce. Reject any malformed, replayed, duplicate, expired, or
   unexpected message and close the connection.
5. Derive the AES-256 session key using P-256 ECDH between the receiver's
   paired private key and the client ephemeral public key, then SHA-256 over
   `APK Sentinel Remote Stream v1`, the nonce, and the ECDH secret. Zeroize
   transient secret material. Do not persist the key.
6. After attestation, accept only ordered encrypted `APSR` v1 frames from the
   `engine/remote-stream` module. Enforce sequence, AES-GCM authentication,
   size/category limits, and the user's session limit. Do not log, relay, or
   implicitly retain or inspect decrypted frame contents. A user may explicitly
   select one bounded local sink for `RAW_ENCRYPTED_PACKET` records (for
   example, a bounded PCAPNG document); the sink is never implicit and cannot
   accept `DECRYPTED_PAYLOAD` or `CREDENTIAL` records.
7. Send only app-attested metadata or packets classified upstream as raw
   encrypted by a reviewed source. Decrypted payloads and credentials are
   prohibited until a separate policy, technical, and consent review adds them.

Before release, complete independent device/security tests for Android 26-36,
certificate rotation/revocation, IPv4/IPv6, captive portal, Wi-Fi/mobile/VPN
   changes, background/process death, relay/proxy refusal, queue limits, nonce
replay, protocol fuzzing, consent expiry, Hindi/TalkBack, Play policy, Data
Safety, and privacy disclosure.
