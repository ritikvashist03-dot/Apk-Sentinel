# APK Sentinel remote receiver

This JDK 17 module is the deliberately explicit PC-09 receiver endpoint. It
binds one administrator-selected literal IPv4/IPv6 address, requires TLS
mutual authentication, pins the exact enrolled Android P-256 client SPKI, and
then accepts only APS1/APSA attestation followed by ordered AES-GCM APSR
frames. It has no discovery, DNS, proxy, cloud, relay, or fallback path.

`ReceiverProtocol.FrameVerifier` accepts an optional caller-selected local
sink only for `RAW_ENCRYPTED_PACKET`. The sink is bounded by the caller's
session limits and receives bytes only during the authenticated callback. No
decrypted-payload or credential sink is representable.

The server's receiver private key is supplied by the operator's protected
PKCS#12/Keystore configuration. The Android client enrollment input is a
public certificate/SPKI only; APK Sentinel never exports its Android Keystore
private key.

## Run the receiver

Build and run the desktop endpoint with the repository JDK 17 and Gradle:

```powershell
$env:JAVA_HOME = 'E:\Apk\jbr'
.\gradlew.bat :tools:remote-receiver:installDist
& '.\tools\remote-receiver\build\install\remote-receiver\bin\remote-receiver.bat' `
  --bind 192.0.2.20 --port 443 `
  --identity 'X:\secure\receiver.p12' --storepass 'use-a-secret-prompt' `
  --client-cert 'X:\secure\apk-sentinel-client.crt' `
  --raw-sink 'X:\captures\remote-raw.bin' --sink-bytes 8388608
```

`--bind` must be the specific unicast IPv4/IPv6 interface literal that the
Android device can reach. Host names, wildcard/loopback/multicast addresses,
DNS, discovery, and proxy fallback are rejected. The receiver requires a
P-256 PKCS#12 private-key entry and the exact public Android client
certificate exported by the app's public-certificate share action. The
optional sink is local, bounded, and accepts only authenticated
`RAW_ENCRYPTED_PACKET` bytes; it is never used for decrypted payloads or
credentials. Keep passwords and private keys out of shell history and cloud
folders; use an operator secret prompt or protected launcher in production.
