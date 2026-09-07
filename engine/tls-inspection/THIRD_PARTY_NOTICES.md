# TLS inspection third-party notices

APK Sentinel's TLS-inspection engine uses Bouncy Castle Java 1.85:

- `org.bouncycastle:bcprov-jdk18on:1.85`
- `org.bouncycastle:bcpkix-jdk18on:1.85`

Bouncy Castle is distributed under the Bouncy Castle License. The complete
license text is available at https://www.bouncycastle.org/licence.html and in
the upstream source distribution. These artifacts are used for X.509v3 CA and
short-lived SAN leaf construction; private keys are not exported by the app.
