# Third-party notices

APK Sentinel is original application code and does not copy PCAPdroid, M-Kavach 2, APK Analyzer, or their branding/source. Reference products are used only to define user-outcome parity and honest limitations.

The Android application and its build/test toolchain use the following open-source projects. Verify the dependency graph and regenerate a machine-readable SBOM from the final release build before publication.

## Distributed Android dependencies

- AndroidX Core, Activity, Lifecycle and Navigation — Android Open Source Project — Apache License 2.0 — <https://source.android.com/docs/setup/about/licenses>
- Jetpack Compose UI, Material 3, tooling annotations and runtime components — Android Open Source Project — Apache License 2.0 — <https://developer.android.com/jetpack/androidx/releases/compose>
- Kotlin standard/runtime components — JetBrains and contributors — Apache License 2.0 — <https://github.com/JetBrains/kotlin/blob/master/license/LICENSE.txt>
- `apksig` — Android Open Source Project — Apache License 2.0 — <https://android.googlesource.com/platform/tools/apksig/>
- Bouncy Castle `bcprov-jdk18on:1.85` and `bcpkix-jdk18on:1.85` — Bouncy Castle License — <https://www.bouncycastle.org/licence.html> (TLS-inspection CA/SAN certificate construction)
- Navigation vector shapes adapted from the Android Material icon vocabulary — Apache License 2.0 — <https://github.com/google/material-design-icons/blob/master/LICENSE>

## Build and test dependencies not intended for runtime packaging

- Android Gradle Plugin and Android build tools — Android Open Source Project — Apache License 2.0.
- Gradle — Gradle Inc. and contributors — Apache License 2.0 — <https://github.com/gradle/gradle/blob/master/LICENSE>
- JUnit 4 — JUnit contributors — Eclipse Public License 1.0 — <https://github.com/junit-team/junit4/blob/main/LICENSE-junit.txt>

## License text

Apache License 2.0: <https://www.apache.org/licenses/LICENSE-2.0>

Eclipse Public License 1.0: <https://www.eclipse.org/legal/epl-v10.html>

This notice is not a substitute for the final artifact's dependency/SBOM and license review. Transitive dependencies, bundled notices and any future threat-data license must be included when the release candidate is assembled.
