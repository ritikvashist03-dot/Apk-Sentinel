# English and Hindi string-resource migration contract

**Status:** required before release

**Supported launch languages:** English (`values`) and Hindi in Devanagari (`values-hi`). The device locale is the default. A later in-app language picker must offer its language names in their own scripts: `English` and `हिन्दी` (no flags).

## Current static baseline

The resource migration remains incomplete outside the owned UX polish slice.

- `app/src/main/res/values/ux_polish_strings.xml` and `values-hi/ux_polish_strings.xml` own the current onboarding, Overview, primary navigation, and UX state copy. The older keys remain in `strings.xml` for compatibility with untouched screens and are not the source for these polished surfaces.
- `OnboardingScreen.kt`, `OverviewScreen.kt`, and `SentinelNavigation.kt` use `stringResource` for their current copy, including checked/not-checked/could-not-verify/next-action language.
- `SentinelShell.kt`, `InstalledAppsScreen.kt`, and `DevicePostureScreen.kt` still contain the majority of visible strings directly in Compose. Those screens cannot present Hindi today.
- `engine/network-monitor/src/main/res/values/strings.xml` contains notification/channel copy but has no Hindi counterpart. A notification is part of the active-session safety path and must be translated with the same priority as in-app copy.
- The existing `app/src/main/res/values-hi/strings.xml` visibly contains mojibake (`à¤...`) rather than readable Devanagari. Replace it from a verified UTF-8 source and inspect the rendered result on a device. Do not “repair” it by editing individual broken byte sequences.

This contract does not claim complete app-wide translation coverage. The owning app, feature, and engine modules must migrate their own strings before release.

## Resource ownership and key policy

| Location | Owns | Must not own |
|---|---|---|
| `app/src/main/res/values*/strings.xml` | Product shell, shared legal/privacy, system handoff copy, cross-feature actions | Engine-only wording and feature-specific technical labels |
| `app/src/main/res/values*/ux_polish_strings.xml` | UX-polish slice: onboarding, Overview, primary navigation, selection/state labels, and responsive shell actions | Feature-specific technical labels or legal/privacy copy |
| `feature/<name>/src/main/res/values*/strings.xml` | That feature’s screen, filters, loading/error/empty/recovery states, actions | App navigation labels or another feature’s text |
| `engine/<name>/src/main/res/values*/strings.xml` | Notification channels, foreground-service wording, system-visible errors | UI-specific interpretation or policy/consent copy |
| `core/designsystem` | No end-user product strings by default | Feature text. Components receive strings from their owner. |

Use descriptive, stable names grouped by screen and intent. For example:

```xml
<string name="nav_home">Home</string>
<string name="apps_search_label">Search app or package</string>
<string name="network_disclosure_title">Before local monitoring starts</string>
<string name="network_state_active">Monitoring active</string>
<string name="apk_report_risk_summary">Risk evidence: %1$d of 100 · %2$s</string>
<plurals name="apps_visible_count">
    <item quantity="one">%1$d visible app</item>
    <item quantity="other">%1$d visible apps</item>
</plurals>
```

Rules:

1. Keys describe meaning, not the English sentence or a visual position. Never reuse a generic `ok`, `details`, or `status` key for two different security consequences.
2. Use numbered placeholders (`%1$s`, `%2$d`) and keep their type/order identical in English and Hindi. Add a translator comment where an argument is sensitive, technical, or untrusted.
3. Use `<plurals>` for visible counts and never concatenate a numeral with a noun in Kotlin. Hindi still needs a valid `other` form.
4. Put non-translatable protocols, MIME types, cryptographic algorithms, and constants in `translatable="false"` resources only when they are never spoken as user copy. Package names, app names, domains, file names, IPs, hashes, and device-provided labels are data, not translation keys.
5. Do not embed HTML, manual line breaks, bullet characters, or visual whitespace as layout. Use composables/lists for structure. Markup in legal text must have an accessible text alternative.
6. Use simple Indian English and professional Hindi. Avoid unexplained jargon, casual Hinglish, blame for sideloading, “safe/unsafe” guarantees, or different severity words for the same state.

## Compose migration pattern

Use resources at the UI boundary, not in domain models. A view-model/model should expose a stable state and facts; the composable maps those to `@StringRes` resources and formatted values.

```kotlin
Text(stringResource(R.string.apps_search_label))
Text(pluralStringResource(R.plurals.apps_visible_count, visibleCount, visibleCount))
Text(stringResource(R.string.apk_report_risk_summary, score, localizedRiskLevel))
```

For Java/service code, use `context.getString(...)`. Keep Android notification strings in the engine resource module so they work before the Compose process is visible.

Never construct user-facing grammar with interpolation such as `"Hostname: $host"`, `"$count permissions"`, or enum `name.replace('_', ' ')`. Instead:

1. map enum values to a resource ID;
2. format count/time using the current locale;
3. pass normalised untrusted data as an argument; and
4. put technical data in its own selectable visual field when necessary.

For mixed-script safety, package IDs, domains, IPs, hashes, file names, and user-provided app labels must be displayed with bidi isolation/wrapping and content-direction-aware text. Do not rely on string concatenation to keep a hostile right-to-left character from changing the apparent order of a hash or hostname. Keep an accessible plain-text equivalent for any visually separated technical value.

## Mandatory screen inventory

Migrate every visible string, including state and recovery text, in these areas:

| Owner | Required group examples |
|---|---|
| Shell/navigation | Home, Apps, Analyze APK, Network, Privacy, Device, Terms; selection state; back/reselection labels; active sensitive-session banner; settings/language/accessibility labels |
| Onboarding | All current onboarding strings plus denied/skip/restart state. Existing use of `stringResource` is the reference pattern, but Hindi resource quality must be repaired. |
| Overview | Privacy-by-default status, primary next action, coverage/freshness, limitation, and all card actions |
| APK and link analysis | Picker/title/selected-file state, file type/size/preflight, working/cancelled/partial/error/saved states, result/finding severity, risk limitations, URL validation, export/redaction/retention copy |
| Installed apps | Search, filters, labels, installer evidence, loading/empty/error/visibility limitation, app details, permission states, split warning, file export, open/close/retry actions |
| Device posture | Score explanation, every check state, scope/limitation/freshness, specific Android setting handoff target, return/recheck failure |
| Network | Dedicated VPN explainer, capability state, consent refusal/another-VPN conflict/recovery, active/stop state, notification permission result, retention, metadata scope, firewall/capture/TLS/root/streaming disclosures |
| Privacy, reports, and legal | Diagnostics, consent history, data-retention/delete/export, destructive confirmation, deletion receipt, terms/publisher placeholders, privacy policy, feature-specific consent/cleanup text |
| Foreground notification | Channel name/description, preparing/active/stopping state, stop action, failure/recovery. Add `engine/network-monitor/src/main/res/values-hi/strings.xml`. |

## Translation quality bar

Every Hindi string must be real Devanagari stored as UTF-8 and rendered in a screenshot/device check. Examples of the expected form:

```xml
<string name="apps_search_label">ऐप या पैकेज खोजें</string>
<string name="network_state_active">निगरानी चालू है</string>
<string name="network_stop_action">सत्र रोकें</string>
```

These examples establish encoding and tone only. A fluent Hindi reviewer must approve every permission, warning, destructive confirmation, limitation, and legal disclosure before release. Do not ship unreviewed machine translation for a consent or security conclusion.

Maintain a bilingual glossary for terms used across app UI, notifications, reports, help, and legal copy. Required entries include: APK, permission, signer/certificate, package, installer, sideloaded, monitoring, protection, local VPN, connection, destination, metadata, report, capture, stop, erase, consent, review, urgent, unavailable, partial result, and no urgent issues found.

## Layout and localisation acceptance

Every migrated screen must pass all of the following before its strings are accepted:

- English, Hindi, and pseudo-localised 40% expansion at 360dp, 600dp, and 840dp widths;
- 1.0x and 2.0x font/display scale with no clipped CTA, status, detail, error, or stop path;
- TalkBack reading order and grammar for a formatted count, status, switch, error, confirmation, and technical value;
- screen-reader language choice follows the app/device locale and does not spell every Hindi phrase as English;
- mixed-script adversarial fixtures for an app label, domain, package name, IP, and hash;
- `lint`/resource validation has no missing English/Hindi entry for product-facing strings; and
- a human reviewer signs off feature-specific consent and legal content in both languages.

## Migration order

1. Repair the Hindi resource encoding and add the Hindi foreground-notification resources.
2. Migrate navigation, onboarding, Privacy/Terms, and every network consent/active/stop string because these are safety-critical.
3. Migrate the APK/link, installed-app, and device-posture surfaces together with their loading/empty/error/partial states.
4. Replace enum-name formatting and ad-hoc interpolation with resource-backed mappings, plurals, and locale-aware formatting.
5. Add pseudo-locale, font-scale, semantic, and screenshot regression fixtures; only then remove obsolete welcome keys after confirming no references remain.
