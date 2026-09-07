# APK Sentinel design-system adoption

**Status:** implementation checkpoint (source and focused test evidence)

**Scope:** `core:designsystem` plus the current Device and Installed Apps integrations. This document records the shared primitives added on 2026-08-09, the adoption that is present in source, and the runtime evidence that is still outstanding.

## What is now available

`core/designsystem/src/main/java/app/apksentinel/design/` now provides a fixed, semantic Material 3 palette, readable system typography, and components that work better with large text, screen readers, and resizable windows. Theme/accessibility tokens live in `SentinelTheme.kt`, adaptive layout lives in `SentinelLayout.kt`, and reusable components live in `SentinelComponents.kt`.

| Primitive | Purpose | Adoption rule |
|---|---|---|
| `ApkSentinelTheme` | Fixed light/dark semantic palette and system-script typography. Dynamic wallpaper colour remains off. | Existing API is unchanged. Keep it at the process root. |
| `ProvideSentinelAccessibilityPreferences` | Supplies the persisted high-contrast and reduced-motion preference without leaking storage into feature modules. | `MainActivity` wraps the root once, before `ApkSentinelTheme`; Privacy exposes the settings. |
| `LocalSentinelMotion` | Provides zero-duration values when reduced motion is enabled. | Any new animation must read these tokens and change immediately when `reducedMotion` is true. Do not add decorative scan/radar animation. |
| `SentinelResponsiveColumn` | Uses actual window width: compact, medium, and expanded. It centres reading surfaces at 720dp and data surfaces at 1200dp. | Use for the outer content column of scroll/form/detail screens. Keep `LazyColumn` as the independently scrollable child for long lists. |
| `currentSentinelWindowWidth` | Compact `<600dp`, medium `600-839dp`, expanded `>=840dp`. | Select a rail/list-detail presentation in the shell; do not use device model or orientation as a proxy. |
| `SentinelCard` | Calm semantic surface with 18dp internal padding. | Existing calls remain compatible. Avoid nesting cards only for visual indentation. |
| `SectionTitle` | Adds a TalkBack heading semantic to the existing title treatment. | Use once at the beginning of every screen and major section. |
| `FullWidthOutlinedAction` | 52dp-minimum secondary action that wraps translated labels. | Existing calls remain compatible. |
| `FullWidthPrimaryAction` | 52dp-minimum filled primary action. | Each screen should expose one clearly primary action before overflow. |
| `KeyValueRow` | Stacks label/value content from 1.3x font scale and makes values selectable. | Use for package IDs, hashes, versions, IPs, and timestamps rather than hand-built `Row` pairs. |
| `SentinelStatusLabel` | Text-first status chip with a semantic status tone. | The label must state the status in words; colour is reinforcement only. |
| `SentinelToggleRow` | One labelled 56dp switch target with spoken on/off state. | Use for preferences and filters; supply a feature-specific `onStateLabel` and `offStateLabel` when generic “On/Off” is insufficient. |

## Compatibility and integration boundary

The existing public calls remain source-compatible:

```kotlin
ApkSentinelTheme { /* content */ }
SentinelCard { /* content */ }
SectionTitle("Title", "Supporting text")
FullWidthOutlinedAction(label = "Action", onClick = { })
KeyValueRow("Label", "Value")
```

The process shell, onboarding, Overview, navigation, Device posture, and Installed Apps now adopt these primitives. Device posture uses `SectionTitle`, `SentinelCard`, `FullWidthOutlinedAction`, and `SentinelStatusLabel`; Installed Apps uses `SectionTitle`, `SentinelCard`, `FullWidthOutlinedAction`, and `SentinelToggleRow`. Installed Apps keeps its search, filters, selected evidence, exports, and Close details action in one `LazyColumn`, so the full journey remains reachable when text is enlarged. `Analyze` is state-preserved by the shell's saveable destination provider and returns to the invoking Installed Apps route through the bounded origin stack.

The source-level and focused unit checks cover primitive adoption contracts and navigation history policy. They do not constitute device acceptance: no emulator run has yet recorded screenshots or TalkBack traversal at 2x font scale, and no physical-device/resizable-window pass has been captured. Treat those runtime checks as release-gate evidence still required.

The process shell wires the user-visible accessibility setting like this:

```kotlin
ProvideSentinelAccessibilityPreferences(
    highContrast = settings.highContrast,
    reduceMotion = settings.reduceMotion,
) {
    ApkSentinelTheme {
        SentinelShell()
    }
}
```

The settings are local, explain what changes, and default to the device/system appearance. A reduced-motion choice affects the app-owned onboarding and destination transitions immediately; it never delays, conceals, or falsifies engine state. The app does not add a decorative custom ripple, so standard Material press feedback remains an interaction affordance rather than a promised motion transition.

## Required pattern changes in screen owners

1. Replace plain outer `Column` widths with `SentinelResponsiveColumn` on remaining reading/detail screens. Preserve system/IME inset padding supplied by the shell. Do not put an unbounded `LazyColumn` inside a vertically scrolling parent.
2. Replace label-and-raw-`Switch` pairs with `SentinelToggleRow`. The entire row becomes a single accessible target, rather than leaving descriptive text unrelated to a small control.
3. Replace status-coloured `Text` with `SentinelStatusLabel` plus a plain-language explanation, scope, freshness, and limitation. A score alone is not a status.
4. Use `KeyValueRow` for technical values and provide a separate explicit copy/share action where the value is long or sensitive. Never truncate a hash and silently imply it is complete.
5. Use `FullWidthPrimaryAction` for the one primary action and `FullWidthOutlinedAction` for a non-destructive alternative. A destructive action must use an explicit destructive confirmation component; never merely make a normal primary button red.
6. Use `LocalSentinelMotion.current` for every future `animate*AsState`, `AnimatedVisibility`, navigation animation, loading transition, or progress shimmer. The shell and onboarding consume it for destination/page transitions; with reduced motion, they use an immediate state change. Do not add decorative scan/radar motion or a custom animated ripple without adding a motion-aware implementation and test.

## Accessibility verification gate

Design-system adoption is not complete when code compiles. Each adopting screen must have evidence at:

- 360x800dp, 411x891dp, 600x960dp, and 840x900dp;
- light and dark appearance;
- English, Hindi, and a 40% pseudo-localised expansion fixture;
- 1.0x and 2.0x font/display scale;
- TalkBack, Voice Access/Switch Access, keyboard, and magnification for its primary task; and
- reduced motion and high contrast when the screen has motion or status/disabled states.

Check that a button, setting, active-session stop control, error recovery control, and screen title remain visible and reachable. Test semantics, not just screenshots: status wording, heading order, button label, switch state, and error/result announcement must be discoverable.

## Intentional limits

- `SentinelResponsiveColumn` supplies gutters and readable maximum widths. It does not create navigation rails or list-detail routes; the navigation shell must adopt those behaviours.
- Compose does not provide a single universal system “reduce motion” flag suitable for this app without product-level policy. The explicit local preference is therefore the product-level source for the owned transitions; platform/device validation is still required.
- Palette values are designed as semantic tokens, but release acceptance still requires automated/visual contrast measurements for enabled, disabled, focused, and pressed states.
- No Gradle task was run for this design-system pass, by task constraint. The next integration/build owner must compile this module and run Compose semantic/screenshot tests.
