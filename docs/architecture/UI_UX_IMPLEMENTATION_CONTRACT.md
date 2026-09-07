# APK Sentinel UI/UX Implementation Contract

**Status:** Implementation contract  
**Scope:** Android Compose UI only; applies to the complete APK Sentinel product in one codebase and delivery cycle  
**Source of truth:** `D:\Projects\explore\APK_SENTINEL_PRODUCT_BLUEPRINT.md` (especially sections 5, 8-10, 19, and 23-25)  
**Current scaffold baseline:** One Compose welcome screen, Material 3, a calm teal theme, selected-file state, and the `OpenDocument` file picker. This contract defines the refactor target; it does not assert that the target already exists.

## 1. Purpose and non-negotiables

This contract converts the product blueprint into buildable UI rules. It is deliberately prescriptive where inconsistent UI would undermine safety, comprehension, privacy, accessibility, or recoverability.

The intended experience is steady, local-first, and clear:

```text
Observe -> Explain -> Recommend -> Let the user decide -> Act -> Verify -> Remember
```

### 1.1 Normative language

- **Must** is a release requirement.
- **Should** is the expected default; an exception requires a documented UX reason and QA coverage.
- **May** is optional only when it does not hide a required control or result.

### 1.2 Product-wide invariants

1. Simple, Advanced, and Sensitive Advanced are presentation and consent levels within one APK Sentinel product and codebase. They are not separate apps, editions, or deferred features.
2. Simple is the default. Advanced adds evidence density; it never changes severity, confidence, privacy defaults, accessibility, or the meaning of Home.
3. Sensitive Advanced features are disabled by default, individually entered, separately disclosed, affirmatively approved, visibly active, bounded, stoppable, and cleanable.
4. General Terms & Conditions may explain authorised use, but cannot substitute for a feature-specific disclosure and affirmative choice.
5. A user must always be able to see and stop active monitoring, enforcement, capture, TLS inspection, root capture, or live streaming from a reachable surface in Simple mode.
6. No view may imply a complete safety guarantee. Status, coverage, freshness, source, and limitations remain distinct.
7. UI state cannot claim a completed action until the underlying engine confirms it. A requested, starting, active, interrupted, and failed state are separate states.
8. Existing data remains visible during refresh failures. Partial results are useful results, not errors disguised as empty content.

### 1.3 Explicit UI exclusions

- No hacker, surveillance, police, skull, virus-radar, or fear-based visual language.
- No global "Tools" destination, account/avatar affordance, paywall, score-only dashboard, fake live scan, or feature-grid onboarding.
- No gesture-only critical action, colour-only status, or snackbar-only recovery path.
- No technical payload, TLS, root, or streaming controls in ordinary onboarding or the default Home hierarchy.

## 2. Compose UI architecture and refactor boundary

The current single-screen UI must be split by responsibility before feature screens expand. Keep UI modules independent from packet, APK-parsing, VPN, storage, and policy implementations. Feature UI receives immutable render models and user intents; it does not infer security conclusions or mutate engine state itself.

### 2.1 Target package layout

This layout maps to real Gradle modules from the start. `app` owns only the process shell and navigation; design, shared models/security, APK parsing, URL inspection, installed-app inspection, device posture, network monitoring, persistence, and feature UI remain in independently testable modules. UI modules receive immutable render models and user intents and never gain direct access to unrelated sensitive engines.

```text
app.apksentinel.mobile.ui
├── app/
│   ├── ApkSentinelApp                 # theme, root NavHost, process-wide banners
│   └── AppStateCoordinator            # mode, active-sensitive-session summary
├── navigation/
│   ├── SentinelDestination
│   ├── SentinelNavGraph
│   ├── SentinelNavigationSuite
│   └── DeepLinkContract
├── design/
│   ├── theme/                         # color, type, shape, motion, dimension tokens
│   ├── component/                     # reusable semantic components only
│   ├── state/                         # common screen-state renderers
│   └── preview/                       # stable preview fixtures and device wrappers
├── model/
│   ├── UiMode
│   ├── UiStatus
│   ├── UiState
│   └── common render models
└── feature/
    ├── onboarding/
    ├── home/
    ├── apps/
    ├── apk/
    ├── link/
    ├── network/
    ├── checkup/
    ├── reports/
    └── settings/
```

Rules:

- `design` has no dependency on a feature package, service, repository, Android permission manager, or navigation controller.
- A feature may use design components and feature-owned render models, but must not call another feature's internal composables.
- Navigation owns route parsing and deep-link argument validation. Screens receive callbacks and stable IDs, not a `NavController` as ordinary business state.
- Engine/domain objects are mapped once in a presenter/view-model layer to immutable UI models. Raw IPs, package names, packet fields, hashes, and implementation exceptions are never exposed accidentally through a generic `toString()`.
- Each screen has a top-level `Route`/state-collector and a pure `Screen` composable. The pure screen must be previewable with loading, empty, partial, error, Simple, Advanced, and relevant Sensitive Advanced fixtures.
- All user actions are named intents, for example `StartMonitoring`, `ApproveVpnDisclosure`, `CreateSimpleRule`, or `StopCapture`. UI controls do not directly toggle a service boolean.

### 2.2 Common UI models

Use one shared vocabulary so the same underlying event is not described differently in Home, Apps, Network, reports, or notifications.

| Model | Required values or fields | UI rule |
|---|---|---|
| `UiMode` | `Simple`, `Advanced`, `SensitiveAdvanced` | `SensitiveAdvanced` represents access to the workspace, not permission to start every sensitive action. |
| `RiskStatus` | `SetupIncomplete`, `Checking`, `NoUrgentIssues`, `Review`, `Important`, `Urgent` | Risk is never a proxy for coverage or engine health. |
| `CoverageState` | `Ready`, `Limited`, `Off`, `Current`, `Due`, `NeverRun`, `On`, `Paused`, `Interrupted`, `LocalOnly`, `OptionalLookupOn`, `Outdated` | Render capability-specific rows; do not compress unrelated capability states into one score. |
| `DataOrigin` | `OnDevice`, `OptionalOnlineLookup`, `AndroidSystem`, `Imported`, `UserProvided` | Show only at a decision, transfer, or source-sensitive result. |
| `Freshness` | observed/verified time, expiry or stale reason | Every status/result screen shows an understandable freshness statement. |
| `Finding` | observation, interpretation, severity, confidence, recommendation, source, timestamp, limitation | The plain-language observation appears before technical evidence. |
| `UiState<T>` | `Uninitialised`, `CapabilityNeeded`, `Loading`, `Content`, `Partial`, `Offline`, `Error`, `BlockingError`, `Stale` | A feature screen must model all applicable cases rather than infer them from nullable data. |
| `ActionState` | `Idle`, `Working`, `Succeeded`, `Failed`, `Unavailable` | Button text and enabled state follow this state; duplicate intent dispatch is blocked. |
| `SensitiveSessionState` | `Inactive`, `Preparing`, `Active`, `Stopping`, `CleanupRequired`, `Failed` | It carries scope, start time, storage/retention, stop route, and cleanup status. |

## 3. Visual foundations

The existing calm teal direction is retained. Dynamic Material colour remains off by default so status and trust semantics remain consistent across devices. A user may choose light, dark, or system appearance; no appearance choice changes severity meaning.

### 3.1 Semantic colour tokens

Every component consumes semantic tokens, never a literal colour. The values below align the scaffold with the approved product palette. Final implementations must verify contrast in all enabled states.

| Token | Light | Dark | Intended use |
|---|---:|---:|---|
| `Canvas` | `#F4F7F6` | `#0D1513` | Window and scrolling background |
| `Surface` | `#FFFFFF` | `#14201D` | Cards, sheets, app bars |
| `OnSurface` | `#14211E` | `#EEF6F3` | Primary text/icons |
| `OnSurfaceVariant` | `#52625D` | `#AFBDB8` | Supporting text/metadata |
| `Brand` | `#0B6554` | `#6FD6B9` | Primary actions, selected navigation |
| `BrandContainer` | `#D8F0E9` | `#1C4036` | Selected/tonal surfaces |
| `Good` | `#146B49` | `#69D49B` | Verified favourable state only |
| `Review` | `#875400` | `#F2BA62` | Context-dependent review |
| `Urgent` | `#A7352D` | `#FFB4AB` | High-confidence urgent/destructive action |
| `Information` | `#2D5F87` | `#A9C7EC` | Neutral explanation/incomplete setup |
| `Outline` | `#CBD5D1` | `#41504B` | Boundaries, dividers, inactive controls |

Colour requirements:

- Status always combines a status word, icon, and colour. For example, `Review` is rendered as an amber-toned label with an information/review icon and the word "Review".
- Red is reserved for a justified urgent finding or destructive confirmation. It must not dominate a default screen.
- Uncertain heuristic evidence never uses urgent red.
- Disabled, pressed, focused, selected, error, and high-contrast states must be tokenised and tested; opacity alone cannot create unreadable text.
- Charts cannot convey severity exclusively through green/red. Provide labels and a row/list alternative.

### 3.2 Type, spacing, shape, and elevation

Use Roboto/Noto system typography for readable English and Indian scripts. Technical values use a system monospace style only inside a bounded/selectable technical field.

| Token | Value | Use |
|---|---|---|
| `Display` | 32sp / 40sp / 600 | Rare hero risk state only |
| `TitleLarge` | 24sp / 32sp / 600 | Screen title |
| `TitleMedium` | 20sp / 28sp / 600 | Major section/card title |
| `BodyLarge` | 16sp / 24sp / 400 | Primary explanation |
| `BodyMedium` | 14sp / 20sp / 400 | Supporting copy |
| `LabelLarge` | 14sp / 20sp / 600 | Buttons and controls |
| `Caption` | 12sp / 16sp / 500 | Metadata; never smaller |

- Base spacing scale: `4, 8, 12, 16, 20, 24, 32, 40, 48, 64dp`.
- Compact-phone horizontal padding: `20dp`. Medium/expanded content gutters: `24-32dp`.
- Card padding: `16-20dp`; related content gap: `8-12dp`; section gap: `24-32dp`.
- Minimum interactive touch target: `48 x 48dp`; primary button minimum height: `52dp`.
- Card radius: `16dp`; button radius: `14dp`; bottom-sheet top radius: `24dp`.
- Use only base, raised-card, and modal elevation. Tonal surfaces and outlines carry hierarchy before shadows.
- Reserve space for asynchronous content so lists and buttons do not jump when loading ends.

### 3.3 Motion, haptics, and sound

| Interaction | Duration | Requirement |
|---|---:|---|
| Press acknowledgement | 80-120ms | Immediate visual response |
| Small toggle/chip/icon state | 160ms | Do not imply engine confirmation before it occurs |
| Content expansion | 200-240ms | Preserve relationship/context |
| Screen transition | 220-260ms | Preserve navigation location |
| Bottom sheet | 260-300ms | Establish a transient decision layer |
| Verified success | 280-340ms | Only after engine/system confirmation |

- Respect system and in-app reduced-motion preferences: crossfade or change immediately.
- No looping scan animation, pulsing threat treatment, parallax, confetti, radar, fake packet animation, or animated threat counter.
- A light haptic may follow an engine-verified reversible control. A stronger haptic is limited to a user-confirmed destructive action. Haptic and sound are never the sole feedback channel.
- Custom sounds are off by default. Notification-channel behaviour remains Android-owned.

## 4. Navigation shell and route contract

### 4.1 Navigation suite

The persistent product model has exactly four top-level destinations:

| Destination | Route root | Purpose | Primary root surface |
|---|---|---|---|
| Home | `home` | Current risk, coverage, one next action, recent material activity | `H-01` |
| Apps | `apps` | Installed-app inspection, APK checking, link checking | `A-01` |
| Network | `network` | Monitoring/protection state, connections, firewall, capture | `N-01` |
| Checkup | `checkup` | Phone-setting checks and guided remediation | `C-01` |

- Settings is opened from a labelled settings icon in the Home top app bar (`settings`). There is no profile/avatar because there is no account.
- Phone/compact layouts use Material 3 bottom navigation with text labels and selected-state icons. It remains visible on top-level overview/list screens.
- Medium and expanded layouts use a navigation rail with the same four labels and ordering. Settings remains in the Home/top-bar action rather than becoming a fifth primary navigation item.
- The shell owns safe-area padding, edge-to-edge insets, global active-session visibility, and consistent navigation state. Feature screens own their content and local app-bar actions.

### 4.2 Route families and stable identifiers

Routes must use opaque stable IDs, not raw names or untrusted URLs as paths. IDs are decoded and validated by navigation before a screen is shown.

| Family | Routes or route shape | UI responsibility |
|---|---|---|
| Home/findings | `home`, `findings`, `finding/{findingId}`, `fix/{findingId}`, `verification/{operationId}`, `activity`, `coverage` | Status, action, verification and recovery |
| Apps | `apps`, `app/{appId}`, `app/{appId}/permissions`, `app/{appId}/network`, `app/{appId}/identity`, `app/{appId}/advanced` | Installed-app evidence and actions |
| APK/link | `apk/check`, `apk/preflight/{fileId}`, `apk/result/{analysisId}`, `link/check`, `link/result/{checkId}` | User-provided file/link flow only |
| Network | `network`, `network/setup`, `connection/{connectionId}`, `rules`, `capture/{captureId}`, `network/conflict`, `network/retention` | Monitoring/protection and recovery |
| Checkup | `checkup`, `checkup/category/{categoryId}`, `checkup/fix/{checkId}`, `checkup/history` | System-setting guidance and return verification |
| Reports/settings | `reports`, `report/{reportId}`, `settings/...`, `help/...`, `trust`, `privacy-access`, `advanced`, `sensitive-advanced` | Local controls, explanation, support |

Deep-link rules:

- A valid deep link lands on the exact known object and displays a visible parent/back route.
- Unknown, deleted, expired, or unauthorised local objects open a recovery surface explaining what is unavailable and where to continue; they never crash or show a blank page.
- Raw URL, APK file path, filesystem URI, technical identifier, and external stream destination are never rendered as a deep-link route without normalisation and safe formatting.

### 4.3 Back-stack and reselection behaviour

- Preserve the last scroll position and local state per top-level destination for the active session.
- Reselecting a selected top-level item returns to that destination root; a second reselect scrolls the root to the top.
- Android Back traverses the user path from object detail to its parent/root. It must not unexpectedly exit an object detail screen.
- From a root screen, Back follows Android predictive-back conventions; never invent a confirmation merely to increase retention.
- Back/Escape dismisses the top transient layer first: keyboard, menu, sheet, dialog, then screen route.
- A system-settings handoff returns to the originating finding/check/app whenever possible, then automatically rechecks the targeted condition. It does not drop the user at generic Home.

### 4.4 Shell visibility rules

The navigation suite is hidden only when it would conflict with a focused task:

- first-run onboarding;
- a permission/disclosure primer immediately before an Android-owned surface;
- a destructive/high-impact confirmation;
- full-screen capture-running control;
- Sensitive Advanced setup/cleanup steps where an accidental navigation change could leave an active state unclear.

When hidden, the screen must still show an explicit close/back route and any active sensitive behaviour must remain visible and stoppable.

## 5. Reusable Compose component contract

All feature UI must use the following semantic components or an approved extension. Component names are implementation targets, not a requirement to expose those names to users.

| Component | Required inputs/states | Required visual/interaction behaviour | Accessibility contract |
|---|---|---|---|
| `SentinelScaffold` | title, navigation mode, app-bar actions, bottom/rail content, insets | Owns surfaces, content padding, navigation suite, global session banner | Landmark/order remains stable; no duplicate title announcement |
| `SentinelTopAppBar` | title, back/up, object identity, actions | Text title first; settings is labelled; supports long localised titles | Back action has a spoken destination; icon actions have text descriptions |
| `SentinelNavigationSuite` | destination list, selected route, compact/rail mode | Four visible text-labelled destinations; selected state has icon + label + colour | `selected`, label, and destination are announced; 48dp targets |
| `StatusHeader` | risk status, coverage sentence, freshness, primary action | Status sentence before proof details; exactly one filled CTA | Announces status, scope, and time as meaningful content |
| `CoverageStrip` | capability rows, display limit, action | Shows independent App/Checkup/Network/Threat-data states; no score | Every row exposes capability, state, and effect of a restore action |
| `FindingCard` | severity, observation, meaning, confidence, action | One recommendation; visual severity is restrained; evidence initially collapsed | Card label includes severity and observation; no colour-only meaning |
| `FindingDetail` | full evidence grammar, technical disclosure, action state | Observation -> meaning -> recommendation -> confidence/source/limitation -> advanced evidence | Headings and expand/collapse state announced; technical text selectable |
| `MonitoringCapsule` | `On`, `Paused`, `Off`, `Starting`, `Interrupted`, `Limited` | Always textual; never icon-only or falsely active | State and consequence are in content description/semantics |
| `DataOriginBadge` | origin, optional provider/field summary | Used at a meaningful data-origin decision, not every row | Read as one concise sentence, not decorative text |
| `PrimaryActionButton` | label, action state, enabled/reason | Filled, min 52dp, active verb while working; no duplicate dispatch | Disabled reason is available to screen reader; focus remains stable |
| `SecondaryAction` | label, action state | Outlined/text hierarchy only; not visually equal to primary | Explicit action wording, never generic "OK" for high impact |
| `SentinelListRow` | leading identity, title, summary, trailing state/action | App-first/object-first identity; supports 2-line title and long scripts | Entire row or discrete action is unambiguous; no nested click targets |
| `SearchAndFilterBar` | query, chips, count, sort/filter callbacks | Local matching begins after two characters; active filters are removable chips | Search field has context-specific hint; chips announce selection/removal |
| `PermissionExplainer` | value, exact data, local/remote processing, decline consequence, continue/not-now | Appears before any Android prompt or product consent; maximum one primary action | Full disclosure is readable before action; focus starts at heading |
| `ActionSheet` | current state, consequence, action, reversal, destructive flag | Modal for high-impact/reversible decision; no hidden consequence | Focus trap; destructive action uses a specific label; Escape/Back closes safely |
| `StatePane` | common `UiState`, retry/background/cancel callbacks | Renders skeleton, empty, partial, offline, stale, error without losing context | Has a concise status announcement; never steals focus during refresh |
| `TechnicalDisclosure` | label, source, time, confidence, limitation, selectable technical values | Collapsed by default outside Advanced; never hides a recommendation-changing limitation | Explicit expanded/collapsed state and copy affordance |
| `AdvancedLabel` | mode/feature label | Compact label for expert-only content; does not imply danger or premium tier | Spoken as "Advanced" before its control |
| `SensitiveSessionBanner` | session type, scope, timer, storage, stop/cleanup route | Visible in every mode while a sensitive session/certificate needs attention | Announces active state once on entry; stop action always labelled and reachable |
| `EvidenceTable` | column schema, rows, summary, empty state | Used for connection/packet/component data in Advanced; small screens remain readable | Table summary plus accessible row/list alternative; values selectable |
| `InlineUndo` | operation, expiry, persistent undo route | Shows after a reversible verified change; persistent recovery exists elsewhere | Respects accessible timeout; action is never only recovery path |

### 5.1 Component composition rules

- A screen begins with `SentinelScaffold`, then a screen-specific `StatePane` or content layout. Do not create a separate bespoke scaffold per feature.
- `StatusHeader`, `FindingCard`, `MonitoringCapsule`, and `PermissionExplainer` are semantic products, not generic cards. Features must not recreate look-alikes with divergent copy/order.
- Use `LazyColumn`/`LazyVerticalGrid` for dynamic lists. There must be only one vertical scrolling parent per screen.
- Cards are not generic navigation buttons. If a card is clickable, it has one deterministic destination and a clear spoken action. Inline controls must be separate targets.
- The filled button is reserved for the one dominant task. A page can have at most one visible filled primary CTA, except a list containing per-item independent actions.
- Technical content has line wrapping or controlled horizontal scrolling inside a bounded field. It must never force the whole page wider than the viewport.

## 6. Screen layout and state model

### 6.1 Shared page hierarchy

Unless a screen explicitly needs a capture control or a system-handoff primer, its reading order is:

1. Location/title.
2. Current state or object identity.
3. Plain-language meaning and consequence.
4. One primary action.
5. Supporting evidence, alternatives, and recovery.
6. Freshness, source, confidence, and limitation.

Rules:

- Summary and recommendation appear before the fold on representative compact devices where content permits.
- Do not lead a novice with a graph, score, raw hash, or settings grid when a human outcome exists.
- Raw technical evidence, methodology, destructive alternatives, and secondary filtering are progressively disclosed. A limitation that changes a recommendation is never hidden.
- Preserve list query, filters, sort, and scroll position when opening and returning from a detail screen.
- Do not present a green reassurance beside an unresolved urgent finding, an active-looking enforcement control while the engine is off, or a celebration after a partial/failed check.

### 6.2 Required state treatment

Each data-driven screen must deliberately render every applicable state below. A single default/loading/success mock-up cannot pass design review.

| State | UI treatment | Required action/recovery |
|---|---|---|
| Uninitialised | Explain the feature value, local processing, and one starting action | Start/setup or a usable alternative |
| Capability needed | `PermissionExplainer` before a system/product request | Continue and Not now; explain remaining capability |
| Loading under 300ms | Preserve prior layout; no spinner needed | None |
| Loading 300ms-1s | Skeleton or inline progress in reserved layout | None |
| Long-running over 1s | Name the current truthful stage | Progress when known |
| Long-running over 8s | Keep usable results; show progress/impact | Continue in background or Cancel when safe |
| Content with findings | Rank by severity, confidence, recency; one next step | Review first/recommended action |
| Content without findings | State scope, freshness, and limitation | Explore evidence or check again |
| Genuine empty | Distinguish not started from nothing recorded from nothing actionable | Contextual start/learn action |
| Partial | Show completed results first, then a distinct "Couldn't check" section | Retry incomplete portion or view limitations |
| Offline | Preserve local result and label only paused online work | Retry when online; do not block local actions |
| Stale | Retain prior result and timestamp/stale reason | Check again |
| Recoverable error | Say what failed, what stayed unchanged, and next step | Try again; technical details behind disclosure |
| Blocking error | Say what cannot proceed and what remains possible | Specific recovery/settings/help route |

All error copy follows: **what happened -> what was affected -> what stayed unchanged -> what the user can do**. Technical codes are behind a labelled technical disclosure and are copyable.

### 6.3 Action feedback and idempotency

For every user action:

1. The control acknowledges touch within 100ms.
2. Its label becomes a truthful active verb such as "Starting...", "Checking...", or "Blocking...".
3. The UI waits for engine/system confirmation before showing the final state.
4. Failure restores the prior affordance and says the intended change was not applied.
5. Reversible verified actions show `InlineUndo` for at least ten seconds, adjusted for accessibility timeout. The owning object and Unified Activity always offer a persistent reversal route.
6. A high-impact or destructive action shows an `ActionSheet` with consequence before execution.
7. Duplicate taps cannot create duplicate jobs, rules, exports, reports, or capture sessions.

## 7. Progressive disclosure and sensitive controls

### 7.1 Presentation-level matrix

| Capability | Simple | Advanced | Sensitive Advanced |
|---|---|---|---|
| Findings/status/coverage | Plain-language outcome, action, scope/freshness | Same conclusion plus technical source/evidence | Same as Advanced; active sensitive behaviour still surfaced |
| Apps/APKs | Identity, sensitive access, clear contextual risk | Package, manifest, signing, components, SDKs, hashes, comparison | No extra exposure without a separate sensitive action |
| Network | App -> destination meaning, allow/block, monitoring state | DNS/SNI/IP/ASN/port/protocol, custom rules, PCAP/PCAPNG capture | TLS/plaintext inspection, payload/hexdump browsing, root capture, external streaming |
| Rules | Simple app/domain decision | Condition editor, conflict preview, import/export | No implicit broadening of scope |
| Storage/export | Plain report scope/redaction | Technical reports, capture export | External destination/session decision and sensitive-data preview |

### 7.2 Advanced entry and exit

- Entry route: `Settings -> Advanced tools`.
- Entry copy states that it adds package details, certificates, components, connection evidence, captures, and custom rules; existing protection does not change.
- Advanced entry has **Enable Advanced tools** and **Not now** only. It does not use a quiz, hidden gesture, or a hacker-themed transformation.
- A user may open one `View technical details` disclosure from a finding without making the global Advanced preference persistent.
- Turning Advanced off hides expert controls but does not silently delete rules/captures or remove certificates. It tells the user what remains active and offers a separate data-cleanup route.

### 7.3 Sensitive Advanced entry and feature gates

Sensitive Advanced workspace route: `Settings -> Advanced tools -> Sensitive Advanced`. It contains high-risk tools, current active sessions, certificates, and cleanup status. It is not promoted in onboarding or normal Home content.

Each sensitive feature must use this sequence before an Android/system or engine action:

1. User explicitly chooses the feature.
2. A dedicated explainer names exact scope, exposed data, local/external processing, recipient or destination where applicable, retention, potential breakage, active indication, stop path, and cleanup path.
3. The user makes an affirmative action for that exact feature. A general T&C check, an earlier Advanced preference, or a different sensitive consent is insufficient.
4. Android-owned certificate/VPN/system flow opens only after the explanation.
5. The feature begins only after engine/system verification. `SensitiveSessionBanner` becomes visible across the product.

| Feature | Default/scope constraints | Persistent UI requirements | Required cleanup/recovery |
|---|---|---|---|
| Raw packet capture | Default metadata-only; explicit app/traffic scope; 10-minute default; size cap; auto-delete after 24h unless saved | Ongoing notification plus in-app timer, size, scope, and **Stop capture** | Save/export/share/delete review; show dropped-detail count and storage state |
| TLS/HTTPS inspection | Explicit selected apps only; exclude banking, UPI, password manager, auth, work-profile and similarly sensitive apps by default | Active inspection banner; selected-app scope; stop route; compatibility limitation | Certificate removal and verified removal status; keep cleanup visible after session |
| In-app payload/hexdump browsing | Deliberate action from an authorised capture/session, not ordinary connection view | Sensitive content warning and source/session identity | Close/return; delete capture if chosen; never promote in Simple content |
| Root capture | Only on an already-rooted device; no rooting capability or implication | Root status, selected scope, stop control, evidence source/limitation | Stop session, clear data/capture as selected; explain unavailable root state honestly |
| Live export/stream | Explicit authenticated destination, scope, exposure, and duration; no auto-share/stream | Destination summary, timer/active state, **Stop session** reachable in Simple | Stop, revoke/clear local session data, retain export explanation |

If Advanced is turned off during an active capture, ask whether to stop it or keep necessary controls available until it ends. No active session may become invisible.

### 7.4 VPN and other access primers

- `VpnService` consent has a dedicated, prominent `PermissionExplainer` directly before Android's VPN surface. It names the app, destination domain/IP, connection time, data amount, local processing, default retention, optional online lookup separation, and one-active-VPN limitation.
- The actions are **Continue** and **Not now**. On cancel, state that monitoring did not start and internet connection is unchanged.
- Another VPN, an engine-start failure, or a denied request routes to `N-19` with a truthful current state and recovery path. It never shows an active monitoring toggle.
- Broad installed-app visibility uses an in-app disclosure/control rather than pretending Android provides a runtime revoke switch. The alternative path remains useful, and its in-app off control deletes local inventory and stops related use.
- Notification, battery optimisation, selected-file, online lookup, certificate, and other access requests occur only at the user action that needs them. No permission bundle is permitted.

## 8. Adaptive and responsive layout

Use Material 3 adaptive window width classes based on the actual window, not the device model or orientation. UI must recompose correctly across resize, fold/unfold, split-screen, ChromeOS windowing, keyboard appearance, and display-size change.

| Window width | Navigation | Content layout | Required behaviour |
|---|---|---|---|
| Compact `<600dp` | Bottom navigation | One content pane; full-width within 20dp gutters | One-column lists; sheets may be near full width; never rely on horizontal space |
| Medium `600-839dp` | Navigation rail | One pane or list-detail where a selected object exists | Bounded readable content; side-by-side detail only when both panes remain usable |
| Expanded `>=840dp` | Navigation rail | List-detail for Apps, Network, findings, reports, and Help | List remains independently scrollable; selected detail preserves context; do not stretch cards edge-to-edge |

Additional layout rules:

- Default content max width is `720dp` for reading/form screens and `1200dp` for list-detail/data surfaces. Center within excess space.
- A modal or bottom sheet has a bounded readable width; switch to a centred dialog/sheet layout when a bottom sheet would be excessively wide.
- In a list-detail layout, the list is at least `320dp`; detail is at least `400dp`; otherwise use a single-pane push route.
- Fold hinges, cut-outs, system bars, and IME insets must not obscure a primary action, capture stop button, or active-session banner.
- Network tables use a selected-row detail pane on expanded layouts. On compact, show a condensed two-line row and open detail; never squeeze six technical columns onto a phone.
- Pointer/hover may reveal a tooltip or overflow affordance but cannot gate a core action. Right-click-equivalent menus must have a visible overflow alternative.

### 8.1 Required preview/viewports

Every reusable component and key screen has stable previews/screenshot fixtures at:

- `360 x 800dp` compact phone;
- `411 x 891dp` large phone;
- `600 x 960dp` medium/folded tablet width;
- `840 x 900dp` expanded tablet/ChromeOS width;
- light and dark appearance;
- English and Hindi, plus a pseudo-localised 40% expansion fixture;
- 1.0x and 2.0x font/display scale; and
- Simple, Advanced, and any active Sensitive Advanced banner state that applies.

## 9. Accessibility, localisation, and content rules

### 9.1 Accessibility acceptance contract

The UI targets WCAG 2.2 AA alongside current Android accessibility guidance.

- All core journeys work with TalkBack, Voice Access, Switch Access, hardware keyboard, and magnification.
- Every critical target is at least 48 x 48dp. Text contrast meets 4.5:1 for normal text and 3:1 for large text in light/dark/focused/disabled states.
- At 200% font/display scaling, no CTA, security finding, status, evidence, or recovery action is clipped, overlapped, hidden, or made unreachable.
- Focus order follows visual order. Initial focus is the title or material state, never an illustration. Expanding content retains focus; live updates never steal it.
- Buttons/switches expose target, current state, and consequence. Example: "Network protection, paused. Start monitoring to apply active rules."
- State announcements use meaningful outcomes, for example "Domain blocked" rather than "Done." Announce grouped live-event counts only when useful; never read every network event.
- No essential information auto-dismisses. Undo respects accessibility timeout and has a persistent alternative.
- Critical paths have an explicit visible action; no drag, swipe, long press, hover, colour, haptic, sound, or animation is the only way to understand or act.
- Charts have a text summary and accessible list/table equivalent. Technical values are selectable.
- Back/Escape closes transient layers; Tab order is visual order; Enter/Space activates focused controls; focus indicators are always visible.

### 9.2 Language and mixed-script contract

- Launch UI is professionally written in English and Hindi. Language names render in their own script and use no flags.
- Follow supported device language by default; always offer English and an in-app language choice.
- Reserve 30-40% expansion in all buttons, chips, tables, card headers, navigation labels, and settings rows.
- Human-review every permission, warning, destructive action, limitation, status phrase, and sensitive-data disclosure in both languages. Keep a controlled glossary across app, notifications, Help, policy, and reports.
- Use simple Indian English and accessible Hindi. Avoid bureaucratic copy, unexplained jargon, judgement about sideloading, and casual Hinglish as a formal default.
- Support RTL layout at the system level; do not concatenate direction-sensitive strings. Safely isolate app names, domains, package names, IPs, hashes, files, and numbers so mixed-script content cannot spoof visual order.
- Country/server location is contextual evidence, not a danger label. UPI/banking apps are not suspicious merely for handling sensitive functions.

### 9.3 Content hierarchy and voice

- Sentence case; direct, calm, factual language.
- Lead with what happened and what it means. Distinguish observation, interpretation, confidence, recommendation, source/time, and limitation.
- Prefer "No urgent issues found" with scope/timestamp over "All clear" or "Your phone is safe."
- Use a precise action label: "Stop capture", "Open VPN settings", "Keep current VPN", "Erase selected data", never generic "OK" for a consequential action.
- One visible filled primary action; at most two visually secondary actions before overflow, except independently actionable list rows.

## 10. Feature-family composition requirements

The product blueprint owns detailed screen IDs and copy. The implementation must use the following compact composition rules so that every family stays coherent while sharing the same shell.

| Family | Required Simple composition | Advanced addition | Sensitive Advanced addition |
|---|---|---|---|
| Onboarding `O-00..O-07` | Welcome, privacy, first-check scope, just-in-time app visibility, truthful progress, result/coverage | None in first-run | Never offered |
| Home/findings `H-01..H-08` | `StatusHeader`, one next action, `CoverageStrip`, ranked findings/activity | Collapsed evidence source/technical detail | Global active session/certificate cleanup banner only |
| Apps `A-01..A-12` | Identity, access, context, findings, simple actions/search/filter | Package/signing/components/SDKs/hashes/version comparison | No sensitive data automatically revealed |
| APK/link `K-01..K-09`, `L-01..L-04` | User-selected file/link only; safe preflight/progress/result; exact online disclosure when needed | Technical evidence/export/comparison | No implicit capture/content access |
| Network/firewall `N-01..N-21` | Engine capsule, local VPN primer, app-first connection feed, simple rules, recovery | Technical connection details, rule editor, bounded capture/export | TLS/payload/root/streaming, individually gated |
| Checkup `C-01..C-07` | Ranked check results, guided Android handoff, post-return verification | Detailed evidence and diagnostic detail | Not applicable unless a separately gated sensitive check is designed |
| Reports `R-01..R-05` | Smallest useful scope, privacy/redaction preview, local generation, save/share/delete | Technical formats/capture evidence where authorised | Explicit destination/session disclosure before external transfer |
| Settings/support `S-01..S-18` | Privacy/access, data/retention, language, accessibility, help, legal | Advanced preference/diagnostics | Sensitive workspace, active session, certificate and cleanup controls |

## 11. Visual QA and release acceptance

### 11.1 Design review evidence

For every implemented screen/route, the owning feature must provide:

1. A state inventory mapped to applicable `UiState` values.
2. Light/dark screenshots at required compact and expanded viewports.
3. English, Hindi, long pseudo-localised, and 200% scale evidence for any text-heavy/high-impact screen.
4. Simple/Advanced/Sensitive Advanced evidence where the screen changes by mode.
5. A TalkBack semantic capture or manual test note for the primary task.
6. The screen ID/distribution tag from the blueprint and a traceable acceptance test.

### 11.2 Automated visual/semantic checks

Automate, at minimum:

| Check | Minimum passing rule |
|---|---|
| Compose semantics | Top-level navigation labels, screen title, primary action, status/capsule state, and visible controls are discoverable by semantic label/role/state |
| Navigation | Four roots, back-stack, deep-link recovery, reselection, and system-handoff return route behave deterministically |
| Screenshot regression | Approved fixtures cover empty, loading, content, partial, offline, stale, error, light/dark, compact/expanded, and mode variants |
| Layout | No clipped/overlapping core content at 200% scale or required width classes; IME/insets leave primary/stop controls reachable |
| Contrast/colour independence | Token contrast is measured; monochrome fixture still distinguishes severity, coverage, enforcement, and selected state |
| Action state | Working controls prevent duplicate dispatch; failed actions restore prior UI and show truthful recovery |
| Sensitive visibility | Any active capture, TLS inspection, root capture, or stream produces a global reachable banner/stop path in all modes |

Screenshot baselines must use deterministic fixtures and a fixed locale, time, and font scale. Dynamic data, clock values, connection counts, and icons must be injected/stabilised so visual tests detect layout regressions rather than unrelated variance.

### 11.3 Manual visual and interaction gate

The following are mandatory before a feature is accepted:

- Run all critical flows on a compact phone, tablet/foldable, and ChromeOS/resizable window where relevant.
- Complete core tasks with TalkBack, keyboard, and 200% font/display scale. Check visual order, spoken order, focus return, and hidden/disabled explanation.
- Validate light/dark mode, colour-vision/monochrome legibility, reduced motion, haptic/sound-off preferences, English, Hindi, and mixed-script object names.
- Validate offline, low-storage, denied/revoked access, another-VPN conflict, app process death/restart, and engine interruption UI recovery for relevant features.
- Test locally stored data/retention/share/delete status against actual state; no visual state may claim deletion, active protection, a successful handoff, or a verified certificate removal without evidence.
- Rehearse every sensitive session start, active indicator, stop, cleanup, and Simple-mode visibility. TLS setup must prove selected scope, bank/UPI/auth exclusion defaults, certificate removal, and verified cleanup.

### 11.4 Visual acceptance checklist

A screen is complete only when every applicable statement is true:

- [ ] One novice can identify what screen they are on, what happened, what has not been checked, and the next action without opening technical detail.
- [ ] There is at most one filled primary CTA before overflow and no equal-priority clutter.
- [ ] Status, coverage, engine state, confidence, freshness, source, and limitation are not conflated.
- [ ] Default, loading, background, success, empty, partial, offline, stale, capability-needed, denied, error, and recovery states are designed where applicable.
- [ ] Existing data persists through refresh/error and retry does not duplicate work.
- [ ] A denial/cancelled system prompt leaves a useful path and says what stayed unchanged.
- [ ] Actions are verified before final UI, reversible where possible, and recoverable beyond a transient snackbar.
- [ ] All content/action remains usable at compact width and 200% scale, with safe insets/IME behaviour.
- [ ] TalkBack/keyboard semantics, focus order, visual focus, text contrast, non-colour state, motion preferences, and localisation rules pass.
- [ ] Advanced content increases detail without changing the core conclusion. Active sensitive behaviour remains visible and stoppable from Simple mode.
- [ ] Any data transfer/sensitive capability has a dedicated readable disclosure, affirmative action, retention/exposure statement, active state, stop path, and cleanup path.
- [ ] The UI remains calm: no unsupported safety guarantee, fear theatre, misleading activation state, or unnecessary alert/prompt.

## 12. Scaffold adoption sequence

This sequence keeps the existing welcome experience useful while replacing its one-off layout with the shared contract. It is an implementation ordering aid, not a phased product-scope reduction.

1. Establish theme tokens, typography, shapes, dimensions, previews, `SentinelScaffold`, navigation suite, and common state components.
2. Convert the current welcome/file-picker surface into `O-01`, `K-01`, and their stateful routes without duplicating theme/card/button code.
3. Build the four root destinations and their common shell/state variants before adding deep detail screens.
4. Add Home/Apps/APK/Link/Checkup/Network/Reports/Settings feature routes by the shared object, disclosure, and state contracts.
5. Add Advanced evidence components and settings gating without changing default conclusions.
6. Add each Sensitive Advanced flow only through its dedicated explainer, persistent session banner, bounded control surface, and cleanup path.
7. Gate feature completion with the visual/semantic/manual QA requirements above rather than happy-path screenshots alone.

## 13. Contract change control

Any change to a status word, consent step, Sensitive Advanced scope, retention/cleanup presentation, navigation destination, or reusable component semantics requires:

1. an update to this contract and the product blueprint traceability;
2. updated visual/semantic fixtures for every affected mode and width class; and
3. manual revalidation of accessibility, disclosure comprehension, and recovery behaviour.

This prevents a visually attractive refactor from silently changing the meaning, visibility, or controllability of security-sensitive behaviour.
