# Rule governance and migration design

## Objective

Keep domestic applications reliable while giving AI services a stable and
intentional egress. A rule is not accepted merely because it appears in a
community list. It must have a clear owner, narrow scope and a rollback path.

## Design principles

1. One source owns one concern. Do not stack several large lists for the same
   traffic class.
2. Exact service domains precede generic Apple, Google and proxy rules.
3. Domestic direct coverage is a maintained baseline, not a growing collection
   of one-off application patches.
4. Shared telemetry, CDN, analytics and feature-flag domains never define an AI
   policy.
5. Apple Intelligence candidates stay disabled until a Surge request log ties
   them to a real Siri or Apple Intelligence action.
6. iOS and macOS share rule sources, but keep separate policy names and
   platform-only rules. macOS keeps Emoji and PROCESS-NAME support; iOS does not.
7. MITM is outside this migration. URL-REGEX rules requiring HTTPS decryption
   are therefore not accepted.
8. Dedicated AI egress is service-scoped rather than global on both platforms.
   Only ChatGPT, Claude and Gemini may use Direct-AI or CF-AI-Auto. Other AI
   services default to Auto Selection, while Apple Intelligence defaults to US
   Node to avoid unsupported-region drift. macOS keeps Emoji policy names and
   its PROCESS-NAME fallback; those presentation and platform capabilities do
   not change the egress contract.

## Why the old AI lists were unsafe

- Gemini included all googleapis.com and googleusercontent.com traffic plus
  generic clients4/clients6 hosts. These domains serve many unrelated Google
  products and could move ordinary application traffic to an AI egress.
- Other AI included global LaunchDarkly and Datadog intake domains used by many
  unrelated applications.
- Claude included a shared analytics host and undocumented IP ranges.
- Grok included shared asset and observability domains and redundant exact
  hosts already covered by x.ai or grok.com.
- Apple Intelligence included all icloud.com, apple-dns.net, App Store static
  assets and a broad Apple IP range. These are not AI-exclusive.

## Rule ordering contract

The production profile order is:

1. LAN and narrowly scoped compatibility exceptions.
2. iCloud Private Relay.
3. OpenAI and personal production AI lists.
4. Inline Apple Intelligence baseline.
5. Maintained domestic direct domain baseline.
6. Generic Apple, Google, social and media lists.
7. Proxy/GFW rules.
8. Domestic IP and GEOIP fallback.
9. Optional filtering rules.
10. FINAL.

The first-match rule model means later exact rules cannot repair a broad rule
placed above them. Static validation therefore blocks known broad AI suffixes.

## Implemented profile safeguards

- The Apple-owned 17.0.0.0/8 range is not present in skip-proxy. Apple traffic
  must enter the Surge rule engine instead of bypassing all domain policies.
- iOS uses ChinaCompanyIp plus GEOIP,CN. ChinaIp is intentionally not stacked
  on top because it largely duplicates the GEOIP fallback. macOS follows the
  same model.
- iCloud Private Relay and all AI rules precede domestic direct, generic Apple,
  advertising and privacy lists on both platforms.
- iOS keeps optional advertising and privacy lists disabled. macOS retains the
  lighter lists but evaluates them after the domestic GEOIP fallback.
- The normal CF smart group includes the base CF proxy and excludes names ending
  in -AI. The AI CF smart group includes only -AI proxies.
- Both profiles default FINAL to My Node so newly blocked or not-yet-catalogued
  domains still receive a proxy route. The maintained direct domain baseline,
  ChinaCompanyIp and GEOIP,CN keep known domestic traffic direct; DIRECT remains
  an explicit manual option in the Final group.
- FINAL is the rule-system catch-all. The Final policy group intentionally uses
  `select`; a Surge `fallback` group only chooses the first available policy by
  health check and cannot determine whether an unmatched destination needs a
  proxy. macOS still defaults FINAL to My Node through its Auto-SSID topology.
- Neither profile defines an AI Egress group. ChatGPT, Claude and Gemini directly
  expose only the two dedicated AI policies; Copilot, Perplexity, Other AI and
  Grok expose ordinary Auto/Manual/US policies; Apple Intelligence exposes the
  stable US group before ordinary manual alternatives.
- encrypted-dns-follow-outbound-mode remains false. The AliDNS and DNSPod DoH
  endpoints bootstrap directly and do not drift with a selected AI egress.
- 100.64.0.0/10 remains excluded for the current external Tailscale topology.
  Remove that exclusion before routing Tailnet traffic through Surge's own
  Tailscale/VIF path.

The profile-contract validator has regression tests for the Apple bypass,
AI-before-broad ordering, China IP duplication, unused composite groups,
cross-platform service-scoped AI egress, indirect dedicated-policy leakage,
macOS Emoji names and proxy-first FINAL behavior. It emits warnings, without
exposing values, when MITM material has no hostname or a device-specific BSSID
still needs human confirmation.

## macOS rollout evidence (2026-07-14)

- The formal iCloud profile was backed up before migration, then synchronized
  from the checked workspace copy and accepted by Surge's bundled parser.
- `surge-cli reload` succeeded. The runtime original and formal profile both
  expose 50 policy groups with identical names; neither contains AI Egress.
- The effective profile retains `PROCESS-NAME,assistantd`, uses `FINAL,🧭 Final`,
  and keeps My Node as the Final group's first policy.
- Persisted selections using the retired `🇺🇲 US Node` spelling were migrated.
  Apple Intelligence now selects `🇺🇸 US Node`; Other AI selects Auto Selection.
- Direct-AI responded to a live policy probe. CF-AI-Auto, US Node and Auto
  Selection each returned at least one available member during group probes.
- The Proxy and MITM sections are byte-for-byte unchanged from the pre-migration
  backup. MITM, short-lived subscription URLs, DNS, Host and TUN settings were
  intentionally outside this change.

These controller and reachability checks do not prove application semantics.
Siri/Apple Intelligence actions, ChatGPT Voice and representative domestic apps
still require Recent Requests evidence before being marked end-to-end verified.

## Release and rollback

- Production profiles point only to release.
- main can advance without changing devices immediately.
- A release is promoted only after local validation and raw URL checks.
- iOS and macOS profile references are changed together when a file is renamed.
- The iOS and macOS profiles each receive a timestamped local backup before
  migration.
- A regression is rolled back by change family. Do not add an app-specific
  exception until the request log identifies the actual matching rule.

## Deferred decisions

- GitHub versus Copilot handling of api.github.com requires connection-log
  verification; routing it wholly to either policy can split or over-broaden
  traffic.
- Sub-Store probe scripts remain unchanged until their live collections and
  cache lifecycle are verified.
- Apple Intelligence candidate domains remain disabled by default.
- The macOS BSSID selector remains until the owner confirms whether the old
  company Wi-Fi mapping is still needed.
