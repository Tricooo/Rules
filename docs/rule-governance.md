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

- ChinaCompanyIp, ChinaIp and GEOIP consolidation requires real request-log
  evidence because removing a broad domestic range can change CDN behavior.
- GitHub versus Copilot handling of api.github.com requires connection-log
  verification; routing it wholly to either policy can split or over-broaden
  traffic.
- Sub-Store probe scripts remain unchanged until their live collections and
  cache lifecycle are verified.
- Apple Intelligence candidate domains remain disabled by default.
