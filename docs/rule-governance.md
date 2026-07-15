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
9. A process-wide DIRECT rule is not an application compatibility fix. It can
   bypass every service rule above FINAL, including the dedicated ChatGPT,
   Claude and Gemini policies. Use maintained domain/IP ownership layers or a
   narrow documented exception instead.

## Why the old AI lists were unsafe

- The former OpenAI list mixed ChatGPT with global Auth0, Stripe, Sentry,
  LaunchDarkly, Segment, Intercom and other shared providers, plus a whole
  Vultr ASN. Recent Requests proved that ordinary Arc telemetry was actually
  being sent to Direct-AI. The production ChatGPT list now contains only
  OpenAI-owned product domains.
- ChatGPT Voice no longer relies on old community IPs or a shared ASN. Its
  exact IP snapshot is generated from OpenAI's maintained
  `chatgpt-voice.json`; a scheduled read-only workflow reports drift.
- The former “Copilot” source mixed Microsoft Copilot, old OpenAI rules and
  shared DigitalOcean/Vultr ASNs. The replacement uses GitHub's Copilot
  allowlist and deliberately leaves generic `github.com`, `api.github.com` and
  shared Azure downloads to ordinary GitHub/FINAL routing.
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
8. Domestic IPv4/GEOIP fallback, followed by the mainland IPv6 supplement.
9. Optional filtering rules.
10. FINAL.

The first-match rule model means later exact rules cannot repair a broad rule
placed above them. Static validation therefore blocks known broad AI suffixes.

## Implemented profile safeguards

- The Apple-owned 17.0.0.0/8 range is not present in skip-proxy. Apple traffic
  must enter the Surge rule engine instead of bypassing all domain policies.
- Both profiles keep ChinaCompanyIp plus GEOIP,CN for the existing IPv4/domain
  behavior. They add SukkaW's maintained mainland IPv6-focused ruleset
  immediately after GEOIP,CN. This fills the dual-stack gap without re-adding
  thousands of duplicate IPv4 CIDRs.
- The mainland IPv6 RULE-SET uses `no-resolve`. It matches literal IPv6 targets
  without DNS; for a domain that reached GEOIP,CN, it reuses the address that
  GEOIP already resolved and can catch a CN IPv6 range missed by the MMDB.
  This ordering follows Surge's documented third `no-resolve` behavior and does
  not add another lookup. See [Understanding Surge](https://manual.nssurge.com/book/understanding-surge/en/).
- ChinaIp is intentionally not stacked on top because it largely duplicates the
  IPv4 GEOIP fallback. macOS follows the same model.
- iCloud Private Relay and all AI rules precede domestic direct, generic Apple,
  advertising and privacy lists on both platforms.
- iOS keeps optional advertising and privacy lists disabled. macOS retains the
  lighter lists but evaluates them after the domestic GEOIP fallback.
- The normal CF smart group includes the base CF proxy and excludes names ending
  in -AI. The AI CF smart group includes only -AI proxies.
- Both profiles default FINAL to My Node so newly blocked or not-yet-catalogued
  domains still receive a proxy route. The maintained direct domain baseline,
  ChinaCompanyIp, the mainland IPv6 ruleset and GEOIP,CN keep known domestic
  traffic direct; DIRECT remains an explicit manual option in the Final group.
- FINAL is the rule-system catch-all. The Final policy group intentionally uses
  `select`; a Surge `fallback` group only chooses the first available policy by
  health check and cannot determine whether an unmatched destination needs a
  proxy. Both profiles add `dns-failed` to FINAL, as required by Surge for a
  proxy default after an earlier IP/GEOIP rule triggers a failed local lookup.
  macOS still defaults FINAL to My Node through its Auto-SSID topology. See the
  [official FINAL rule documentation](https://manual.nssurge.com/rule/final.html).
- Neither profile defines an AI Egress group. ChatGPT, Claude and Gemini directly
  expose only the two dedicated AI policies; Copilot, Perplexity, Other AI and
  Grok expose ordinary Auto/Manual/US policies; Apple Intelligence exposes the
  stable US group before ordinary manual alternatives.
- ChatGPT domain and Voice-IP rules point to reviewed production files on the
  `release` branch. The Voice RULE-SET uses `no-resolve`; it matches OpenAI's
  published media endpoints without forcing DNS or widening to a cloud ASN.
- Active general proxy-service groups (X, Reddit, Proxy Media and Google FCM)
  default to My Node. DIRECT remains a manual last-resort choice, rather than a
  silent default that can break services on a mainland network.
- macOS has no active process-wide DIRECT rule. The only process supplement is
  `assistantd` to Apple Intelligence; application compatibility remains owned by
  domain and domestic IP layers.
- encrypted-dns-follow-outbound-mode remains false. The AliDNS and DNSPod DoH
  endpoints bootstrap directly and do not drift with a selected AI egress.
- 100.64.0.0/10 remains excluded for the current external Tailscale topology.
  Remove that exclusion before routing Tailnet traffic through Surge's own
  Tailscale/VIF path.

The profile-contract validator has regression tests for the Apple bypass,
official/community Apple Intelligence baseline, candidate quarantine,
AI-before-broad ordering, China IP duplication, the required mainland IPv6
source/policy/no-resolve/order, process-wide DIRECT bypasses, proxy-service
defaults, unused composite groups, cross-platform service-scoped AI egress,
indirect dedicated-policy leakage, macOS Emoji names and proxy-first FINAL
behavior. It emits warnings, without exposing values, when MITM material has no
hostname or a device-specific BSSID still needs human confirmation.

## Mainland literal-IPv6 closure (2026-07-14)

- Recent Requests showed WeChat-family connections whose destination was an
  IPv6 literal under `2408:8756:f50::/48`; with no hostname, domain rules could
  never classify them.
- Direct inspection of the configured Hackl0us Country.mmdb returned no record
  for both samples. The active ACL4SSR ChinaCompanyIp list also contains no
  IP-CIDR6 entries, so the request reached the proxy-first FINAL by design.
- This is an IPv4/IPv6 coverage asymmetry, not a WeChat-domain omission. The fix
  therefore does not add the two observed /128 addresses, a WeChat process rule,
  or an unsafe all-IPv6 DIRECT rule.
- The production source is SukkaW's mainland-friendly official mirror:
  `https://ruleset-mirror.skk.moe/List/ip/china_ip_ipv6.conf`. The verified
  2026-07-14 artifact contains 1,620 IP-CIDR6 entries, no IPv4 CIDR, and one
  maintainer watermark DOMAIN entry. It covers both samples via
  `2408:8756::/31`; the main server and official mirror were byte-identical.
- Keep this rule after domain/service/proxy rules and immediately after
  GEOIP,CN. The order covers both literal destinations and a domain address that
  GEOIP already resolved but the MMDB did not classify. Removing this single
  RULE-SET line is the rollback; do not change FINAL, disable IPv6, or widen
  DIRECT to all IPv6 destinations.

## macOS rollout evidence (2026-07-14 to 2026-07-15)

- The formal iCloud profile was backed up before migration, then synchronized
  from the checked workspace copy and accepted by Surge's bundled parser.
- `surge-cli reload` succeeded. The runtime original and formal profile both
  expose 50 policy groups with identical names; neither contains AI Egress.
- The effective profile retains `PROCESS-NAME,assistantd`, uses `FINAL,🧭 Final`,
  retains the `dns-failed` fallback modifier, and keeps My Node as the Final
  group's first policy.
- Persisted selections using the retired `🇺🇲 US Node` spelling were migrated.
  Apple Intelligence now selects `🇺🇸 US Node`; Other AI selects Auto Selection.
- Direct-AI responded to a live policy probe. CF-AI-Auto, US Node and Auto
  Selection each returned at least one available member during group probes.
- The profile's Proxy and MITM sections are byte-for-byte unchanged from the
  pre-migration backup. Runtime inspection nevertheless shows that enabled
  modules add MITM host targets and that MITM/rewrite/scripting are active.
  Per the owner's decision, this migration does not remove or alter MITM; the
  distinction is documented so an empty base-profile hostname is not mistaken
  for “no decryption”.

These controller and reachability checks do not prove application semantics.
Siri/Apple Intelligence actions, an actual ChatGPT Voice session and
representative domestic apps still require device actions before being marked
end-to-end verified.

## Completion audit (2026-07-15)

- The reviewed functional release is `1d37920dc7bd3a274a6dc45887cba0a97ab610f9`.
  `main`, `release` and `codex/rules-v2` point to that object; all three raw
  ChatGPT, ChatGPT Voice and Copilot production URLs returned HTTP 200 with
  content hashes equal to the local files. The three branch CI runs completed
  successfully.
- The final local gate passed 61 unit tests, validated 19 files containing 68
  production rules, and confirmed that the current official OpenAI Voice feed
  contains 23 global host prefixes. Both workspace profiles and both formal
  iCloud profiles passed the bundled Surge parser and the profile-contract
  validator.
- After the macOS reload, all 35 external resources reported `ready=true`. The
  effective order is ProxyGFW, GEOIP,CN, the mainland IPv6 supplement, optional
  filters and `FINAL,...,dns-failed`; no active process-wide DIRECT rule exists.
- A local HTTP-proxy probe to one exact address from OpenAI's current Voice feed
  matched `ChatGPTVoice.list` and followed ChatGPT to Direct-AI. This verifies
  the routing rule and policy path, not a real in-app voice session.
- A Google FCM probe matched `GoogleFCM.list` and followed Google FCM to My Node.
  The persisted Google FCM and Final selections were explicitly migrated to My
  Node so a reload cannot silently preserve their retired selections.
- A probe to one of the observed WeChat-family IPv6 literals matched SukkaW's
  mainland IPv6 ruleset and selected DIRECT. The connection itself could not be
  established because that literal had no outgoing interface at probe time;
  only the classification and policy decision are claimed.
- A reserved `.invalid` probe caused the preceding GEOIP lookup to return an
  empty answer and then matched FINAL through My Node. This is direct runtime
  evidence for the `dns-failed` modifier and proxy-first catch-all contract.
- The macOS Wi-Fi HTTP, HTTPS and SOCKS system proxies remained disabled. The
  rollout therefore preserves the existing Enhanced/TUN-only operating mode.
- The base profile's MITM material and the active module-provided MITM hosts are
  intentionally unchanged. The five-minute provider subscription lifecycle is
  also unchanged; `ready=true` proves the current cache is usable, not that an
  expired URL can be re-imported after cache deletion.

The remaining acceptance boundary is deliberately narrow: run New Siri/Apple
Intelligence and an actual ChatGPT Voice call on the target devices, and inspect
the iPhone/iPad Recent Requests for representative domestic applications. Do
not promote candidate Apple domains or add app-specific exceptions without that
evidence.

## Release and rollback

- Production profiles point only to release.
- main can advance without changing devices immediately.
- A release is promoted only after local validation and raw URL checks.
- iOS and macOS profile references are changed together when a file is renamed.
- The iOS and macOS profiles each receive a timestamped local backup before
  migration.
- A regression is rolled back by change family. Do not add an app-specific
  exception until the request log identifies the actual matching rule.

### Profile rollback runbook

1. Keep the timestamped `bak-before-dns-failed-20260715` files beside the two
   formal profiles; do not edit the backup in place.
2. Restore the affected platform's formal profile from that backup and copy the
   same content back to the workspace copy so future edits do not reintroduce
   the failed version.
3. Run `surge-cli --check` against both the restored formal file and workspace
   copy before reloading.
4. On macOS, reload Surge and inspect the effective FINAL rule, the
   GEOIP/IPv6 ordering, external-resource readiness and relevant persisted group
   selections. On iOS, reload the profile and confirm representative traffic in
   Recent Requests.
5. Roll back a published rule release with a normal revert commit promoted to
   `release`; never rewrite branch history that active profiles may be fetching.

## Deferred decisions

- GitHub versus Copilot handling of api.github.com requires connection-log
  verification; routing it wholly to either policy can split or over-broaden
  traffic.
- Sub-Store probe scripts remain unchanged until their live collections and
  cache lifecycle are verified.
- Apple Intelligence candidate domains remain disabled by default.
- The macOS BSSID selector remains until the owner confirms whether the old
  company Wi-Fi mapping is still needed.
- The Mac Sub-Store collection URL is intentionally short-lived for provider
  risk control. Runtime cache can remain ready after refreshes start returning
  HTTP 500, but a re-import or cache purge would then have no recovery source.
  Refresh/re-sign automation must be solved with the provider; the URL is not
  replaced or published here.
- The repeated Sub-Store policy path is a maintenance concern, not twelve live
  downloads: Surge deduplicates it into one external resource. Refactor only
  after the short-lived refresh lifecycle is reproducible.
- GitHub branch protection is not enabled in this migration. CI verifies a
  pushed commit but cannot prevent an unreviewed `release` update; enabling
  protection is a separate repository-administration decision.
- For external Tailscale, the current Mac TUN exclusions are intentional. If
  System Proxy is later enabled, align `skip-proxy`; if Surge's built-in
  Tailscale is enabled, remove the TUN exclusions and add explicit Tailnet
  policy/rules instead.
