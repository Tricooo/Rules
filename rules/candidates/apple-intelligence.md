# Apple Intelligence candidate register

No public community list is treated as proof of complete coverage for the
current iOS beta. Production profiles intentionally use a small inline baseline.

## Official Apple connectivity baseline

Apple currently lists the following hosts under “Apple Intelligence, Siri, and
Search” in its enterprise-network document. Checked 2026-07-15:
[Apple support 101555](https://support.apple.com/zh-tw/101555).

- guzzoni.apple.com
- smoot.apple.com and subdomains
- apple-relay.apple.com and subdomains
- apple-relay.cloudflare.com and subdomains
- apple-relay.fastly-edge.com and subdomains
- cp4.cloudflare.com

This is an official connectivity list, not proof of complete iOS 27 beta
coverage or proof that every host is AI-exclusive. In particular, Apple says
`*.smoot.apple.com` is also used by Spotlight, Safari, News, Messages, Music,
and other search flows.

## Community long-term observation

- siri.apple.com and subdomains

This suffix remains in production because it is narrowly scoped and has a long
Siri-routing history. Apple does not list it separately in the current section
above, so it is not labelled official here. `seed-sequoia.siri.apple.com` is
already covered and must not be duplicated.

## Candidate: request-log verification required

- cp10.cloudflare.com
- apple-relay.akamaized.net and subdomains
- humb.apple.com and subdomains
- sequoia.apple.com and subdomains
- appleintelligencefeedback.care.apple.com
- gspe1-ssl.ls.apple.com
- gateway.icloud.com

## Candidate likely shared with other Apple services

- apple-relay.mask.apple-dns.net: likely overlaps Private Relay infrastructure.
- humb.apple.com: Apple currently documents it for device setup, Tap to Pay,
  and ID verification, not under Apple Intelligence.
- gspe1-ssl.ls.apple.com: also associated with geolocation-dependent Apple
  services.
- gateway.icloud.com: not proven to be AI-exclusive.

## Rejected as over-broad

- icloud.com
- apple-dns.net
- apps.mzstatic.com
- 17.250.0.0/16
- mask.icloud.com, mask-api.icloud.com and mask-h2.icloud.com

To promote a candidate, clear recent requests, trigger one Siri or Apple
Intelligence action, reproduce it on the intended network, record the matched
hostname and policy, and verify that the hostname is not used by an ordinary
Apple flow such as iCloud Drive, Photos, App Store or Private Relay.
