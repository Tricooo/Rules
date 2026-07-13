# Apple Intelligence candidate register

No public community list is treated as proof of complete coverage for the
current iOS beta. Production profiles intentionally use a small inline baseline.

## Current production baseline

These entries are retained because they are narrowly scoped and form the current
working Siri baseline. They are not described as an official completeness list.

- guzzoni.apple.com
- siri.apple.com and subdomains
- smoot.apple.com and subdomains
- apple-relay.apple.com and subdomains
- apple-relay.cloudflare.com and subdomains
- apple-relay.fastly-edge.com and subdomains
- cp4.cloudflare.com

## Candidate: request-log verification required

- cp10.cloudflare.com
- apple-relay.akamaized.net and subdomains
- humb.apple.com and subdomains
- sequoia.apple.com and subdomains
- appleintelligencefeedback.care.apple.com

## Candidate likely shared with other Apple services

- gspe1-ssl.ls.apple.com: also associated with geolocation-dependent Apple
  services.
- gateway.icloud.com: not proven to be AI-exclusive.
- apple-relay.mask.apple-dns.net: likely overlaps Private Relay infrastructure.

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
