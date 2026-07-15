# Tricooo Rules

Personal, evidence-gated rule deltas for Surge. This repository is intentionally
small: public upstream projects remain responsible for broad country, media and
service coverage; this repository owns only rules that need personal review.

## Branch contract

- main: staging and documentation. Changes may be reviewed here before release.
- release: production branch consumed by Surge profiles.
- Never point a production profile at an unreviewed feature branch.

## Supported format

Files under rules/production are Surge RULE-SET files. A policy is selected by
the parent RULE-SET line in the Surge profile; policy names such as DIRECT or
REJECT must never appear inside these files.

Selected older AI paths are retained as tested compatibility mirrors. The
remaining root-level lists are archival and unvalidated: new profiles must not
consume them, and they may be removed only after all known consumers have
migrated.

## Repository layout

~~~text
rules/
  production/ai/   # narrow, service-owned domains used by production profiles
  candidates/      # observations and rejected broad domains; never auto-loaded
docs/               # governance and migration rationale
script/             # legacy Sub-Store helpers
scripts/            # static validation
tests/              # profile-contract regression tests
.github/workflows/  # validation gate
AI/ and *.list      # legacy compatibility paths
~~~

## Production URLs

Use the release branch only:

~~~text
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/Claude.list
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/ChatGPT.list
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/ChatGPTVoice.list
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/Copilot.list
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/Gemini.list
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/Grok.list
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/Perplexity.list
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/OtherAI.list
~~~

Apple Intelligence remains inline in the device profiles. This keeps the Siri
baseline available even when GitHub is unreachable and prevents candidate or
Private Relay domains from being enabled accidentally.

## Source ownership

| Concern | Owner |
| --- | --- |
| iOS domestic direct domain baseline | Loyalsoldier/surge-rules |
| macOS domestic direct domain baseline | ACL4SSR ChinaDomain (retained pending runtime migration) |
| Mainland China IPv6 baseline | SukkaW-maintained mainland-friendly ruleset mirror |
| Mature service-specific lists | blackmatrix7/ios_rule_script |
| Compatibility exceptions | selected ACL4SSR lists |
| Personal AI deltas | this repository |

Clash-formatted repositories are not consumed directly unless every referenced
rule type has been checked for Surge compatibility.

## Change workflow

1. Put a new observation in rules/candidates or a Markdown evidence note.
2. Confirm the hostname in Surge request logs on both Wi-Fi and cellular where
   relevant.
3. Prove that the hostname is service-specific. Shared analytics, feature flag,
   CDN and generic API domains stay out of production.
4. Run python3 -m unittest discover -s tests -v and python3 scripts/validate_rules.py.
   The suite also verifies that every supported legacy AI mirror has the same
   active rules as its production source.
   Run `python3 scripts/sync_chatgpt_voice.py --check` when reviewing the
   scheduled Voice-prefix drift alert; the source is OpenAI's current JSON, not
   a shared cloud ASN.
5. Run scripts/validate_surge_profile.py with --platform ios or --platform mac
   against the local profile copy. The validator reports references and line
   numbers without printing proxy credentials. It also enforces the agreed AI
   order, stable defaults, platform naming, subnet selectors, CF filters and
   domestic-IP de-duplication and the mainland IPv6 fallback contract.
   Proxy-first FINAL rules must also retain `dns-failed`, so a local lookup
   failure can still be handed to the selected proxy policy.
6. Review the profile diff, publish to release, then update profile URLs.
7. Keep one rollback snapshot per change family.

See docs/rule-governance.md for the detailed decisions and safety boundaries.
