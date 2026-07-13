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

The older root-level lists are retained as compatibility mirrors. They are not
the source of truth for new profiles and may be removed only after all known
consumers have migrated.

## Repository layout

~~~text
rules/
  production/ai/   # narrow, service-owned domains used by production profiles
  candidates/      # observations and rejected broad domains; never auto-loaded
docs/               # governance and migration rationale
scripts/            # Sub-Store helpers and static validation
.github/workflows/  # validation gate
AI/ and *.list      # legacy compatibility paths
~~~

## Production URLs

Use the release branch only:

~~~text
https://raw.githubusercontent.com/Tricooo/Rules/release/rules/production/ai/Claude.list
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
| Domestic direct domain baseline | Loyalsoldier/surge-rules |
| Mature service-specific lists | blackmatrix7/ios_rule_script |
| Compatibility exceptions | selected ACL4SSR lists |
| Personal AI deltas | this repository |
| Research reference | SukkaW/Surge |

Clash-formatted repositories are not consumed directly unless every referenced
rule type has been checked for Surge compatibility.

## Change workflow

1. Put a new observation in rules/candidates or a Markdown evidence note.
2. Confirm the hostname in Surge request logs on both Wi-Fi and cellular where
   relevant.
3. Prove that the hostname is service-specific. Shared analytics, feature flag,
   CDN and generic API domains stay out of production.
4. Run python3 scripts/validate_rules.py.
5. Review the profile diff, publish to release, then update profile URLs.
6. Keep one rollback snapshot per change family.

See docs/rule-governance.md for the detailed decisions and safety boundaries.
