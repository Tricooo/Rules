# Shared domains removed from AI production rules

The following observations are retained for provenance but must not be loaded as
a Surge RULE-SET. They are shared infrastructure or lack enough ownership
evidence to define an AI egress.

| Domain | Previous list | Reason |
| --- | --- | --- |
| cdn.usefathom.com | Claude | shared analytics CDN |
| 160.79.104.0/23 | Claude | undocumented non-exclusive IP range |
| 2607:6bc0::/48 | Claude | undocumented non-exclusive IP range |
| googleapis.com | Gemini | shared by many Google APIs |
| googleusercontent.com | Gemini | shared Google content hosting |
| clients4.google.com | Gemini | generic Google client endpoint |
| clients6.google.com | Gemini | generic Google client endpoint |
| apis.google.com | Gemini | generic Google API loader |
| developerprofiles.google.com | Gemini | developer account service |
| colab.google.com | Gemini | separate Google product |
| featureassets.org | Grok | ownership and exclusivity unproven |
| xai.chronosphere.io | Grok | observability endpoint |
| browser-intake-datadoghq.com | Other AI | shared Datadog telemetry |
| launchdarkly.com | Other AI | shared feature-flag platform |
