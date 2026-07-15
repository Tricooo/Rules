# Other AI candidate register

Candidate hostnames remain outside production until a focused Surge request log
ties them to one service and rules out shared infrastructure.

## Request-log verification required

- `trae-api-sg.mchost.guru`
  - Observed in a Trae-related flow, but the parent domain is not owned by Trae.
  - Reproduce the request from a cleared Recent Requests view and confirm the
    hostname is not shared by another application before promotion.
  - If promoted, record the observation date, network and ownership evidence in
    this register; otherwise leave `trae.ai` as the production boundary.
