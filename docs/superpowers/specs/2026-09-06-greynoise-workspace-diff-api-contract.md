# GreyNoise Workspace Diff API contract

Vendor contract verified on 2026-09-06:

- `POST https://api.greynoise.io/v3/workspaces/diff`
- required body field: `query`
- optional body fields: `source_workspace`, `target_workspace`, `size`, `next_token`, `require_both_workspaces`, `ips_from_source`
- accepted vendor workspace aliases include `greynoise`, `community`, and `personal`
- PARA11AX intentionally accepts only those aliases and never arbitrary workspace UUIDs
- response is bounded JSON operator context
