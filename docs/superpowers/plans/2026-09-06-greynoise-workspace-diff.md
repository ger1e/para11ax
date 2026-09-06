# GreyNoise Workspace Diff implementation scope

Approved bounded design:

- add `swarm diff` as a Web-only read operator under the existing authenticated `/api/para11ax/swarm` gateway;
- fixed upstream `POST https://api.greynoise.io/v3/workspaces/diff`;
- require bounded GNQL query text;
- expose only `personal`, `community`, and `greynoise` workspace aliases, never arbitrary workspace UUIDs;
- default comparison: `personal` -> `greynoise`, `source-only`, size 10;
- modes map to GreyNoise booleans: `source-only` => `ips_from_source=true`, `both` => `require_both_workspaces=true`, `all` => both false;
- support bounded opaque pagination token and size 1..100;
- return sanitized JSON as `greynoise-swarm` operator context;
- no automatic Evidence v2 mutation;
- keep existing session search/get/unique/timeseries/export behavior unchanged;
- verify RED before production implementation, then full Tooling smoke + CodeQL before merge.
