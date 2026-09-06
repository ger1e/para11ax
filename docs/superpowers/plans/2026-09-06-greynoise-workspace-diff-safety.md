# GreyNoise Workspace Diff safety boundary

The Workspace Diff feature must not:

- expose arbitrary caller-supplied upstream URLs or methods;
- expose arbitrary workspace UUIDs;
- reflect `GREYNOISE_API_KEY`;
- auto-promote diff output into Evidence v2;
- permit unbounded GNQL, response size, pagination token, or result size;
- alter existing Swarm export semantics.
