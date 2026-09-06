<!-- PARA11AX-DOC-STANDARD: GER1E/PARA11AX v1 -->
### Compatibility note

The integration intentionally uses `maltego-trx==1.7.0` for the Desktop Local Transform + generated MTZ path. Maltego archived the TRX repository in July 2026 and recommends the newer `maltego-transforms` SDK for new transform-server integrations. The current SDK is server/data-source oriented, while Graph Desktop continues to document Local Transforms and the TRX MTZ workflow remains supported for existing local integrations.

This adapter is isolated behind `gateway_client.py` and `mapper.py` so the Maltego transport can be replaced with the current SDK later without changing the PARA11AX Evidence v2 contract or provider integrations.

Compatibility scope is deliberately narrower than the full analyst shell. Native Shodan commands, User Scanner, and GreyNoise Project Swarm `swarm search`, `swarm get`, `swarm unique`, `swarm timeseries`, and `swarm export` remain specialist operator surfaces rather than Maltego transforms. A future Maltego transport migration must not silently convert those operator-context contracts into Evidence v2 graph transforms. See [`../docs/SHELL.md`](../docs/SHELL.md) and [`../docs/GREYNOISE-SWARM.md`](../docs/GREYNOISE-SWARM.md).

---

<p align="center"><sub>PΛRΛ11ΛX // PER ASPERA AD ASTRA</sub></p>