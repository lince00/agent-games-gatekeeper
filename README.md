# agent-games-gatekeeper

Proof Gatekeeper endpoint for zkVerify Agent Games Season 01.

Deterministic APPROVE/REJECT decisions with local Groth16 proofs
(snarkjs + official gatekeeper circuit). No private keys, no
transactions, no spending — this server only judges and proves.

- `gatekeeper/` — the Node.js endpoint (`POST /gatekeeper`, `GET /health`)
- `circuits/` — the official gatekeeper circuit (`gatekeeper.wasm`,
  `gatekeeper_final.zkey`, `verification_key.json`)

See `gatekeeper/README.md` for the run, deploy, and protocol details.
