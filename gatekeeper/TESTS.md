# Test results — Proof Gatekeeper endpoint

All tests run locally on 2026-11-16 (~02:00–02:15 WIB). No secrets, no deploy,
no network calls to zkVerify mainnet. Test secret used in e2e was the clearly
labelled fake value `test-secret-NOT-REAL-do-not-use-in-production`.

## 0. Circuit artifacts (official, from agentgames.zkverify.io)

| file | size | sha256 |
| --- | --- | --- |
| `../circuits/gatekeeper.wasm` | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `../circuits/gatekeeper_final.zkey` | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `../circuits/verification_key.json` (exported from the zkey with snarkjs 0.7.6; the site returns 404 for this file) | 8,089 | `6ce4899b3bc74d6a5c10ede61daf8820716982e1ef7e6778a5a8872ddaf28221` |

Verification key: Groth16, curve bn128, **nPublic = 13**, witness size 647.
Registered vk hash (zkVerify mainnet, from `/api/circuit-info`):
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

## 1. Circuit signal discovery (probing the compiled wasm)

The official docs do not publish the circuit's input signal names. Verified by
probing the wasm's `getInputSignalSize` (FNV-1a hash of the name): exactly the
13 camelCase names below exist (size 1 each) and `getInputSize() == 13`:

`taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash,
salt, decision`

Public signals (13, output-then-public order), confirmed from generated proofs:

```
[ commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId ]
```

Confirmed locally: `public[0] == Poseidon(salt, taskId)` is **true**
(`Poseidon(taskId, salt)` is false). Task-id encoding used: the string's
UTF-8 bytes as a bigint (e.g. `"gk_24_9d1"` -> `1907751597477446902833`).
256-bit hashes are reduced mod the bn128 field prime before entering the
circuit (e.g. the official vk hash appears in the public signals as
`4836144126773920907502496244340012141761656471453348073975163706578152814510`).

## 2. Circuit matrix test (`node test-circuit.mjs`, 12 cases)

Sample values from the official event page (minimum 1000, balance 1460,
expiry 19842201, current 19832000, amount 500, cap 1000, recipient ==
condition recipient, vk hashes equal):

| case | result |
| --- | --- |
| VALID + APPROVE | PASS — proof generated in 886 ms (first run, incl. wasm load), `snarkjs groth16 verify` OK, 13 public signals |
| VALID + REJECT | PASS — witness generation correctly REFUSED (`Assert Failed. Error in template GatekeeperEvaluation_79 line: 102`) |
| VK_SUBSTITUTION + APPROVE | PASS — refused (same assertion) |
| VK_SUBSTITUTION + REJECT | PASS — proof OK, verify OK (350 ms) |
| THRESHOLD_MISMATCH + APPROVE | PASS — refused |
| THRESHOLD_MISMATCH + REJECT | PASS — proof OK, verify OK (297 ms) |
| EXPIRED + APPROVE | PASS — refused |
| EXPIRED + REJECT | PASS — proof OK, verify OK (294 ms) |
| RECIPIENT_MISMATCH + APPROVE | PASS — refused |
| RECIPIENT_MISMATCH + REJECT | PASS — proof OK, verify OK (287 ms) |
| AMOUNT_OVERFLOW + APPROVE | PASS — refused |
| AMOUNT_OVERFLOW + REJECT | PASS — proof OK, verify OK (273 ms) |

**12/12 pass.** Proof generation takes ~270–900 ms — far below the 60 s
platform deadline. The circuit refuses any decision that contradicts the
inputs, so a proof can only ever be produced for the correct decision.

## 3. Module self-test (`npm run selftest`, 12 cases)

Same matrix as §2 but routed through the real `decision.mjs` +
`buildCircuitInput` code (decision correctness + circuit agreement checked
together). **12/12 pass, exit 0.**

## 4. End-to-end HTTP test (`node e2e-test.mjs`, 11 checks)

Real `server.mjs` spawned with a fake test secret; response signatures
verified independently with Node `crypto`; proofs re-verified with snarkjs.

| check | result |
| --- | --- |
| GET /health ok + HMAC configured + self-test OK | PASS (startup self-test 1100 ms) |
| Preflight -> `{ok:true, protocolVersion:"v1"}` + valid signature | PASS |
| Valid task -> APPROVE/VALID_CONDITION + verifying proof + valid sig | PASS (351 ms end-to-end) |
| Same task_id replay -> byte-identical cached body | PASS |
| Trap task -> REJECT/VK_SUBSTITUTION + verifying proof | PASS |
| Reused proof_tx, different task -> REJECT/PROOF_REUSED, no proof | PASS |
| Bad signature -> 401 | PASS |
| Missing signature -> 401 | PASS |
| Malformed JSON (signed) -> 400 | PASS |
| Unknown route -> 404 | PASS |
| POST /agent alias -> APPROVE | PASS |

**11/11 pass, exit 0.**

## 5. No-secret boot test (manual)

Server started with `AGENT_GAMES_HMAC_SECRET` unset:
- `GET /health` -> `ok:false, hmacConfigured:false`, circuits present,
  self-test OK.
- Signed preflight -> **503** (refuses to answer without a configured secret).

No `.env` file exists in the repo (only `.env.example`); no secret was ever
written to disk. The only secret-like string in the tree is the labelled fake
test secret inside `e2e-test.mjs`.

## 6. What is NOT tested here (needs the account holder / live platform)

- **Preflight against the real platform** — needs the real HMAC secret from
  the dashboard (Rotate Secret). The signature format (lowercase hex
  HMAC-SHA256) follows the standard convention; the docs do not spell it
  out, so preflight is the confirmation step.
- **Practice task with a real signed envelope** — confirms the task-id
  string->field encoding and the response schema end-to-end. If the platform
  rejects a proof, the first thing to revisit is the `taskId` encoding in
  `decision.mjs` (`buildCircuitInput`).
- **Kurier / zkVerify mainnet submission** — not implemented on purpose:
  the response schema only requires the local Groth16 proof; on-chain
  submission needs a Kurier API key (not available) and is not required to
  score. Documented as an optional later step in README.md.
- **Load / uptime under real rounds** — 8 tasks per round, 60 s each; local
  proof time (~0.3–0.9 s) leaves ample headroom.
