# Proof Gatekeeper endpoint — zkVerify Agent Games Season 01

Deterministic APPROVE/REJECT agent for the Proof Gatekeeper track. Receives
signed task envelopes, decides by a fixed checklist (never an LLM judgement),
generates a Groth16 proof locally with snarkjs + the official circuit, and
returns the signed protocol-v1 response. No private keys, no transactions,
no spending — this server only judges and proves.

## Files

```
~/workspace/zkverify/
  circuits/
    gatekeeper.wasm               official circuit (1,755,820 bytes)
    gatekeeper_final.zkey         official proving key (309,750 bytes)
    verification_key.json         exported from the zkey (site returns 404)
  gatekeeper/
    server.mjs                    HTTP server (POST /gatekeeper, /agent; GET /health)
    decision.mjs                  deterministic checks + circuit input builder
    state.mjs                     proof-reuse seen-set + idempotency cache (disk)
    proof.mjs                     snarkjs fullProve/verify wrapper (45 s budget)
    hmac.mjs                      HMAC-SHA256 sign/verify (raw body, hex)
    config.mjs                    constants (vk hash, field prime, paths)
    selftest.mjs                  12-case decision + circuit matrix test
    test-circuit.mjs              original 12-case circuit probe
    e2e-test.mjs                  11-check live-server test (fake test secret)
    .env.example                  env template (no real values)
    package.json / package-lock.json   (snarkjs 0.7.6, circomlibjs 0.1.7)
    TESTS.md                      full test results
```

## Run locally

```bash
cd ~/workspace/zkverify/gatekeeper
npm install
cp .env.example .env        # then fill AGENT_GAMES_HMAC_SECRET from the dashboard
npm run selftest            # 12/12 decision + circuit cases, no secret needed
node e2e-test.mjs           # 11/11 live-server checks (fake test secret)
npm start                   # listens on $PORT (default 3000)
curl localhost:3000/health
```

## Deploy (when the account holder picks hosting)

1. Pick **Railway** or **Vercel** (decision pending with the account holder).
   Railway is the safer default: always-on service, no cold starts (the
   rules warn that free-tier hosts that sleep cost tasks — a forfeit per
   missed task). Vercel serverless can cold-start; only use it with a
   paid/always-warm plan or a keep-alive pinger.
2. Deploy this folder (`gatekeeper/`) plus `../circuits/` (the server reads
   circuits from `CIRCUIT_DIR`, default `../circuits`). Set env:
   `AGENT_GAMES_HMAC_SECRET=<secret from dashboard Rotate Secret>`,
   `PORT` (hosting injects it), `CIRCUIT_DIR` if the layout differs.
3. Confirm `GET https://<host>/health` returns `ok:true`
   (`hmacConfigured:true`, `selfTest.ok:true`).
4. In the dashboard (**Dashboard -> My Agents -> Register agent**):
   register the endpoint with the **full handler path**
   (`https://<host>/gatekeeper`), then **Rotate Secret** and copy the
   plaintext secret into the hosting env (shown exactly once).
5. Wait for the platform's signed **preflight** — the server answers
   `{ok:true, protocolVersion:"v1"}` signed. Preflight must pass before the
   agent is marked active.
6. Run at least **one practice task** (dashboard practice mode, capped at
   10 dispatches/hour) and confirm the platform accepts the proof. This is
   the step that confirms the task-id encoding and signature format.
7. Enter scored rounds. Rounds run daily 16:00–02:00 IST (17:30–03:30 WIB),
   8 tasks per agent per round, cumulative scoring (+12 correct, −6 wrong
   approve, −3 wrong reject, −2 timeout / missing proof).

## Protocol summary (sources: /build, /events/proof-gatekeeper, /rules)

- Inbound: `POST` JSON, header `x-agent-games-signature` = HMAC-SHA256 (hex)
  over the RAW body, verified BEFORE parsing. 60 s hard deadline, HTTPS only.
- Task: `{type:"agent-games.proof-gatekeeper.v1", task_id, mode, issued_at,
  deadline_at, input:{registered_vk, proof_vk, minimum, public_balance,
  expiry_block, current_block, recipient, condition_recipient, amount,
  max_transfer, proof_tx}}`.
- Response: `{decision, reason_code, proof_tx, proof, public_signals}`,
  signed with the same HMAC over the raw response body. `proof` is the raw
  snarkjs Groth16 proof; `public_signals` are 13 decimal strings in
  output-then-public order. `PROOF_REUSED` answers carry no proof (excluded
  from the reliability bonus by the rules).
- Preflight: platform sends `{type:"agent-games.preflight.v1", agent_id,
  issued_at, nonce}`; answer `{ok:true, protocolVersion:"v1"}`, signed.
- Decision checklist (in order): idempotency replay -> PROOF_REUSED ->
  VK_SUBSTITUTION -> THRESHOLD_MISMATCH -> RECIPIENT_MISMATCH ->
  AMOUNT_OVERFLOW -> EXPIRED_CONDITION -> VALID_CONDITION (APPROVE).
  Fail closed everywhere; task IDs are idempotency keys (platform retries).

## Open points (verify in practice mode, not locally testable)

1. **Signature encoding**: lowercase hex HMAC-SHA256 is the standard
   convention, but the docs never spell it out. Preflight confirms it.
2. **taskId encoding**: the task-id string is hashed into a field element as
   its UTF-8 bytes (`"gk_24_9d1"` -> `1907751597477446902833`). The commitment
   formula `public[0] = Poseidon(salt, taskId)` was confirmed locally with
   this encoding. If the platform rejects a practice proof, revisit this first.
3. **Kurier submission (optional)**: the response schema does not require
   on-chain submission; the platform re-verifies the proof itself. If the
   account holder later gets a Kurier API key, proofs can additionally be
   submitted to Kurier (`proofType: groth16, vkRegistered: true,
   proofOptions: {library: "snarkjs", curve: "bn128"}`, vk =
   `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`)
   and polled to Finalized — but it is not needed to score.

## Security notes

- The HMAC secret comes only from `AGENT_GAMES_HMAC_SECRET`. It is never
  logged, never committed, never pasted anywhere. Rotate it from the
  dashboard if it ever leaks — the old secret stops working immediately.
- `state.json` (proof-reuse seen-set + idempotency cache) persists on disk so
  restarts cannot let a reused proof through. It holds only proof_tx hashes
  and task IDs — no secrets.
- The server never holds a wallet key and cannot sign or send transactions.
