// Proof Gatekeeper HTTP endpoint — plain Node.js http, no framework.
//
// Routes:
//   POST /gatekeeper  (primary; /agent is accepted as an alias)
//     - Verifies x-agent-games-signature (HMAC-SHA256 over the RAW body) BEFORE
//       parsing. Mismatch -> 401, no processing.
//     - type "agent-games.preflight.v1" -> { ok: true, protocolVersion: "v1" }, signed.
//     - type "agent-games.proof-gatekeeper.v1" -> deterministic decision +
//       local Groth16 proof, signed. 60s platform deadline; internal proof
//       budget is 45s, after which we answer the decision WITHOUT a proof
//       rather than timing out.
//     - Every response carries x-agent-games-signature over the raw body.
//   GET /health
//     - Readiness: HMAC configured?, circuit files present?, verification key
//       (nPublic), state sizes, last startup self-test result.
//     - GET /health?selftest=1 re-runs the self-test on demand.
//
// This server NEVER signs transactions, NEVER spends anything, and NEVER
// stores a private key or seed. The only secret it holds is the platform
// HMAC secret from AGENT_GAMES_HMAC_SECRET (never logged).
import http from "node:http";
import { readFileSync } from "node:fs";
import {
  CIRCUIT_DIR,
  GATEKEEPER_VK_HASH,
  PORT,
  PREFLIGHT_TYPE,
  PROTOCOL_VERSION,
  STATE_FILE,
  TASK_TYPE,
  circuitsPresent,
  hmacSecret,
} from "./config.mjs";
import { hmacHex, verifySignature } from "./hmac.mjs";
import { REASON, buildCircuitInput, decide, parseTask } from "./decision.mjs";
import { generateProof, loadVerificationKey, verifyProof } from "./proof.mjs";
import { StateStore } from "./state.mjs";

const state = new StateStore(STATE_FILE);
const selfTest = { ranAt: null, ok: null, detail: null, proofMs: null };

function json(res, status, bodyObj, secret) {
  const body = JSON.stringify(bodyObj);
  const headers = { "content-type": "application/json" };
  if (secret) headers["x-agent-games-signature"] = hmacHex(secret, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) reject(new Error("body too large"));
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function runSelfTest() {
  // Valid sample task from the official event page (decision must be APPROVE
  // and the proof must verify locally).
  const task = {
    taskId: "selftest-gk",
    minimum: 1000n,
    publicBalance: 1460n,
    expiryBlock: 19842201n,
    currentBlock: 19832000n,
    recipient: "0xde42000000000000000000000000000000009f01",
    conditionRecipient: "0xde42000000000000000000000000000000009f01",
    amount: 500n,
    maxTransfer: 1000n,
    registeredVk: GATEKEEPER_VK_HASH,
    proofVk: GATEKEEPER_VK_HASH,
    proofTx: "0x0000000000000000000000000000000000000000000000000000000000000000",
  };
  const t0 = Date.now();
  try {
    const d = decide(task, new Set());
    if (d.decision !== "APPROVE" || d.reasonCode !== REASON.VALID) {
      throw new Error(`self-test decision wrong: ${d.decision}/${d.reasonCode}`);
    }
    const input = buildCircuitInput(task, "APPROVE");
    const { proof, publicSignals, proofMs } = await generateProof(input);
    const ok = await verifyProof(proof, publicSignals);
    if (!ok) throw new Error("self-test proof did not verify");
    if (publicSignals.length !== 13) throw new Error(`expected 13 public signals, got ${publicSignals.length}`);
    selfTest.ranAt = new Date().toISOString();
    selfTest.ok = true;
    selfTest.proofMs = proofMs;
    selfTest.detail = `APPROVE/VALID_CONDITION, proof verified, ${publicSignals.length} public signals, ${proofMs}ms (total ${Date.now() - t0}ms)`;
  } catch (e) {
    selfTest.ranAt = new Date().toISOString();
    selfTest.ok = false;
    selfTest.proofMs = null;
    selfTest.detail = String(e.message || e);
  }
  return selfTest;
}

async function handleTask(req, res, secret) {
  const t0 = Date.now();
  let raw;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    return json(res, 400, { error: "bad request body" }, null);
  }

  // 1. HMAC first, BEFORE parsing. Fail closed.
  const sig = req.headers["x-agent-games-signature"];
  if (!secret) {
    console.error("[gatekeeper] AGENT_GAMES_HMAC_SECRET is not configured — refusing to answer");
    return json(res, 503, { error: "agent not configured (HMAC secret missing)" }, null);
  }
  if (!verifySignature(secret, raw, sig)) {
    console.warn("[gatekeeper] bad signature — rejected before parsing");
    return json(res, 401, { error: "bad signature" }, null);
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return json(res, 400, { error: "invalid JSON" }, null);
  }

  // 2. Preflight handshake (same endpoint, distinguished by type).
  if (envelope && envelope.type === PREFLIGHT_TYPE) {
    console.log(`[preflight] nonce=${String(envelope.nonce ?? "?").slice(0, 24)}`);
    return json(res, 200, { ok: true, protocolVersion: PROTOCOL_VERSION }, secret);
  }

  if (!envelope || envelope.type !== TASK_TYPE) {
    return json(res, 400, { error: `unexpected type: ${String(envelope?.type)}` }, null);
  }

  // 3. Parse + decide deterministically.
  let task;
  try {
    task = parseTask(envelope);
  } catch (e) {
    console.warn(`[gatekeeper] invalid task: ${e.message}`);
    return json(res, 200, { decision: "REJECT", reason_code: REASON.INVALID_TASK }, secret);
  }

  // 4. Idempotency: same task_id -> same response (platform retries).
  const cached = state.getCachedResponse(task.taskId);
  if (cached) {
    console.log(`[gatekeeper] ${task.taskId} idempotent replay -> cached ${JSON.parse(cached.body).decision}`);
    const headers = {
      "content-type": "application/json",
      "x-agent-games-signature": hmacHex(secret, cached.body),
    };
    res.writeHead(200, headers);
    return res.end(cached.body);
  }

  const { decision, reasonCode, needsProof } = decide(task, state.seen);
  const response = { decision, reason_code: reasonCode, proof_tx: task.proofTx };

  // 5. Prove the decision locally (except PROOF_REUSED: no proof to submit).
  if (needsProof) {
    try {
      const input = buildCircuitInput(task, decision);
      const { proof, publicSignals, proofMs } = await generateProof(input);
      response.proof = proof;
      response.public_signals = publicSignals;
      console.log(`[gatekeeper] ${task.taskId} ${decision}/${reasonCode} proof ${proofMs}ms`);
    } catch (e) {
      // Fail closed on the DECISION, not on transport: answer the decision
      // without a proof (costs -2) rather than timing out (also -2, but a
      // correct REJECT without proof still scores +10 on trap tasks).
      console.error(`[gatekeeper] ${task.taskId} proof generation failed (${e.message}) — answering without proof`);
    }
  } else {
    console.log(`[gatekeeper] ${task.taskId} ${decision}/${reasonCode} (no proof — reused reference)`);
  }

  // 6. Record the reference as seen + cache the response, then answer signed.
  state.markProofTxSeen(task.proofTx);
  const body = JSON.stringify(response);
  state.cacheResponse(task.taskId, body);
  console.log(`[gatekeeper] ${task.taskId} answered in ${Date.now() - t0}ms`);
  const headers = {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(secret, body),
  };
  res.writeHead(200, headers);
  res.end(body);
}

function handleHealth(req, res) {
  const url = new URL(req.url, "http://localhost");
  if (url.searchParams.get("selftest") === "1") {
    return runSelfTest().then(() => json(res, 200, healthPayload(), null));
  }
  return json(res, 200, healthPayload(), null);
}

function healthPayload() {
  const present = circuitsPresent();
  let vkInfo = null;
  try {
    const vk = loadVerificationKey();
    vkInfo = { protocol: vk.protocol, curve: vk.curve, nPublic: vk.nPublic };
  } catch (e) {
    vkInfo = { error: String(e.message || e) };
  }
  return {
    ok: Boolean(hmacSecret()) && present.wasm && present.zkey && present.vk && selfTest.ok !== false,
    protocolVersion: PROTOCOL_VERSION,
    hmacConfigured: Boolean(hmacSecret()),
    circuits: { ...present, dir: CIRCUIT_DIR, vkHash: GATEKEEPER_VK_HASH, vk: vkInfo },
    state: state.stats(),
    selfTest,
  };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && url.pathname === "/health") return handleHealth(req, res);
  if (req.method === "POST" && (url.pathname === "/gatekeeper" || url.pathname === "/agent")) {
    return handleTask(req, res, hmacSecret()).catch((e) => {
      console.error(`[gatekeeper] handler error: ${e.message}`);
      try {
        json(res, 500, { error: "internal error" }, null);
      } catch { /* socket already gone */ }
    });
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

server.requestTimeout = 55_000;
server.headersTimeout = 60_000;

// Self-test BEFORE accepting traffic, so /health is truthful from the first
// request. A failed self-test does not stop the server (so /health can report
// it), but it is logged loudly.
const startupTest = await runSelfTest();
console.log(`[gatekeeper] startup self-test: ${startupTest.ok ? "OK" : "FAIL"} — ${startupTest.detail}`);
if (!startupTest.ok) {
  console.error("[gatekeeper] WARNING: self-test failed — the endpoint is NOT competition-ready");
}

server.listen(PORT, () => {
  console.log(`[gatekeeper] listening on :${PORT} (POST /gatekeeper, GET /health)`);
  console.log(`[gatekeeper] HMAC configured: ${Boolean(hmacSecret())}; circuits: ${JSON.stringify(circuitsPresent())}`);
});

export { server };
