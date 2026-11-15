// End-to-end test of the real HTTP server (server.mjs) with a FAKE test HMAC
// secret — never a real platform secret. Starts the server as a child process,
// exercises every route, verifies response signatures independently, then kills it.
// Usage: node e2e-test.mjs   (exit 0 = all green)
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { groth16 } from "snarkjs";
import { readFileSync } from "node:fs";

const SECRET = "test-secret-NOT-REAL-do-not-use-in-production";
const BASE = "http://127.0.0.1:3123";
const vk = JSON.parse(readFileSync("../circuits/verification_key.json", "utf8"));

const sign = (body, secret = SECRET) => createHmac("sha256", secret).update(body).digest("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function post(path, bodyObj, secretOverride = SECRET, rawBody = null) {
  const body = rawBody ?? JSON.stringify(bodyObj);
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": secretOverride ? sign(body, secretOverride) : "",
    },
    body,
  });
  const text = await res.text();
  return { status: res.status, sig: res.headers.get("x-agent-games-signature"), text, json: safeJson(text) };
}
const safeJson = (t) => { try { return JSON.parse(t); } catch { return null; } };

const validTask = {
  type: "agent-games.proof-gatekeeper.v1",
  task_id: "gk_e2e_001",
  mode: "competition",
  issued_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: {
    registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: "0xDe42000000000000000000000000000000009f01",
    condition_recipient: "0xDe42000000000000000000000000000000009f01",
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
  },
};
const trapTask = {
  ...validTask,
  task_id: "gk_e2e_002",
  input: { ...validTask.input, proof_vk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff", proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff2" },
};
const reusedTask = {
  ...validTask,
  task_id: "gk_e2e_003",
  input: { ...validTask.input, proof_tx: validTask.input.proof_tx }, // same proof_tx, different task
};

let pass = 0, total = 0;
const check = (name, cond, extra = "") => { total++; if (cond) pass++; console.log(`${cond ? "PASS" : "FAIL"} | ${name}${extra ? " | " + extra : ""}`); };

const server = spawn("node", ["server.mjs"], {
  env: { ...process.env, PORT: "3123", AGENT_GAMES_HMAC_SECRET: SECRET, STATE_FILE: "./state.e2e.json" },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
server.stdout.on("data", (d) => { serverLog += d; });
server.stderr.on("data", (d) => { serverLog += d; });
process.on("exit", () => { try { server.kill(); } catch {} });

try {
  // wait for health
  let health = null;
  for (let i = 0; i < 40; i++) {
    await sleep(500);
    try { const r = await fetch(`${BASE}/health`); health = await r.json(); if (health.ok) break; } catch {}
  }
  check("GET /health ok + HMAC configured + self-test OK", health?.ok === true && health?.hmacConfigured === true && health?.selfTest?.ok === true, JSON.stringify(health?.selfTest ?? health));

  // preflight
  const pfBody = JSON.stringify({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  const pf = await post("/gatekeeper", null, SECRET, pfBody);
  check("preflight -> {ok:true, protocolVersion:v1} + valid signature", pf.status === 200 && pf.json?.ok === true && pf.json?.protocolVersion === "v1" && pf.sig === sign(pf.text), `status=${pf.status}`);

  // valid task -> APPROVE + proof that verifies + valid signature
  const t0 = Date.now();
  const v = await post("/gatekeeper", validTask);
  const vMs = Date.now() - t0;
  const vSigOk = v.sig === sign(v.text);
  const vProofOk = v.json?.proof && v.json?.public_signals?.length === 13 && await groth16.verify(vk, v.json.public_signals, v.json.proof);
  check("valid task -> APPROVE/VALID_CONDITION + verifying proof + valid sig", v.status === 200 && v.json?.decision === "APPROVE" && v.json?.reason_code === "VALID_CONDITION" && vSigOk && vProofOk, `${vMs}ms status=${v.status}`);

  // idempotent replay -> byte-identical body, same signature
  const v2 = await post("/gatekeeper", validTask);
  check("same task_id replay -> identical cached body", v2.status === 200 && v2.text === v.text, "");

  // trap task -> REJECT/VK_SUBSTITUTION + verifying proof
  const t = await post("/gatekeeper", trapTask);
  const tProofOk = t.json?.proof && await groth16.verify(vk, t.json.public_signals, t.json.proof);
  check("trap task -> REJECT/VK_SUBSTITUTION + verifying proof", t.status === 200 && t.json?.decision === "REJECT" && t.json?.reason_code === "VK_SUBSTITUTION" && tProofOk, `status=${t.status}`);

  // reused proof_tx under a different task -> PROOF_REUSED, NO proof
  const r = await post("/gatekeeper", reusedTask);
  check("reused proof_tx -> REJECT/PROOF_REUSED without proof", r.status === 200 && r.json?.decision === "REJECT" && r.json?.reason_code === "PROOF_REUSED" && !r.json?.proof && !r.json?.public_signals, `status=${r.status}`);

  // bad signature -> 401, no decision leaked
  const bad = await post("/gatekeeper", validTask, "wrong-secret");
  check("bad signature -> 401", bad.status === 401 && !bad.json?.decision, `status=${bad.status}`);

  // no signature -> 401
  const nosig = await post("/gatekeeper", validTask, null);
  check("missing signature -> 401", nosig.status === 401, `status=${nosig.status}`);

  // malformed JSON (signed) -> 400
  const malformed = await post("/gatekeeper", null, SECRET, "{not json");
  check("malformed JSON (signed) -> 400", malformed.status === 400, `status=${malformed.status}`);

  // unknown route -> 404
  const nf = await fetch(`${BASE}/nope`);
  check("unknown route -> 404", nf.status === 404, `status=${nf.status}`);

  // /agent alias works
  const aliasTask = { ...validTask, task_id: "gk_e2e_004", input: { ...validTask.input, proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff4" } };
  const al = await post("/agent", aliasTask);
  check("POST /agent alias -> APPROVE", al.status === 200 && al.json?.decision === "APPROVE", `status=${al.status}`);
} finally {
  server.kill();
  await sleep(300);
}
console.log(`\n${pass}/${total} e2e checks pass`);
process.exit(pass === total ? 0 : 1);
