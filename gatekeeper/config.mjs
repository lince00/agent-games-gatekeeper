// Shared constants + env config. No secrets live here — the HMAC secret comes
// ONLY from the AGENT_GAMES_HMAC_SECRET environment variable (dashboard -> Rotate Secret).
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const PROTOCOL_VERSION = "v1";
export const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
export const PREFLIGHT_TYPE = "agent-games.preflight.v1";

// bn128 scalar field prime (used to reduce 256-bit hashes into field elements).
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Gatekeeper circuit verification-key hash, registered on zkVerify mainnet
// (source: https://agentgames.zkverify.io/api/circuit-info, 2026-11-16).
// NOTE: this is the hash of the *gatekeeper circuit's own* verification key.
// It is used when submitting OUR proof to Kurier/zkVerify — it is NOT compared
// against the task's registered_vk / proof_vk fields (those belong to the
// payment condition's proof; the circuit only checks that the two are equal).
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const CIRCUIT_DIR =
  process.env.CIRCUIT_DIR || path.join(__dirname, "..", "circuits");
export const WASM_PATH = path.join(CIRCUIT_DIR, "gatekeeper.wasm");
export const ZKEY_PATH = path.join(CIRCUIT_DIR, "gatekeeper_final.zkey");
export const VK_PATH = path.join(CIRCUIT_DIR, "verification_key.json");

export const PORT = Number(process.env.PORT || 3000);
export const STATE_FILE =
  process.env.STATE_FILE || path.join(__dirname, "state.json");

// Hard internal budget: the platform allows 60s per response. Proof generation
// is expected to take ~1s; if it ever exceeds this budget we answer the
// deterministic decision WITHOUT a proof instead of timing out.
export const PROOF_TIMEOUT_MS = 45_000;

export function hmacSecret() {
  const s = (process.env.AGENT_GAMES_HMAC_SECRET || "").trim();
  return s.length > 0 ? s : null;
}

export function circuitsPresent() {
  return {
    wasm: existsSync(WASM_PATH),
    zkey: existsSync(ZKEY_PATH),
    vk: existsSync(VK_PATH),
  };
}
