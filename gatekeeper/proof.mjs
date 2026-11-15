// Local Groth16 proving with snarkjs 0.7.6 + the official gatekeeper circuit.
// No network, no keys, no spending: the proof is generated entirely locally
// and returned to the platform, which re-verifies it against its own VK.
import { readFileSync } from "node:fs";
import { groth16 } from "snarkjs";
import { PROOF_TIMEOUT_MS, VK_PATH, WASM_PATH, ZKEY_PATH } from "./config.mjs";

let cachedVk = null;

export function loadVerificationKey() {
  if (!cachedVk) cachedVk = JSON.parse(readFileSync(VK_PATH, "utf8"));
  return cachedVk;
}

/** Generate a proof; rejects on timeout (PROOF_TIMEOUT_MS) or circuit assertion. */
export async function generateProof(circuitInput, timeoutMs = PROOF_TIMEOUT_MS) {
  const t0 = Date.now();
  const work = groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  const timer = new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`proof generation exceeded ${timeoutMs}ms`)), timeoutMs),
  );
  const { proof, publicSignals } = await Promise.race([work, timer]);
  return { proof, publicSignals, proofMs: Date.now() - t0 };
}

/** Locally verify a proof against the exported verification key. */
export async function verifyProof(proof, publicSignals) {
  return groth16.verify(loadVerificationKey(), publicSignals, proof);
}
