// Deterministic Proof Gatekeeper decisions.
//
// NO language model, NO judgement calls: every check is a pure comparison over
// the task fields, in a fixed order. Fail closed — any doubt => REJECT.
//
// Check order (reason codes are the documented trap names from
// https://agentgames.zkverify.io/events/proof-gatekeeper):
//   1. envelope malformed            -> REJECT / INVALID_TASK (no proof)
//   2. task_id seen before          -> return the cached response (idempotency;
//                                      the platform may retry after a network failure)
//   3. proof_tx seen under another task_id -> REJECT / PROOF_REUSED (no proof;
//                                      the scoring rules exclude these from the proof bonus)
//   4. proof_vk != registered_vk    -> REJECT / VK_SUBSTITUTION
//   5. public_balance < minimum     -> REJECT / THRESHOLD_MISMATCH
//   6. recipient != condition_recipient -> REJECT / RECIPIENT_MISMATCH
//   7. amount > max_transfer        -> REJECT / AMOUNT_OVERFLOW
//   8. current_block > expiry_block -> REJECT / EXPIRED_CONDITION
//   9. otherwise                    -> APPROVE / VALID_CONDITION
//
// The gatekeeper circuit enforces the SAME logic: it refuses to generate a
// witness for a decision that contradicts the inputs (assertion in template
// GatekeeperEvaluation_79). So a proof can only ever be produced for the
// decision this module computes — the circuit is the referee.
//
// Circuit inputs (verified by probing the compiled wasm, 2026-11-16;
// the official docs do not publish signal names):
//   taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
//   conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash,
//   salt (private), decision (1 = approve, 0 = reject)
// Public signals (13, output-then-public order):
//   [ commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
//     expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//     maxTransfer, decision, taskId ]
//   where commitment is computed inside the circuit as Poseidon(salt, taskId)
//   (hypothesis confirmed locally — see TESTS.md).
//
// Value encodings into field elements:
//   - 256-bit hex hashes (registered_vk / proof_vk): BigInt(hex) mod FIELD_PRIME
//     (the registered vk hash itself exceeds the bn128 prime, so the reduced
//     value is what appears in the public signals).
//   - addresses: BigInt(hex) (160-bit, fits the field).
//   - task_id string: BigInt of its UTF-8 bytes. ASSUMPTION — the official
//     docs do not specify the string->field encoding; confirm in practice
//     mode (if the platform rejects the proof, this encoding is the first
//     thing to revisit).
//   - salt: fresh random 128-bit value per proof. Private, never logged,
//     never returned.
import { randomBytes } from "node:crypto";
import { FIELD_PRIME, TASK_TYPE } from "./config.mjs";

export const REASON = Object.freeze({
  VALID: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  INVALID_TASK: "INVALID_TASK",
});

const HEX_RE = /^0x[0-9a-fA-F]+$/;

function toBigInt(value, field) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`bad number for ${field}`);
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (HEX_RE.test(s)) return BigInt(s);
    if (/^\d+$/.test(s)) return BigInt(s);
    throw new Error(`bad numeric string for ${field}: ${s.slice(0, 40)}`);
  }
  throw new Error(`bad type for ${field}: ${typeof value}`);
}

function normHex(value, field) {
  if (typeof value !== "string" || !HEX_RE.test(value.trim())) {
    throw new Error(`bad hex for ${field}`);
  }
  return value.trim().toLowerCase();
}

/** Validate the envelope and return the parsed input, or throw. */
export function parseTask(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("envelope is not an object");
  }
  if (envelope.type !== TASK_TYPE) {
    throw new Error(`unexpected type: ${String(envelope.type)}`);
  }
  if (typeof envelope.task_id !== "string" || envelope.task_id.length === 0) {
    throw new Error("missing task_id");
  }
  const input = envelope.input;
  if (!input || typeof input !== "object") throw new Error("missing input");

  const registeredVk = normHex(input.registered_vk, "registered_vk");
  const proofVk = normHex(input.proof_vk, "proof_vk");
  const recipient = normHex(input.recipient, "recipient");
  const conditionRecipient = normHex(input.condition_recipient, "condition_recipient");
  const proofTx = normHex(input.proof_tx, "proof_tx");

  return {
    taskId: envelope.task_id,
    mode: envelope.mode,
    registeredVk,
    proofVk,
    minimum: toBigInt(input.minimum, "minimum"),
    publicBalance: toBigInt(input.public_balance, "public_balance"),
    expiryBlock: toBigInt(input.expiry_block, "expiry_block"),
    currentBlock: toBigInt(input.current_block, "current_block"),
    recipient,
    conditionRecipient,
    amount: toBigInt(input.amount, "amount"),
    maxTransfer: toBigInt(input.max_transfer, "max_transfer"),
    proofTx,
  };
}

/**
 * Pure decision. `seenProofTx` is a Set of proof_tx values already used by
 * OTHER task_ids. Returns { decision, reasonCode, needsProof }.
 * needsProof is false for PROOF_REUSED (scoring excludes those) and for
 * INVALID_TASK (nothing provable).
 */
export function decide(task, seenProofTx) {
  if (seenProofTx.has(task.proofTx)) {
    return { decision: "REJECT", reasonCode: REASON.PROOF_REUSED, needsProof: false };
  }
  if (task.proofVk !== task.registeredVk) {
    return { decision: "REJECT", reasonCode: REASON.VK_SUBSTITUTION, needsProof: true };
  }
  if (task.publicBalance < task.minimum) {
    return { decision: "REJECT", reasonCode: REASON.THRESHOLD_MISMATCH, needsProof: true };
  }
  if (task.recipient !== task.conditionRecipient) {
    return { decision: "REJECT", reasonCode: REASON.RECIPIENT_MISMATCH, needsProof: true };
  }
  if (task.amount > task.maxTransfer) {
    return { decision: "REJECT", reasonCode: REASON.AMOUNT_OVERFLOW, needsProof: true };
  }
  if (task.currentBlock > task.expiryBlock) {
    return { decision: "REJECT", reasonCode: REASON.EXPIRED_CONDITION, needsProof: true };
  }
  return { decision: "APPROVE", reasonCode: REASON.VALID, needsProof: true };
}

/** Build the 13 circuit inputs for a decided task. `saltHex` is optional (random if omitted). */
export function buildCircuitInput(task, decision, saltHex) {
  const salt = saltHex ?? randomBytes(16).toString("hex");
  const reduce = (hex) => (BigInt(hex) % FIELD_PRIME).toString();
  return {
    taskId: BigInt("0x" + Buffer.from(task.taskId, "utf8").toString("hex")).toString(),
    minimum: task.minimum.toString(),
    publicBalance: task.publicBalance.toString(),
    expiryBlock: task.expiryBlock.toString(),
    currentBlock: task.currentBlock.toString(),
    recipient: BigInt(task.recipient).toString(),
    conditionRecipient: BigInt(task.conditionRecipient).toString(),
    amount: task.amount.toString(),
    maxTransfer: task.maxTransfer.toString(),
    registeredVkHash: reduce(task.registeredVk),
    proofVkHash: reduce(task.proofVk),
    salt: BigInt("0x" + salt).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
  };
}
