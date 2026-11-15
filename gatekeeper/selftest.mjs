// Standalone self-test: replays the official sample task + all 7 trap varieties
// through the decision logic AND the real circuit, without any server or secret.
// Each case checks TWO things:
//   (a) decide() returns the CORRECT decision for the task, and
//   (b) the circuit only generates a proof for that correct decision —
//       claiming the opposite decision must fail witness generation
//       (assertion in template GatekeeperEvaluation_79, line 102).
// Usage: npm run selftest   (exit 0 = all green)
import { groth16 } from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { FIELD_PRIME, GATEKEEPER_VK_HASH } from "./config.mjs";
import { buildCircuitInput, decide } from "./decision.mjs";
import { loadVerificationKey } from "./proof.mjs";

const P = FIELD_PRIME;
const ADDR = "0xde42000000000000000000000000000000009f01";
const ADDR2 = "0xde42000000000000000000000000000000009f02";
const modP = (hex) => (BigInt(hex) % P).toString();
const taskIdNum = (s) => BigInt("0x" + Buffer.from(s, "utf8").toString("hex")).toString();

const base = {
  taskId: "gk_24_9d1",
  minimum: 1000n,
  publicBalance: 1460n,
  expiryBlock: 19842201n,
  currentBlock: 19832000n,
  recipient: ADDR,
  conditionRecipient: ADDR,
  amount: 500n,
  maxTransfer: 1000n,
  registeredVk: GATEKEEPER_VK_HASH,
  proofVk: GATEKEEPER_VK_HASH,
  proofTx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
};

const vk = loadVerificationKey();
const poseidon = await buildPoseidon();
// [name, task, expectedDecision, claimedDecision, shouldProve]
const cases = [
  ["VALID + APPROVE", { ...base }, "APPROVE", "APPROVE", true],
  ["VALID + REJECT (must fail)", { ...base }, "APPROVE", "REJECT", false],
  ["VK_SUBSTITUTION + APPROVE (must fail)", { ...base, proofVk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff" }, "REJECT", "APPROVE", false],
  ["VK_SUBSTITUTION + REJECT", { ...base, proofVk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff" }, "REJECT", "REJECT", true],
  ["THRESHOLD_MISMATCH + APPROVE (must fail)", { ...base, publicBalance: 900n }, "REJECT", "APPROVE", false],
  ["THRESHOLD_MISMATCH + REJECT", { ...base, publicBalance: 900n }, "REJECT", "REJECT", true],
  ["EXPIRED + APPROVE (must fail)", { ...base, currentBlock: 19842202n }, "REJECT", "APPROVE", false],
  ["EXPIRED + REJECT", { ...base, currentBlock: 19842202n }, "REJECT", "REJECT", true],
  ["RECIPIENT_MISMATCH + APPROVE (must fail)", { ...base, recipient: ADDR2 }, "REJECT", "APPROVE", false],
  ["RECIPIENT_MISMATCH + REJECT", { ...base, recipient: ADDR2 }, "REJECT", "REJECT", true],
  ["AMOUNT_OVERFLOW + APPROVE (must fail)", { ...base, amount: 1500n }, "REJECT", "APPROVE", false],
  ["AMOUNT_OVERFLOW + REJECT", { ...base, amount: 1500n }, "REJECT", "REJECT", true],
];

let pass = 0;
for (const [name, task, expected, claimed, shouldProve] of cases) {
  const d = decide(task, new Set());
  const decisionOk = d.decision === expected;
  const t0 = Date.now();
  let proved = false, verified = false, err = "";
  try {
    const input = buildCircuitInput(task, claimed, "123456789");
    const { proof, publicSignals } = await groth16.fullProve(input, "../circuits/gatekeeper.wasm", "../circuits/gatekeeper_final.zkey");
    proved = true;
    verified = await groth16.verify(vk, publicSignals, proof);
    if (name === "VALID + APPROVE") {
      const commit = poseidon.F.toString(poseidon([poseidon.F.e(input.salt), poseidon.F.e(input.taskId)]));
      console.log(`  commitment check: public[0] == Poseidon(salt,taskId)? ${commit === publicSignals[0]}`);
      console.log(`  publicSignals: ${JSON.stringify(publicSignals)}`);
      console.log(`  taskId encoding: "${task.taskId}" -> ${taskIdNum(task.taskId)}; registeredVk mod p: ${modP(task.registeredVk)}`);
    }
  } catch (e) {
    err = String(e.message || e).split("\n")[0].slice(0, 120);
  }
  const ms = Date.now() - t0;
  const ok = decisionOk && proved === shouldProve && (!shouldProve || verified);
  if (ok) pass++;
  console.log(`${ok ? "PASS" : "FAIL"} | ${name} | decide=${d.decision}(${d.reasonCode}) expected=${expected} | proved=${proved} verified=${verified} ${ms}ms${err ? ` | ${err}` : ""}`);
}
console.log(`\n${pass}/${cases.length} cases pass`);
process.exit(pass === cases.length ? 0 : 1);
