import { groth16 } from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { randomBytes } from "crypto";

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const OFFICIAL_VK = 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0n;
const ADDR = 0xDe42000000000000000000000000000000009f01n;
const ADDR2 = 0xDe42000000000000000000000000000000009f02n; // different recipient
const taskIdNum = (s) => BigInt("0x" + Buffer.from(s, "utf8").toString("hex"));
const modP = (x) => ((x % P) + P) % P;

const base = {
  taskId: taskIdNum("gk_24_9d1").toString(),
  minimum: "1000",
  publicBalance: "1460",
  expiryBlock: "19842201",
  currentBlock: "19832000",
  recipient: ADDR.toString(),
  conditionRecipient: ADDR.toString(),
  amount: "500",
  maxTransfer: "1000",
  registeredVkHash: modP(OFFICIAL_VK).toString(),
  proofVkHash: modP(OFFICIAL_VK).toString(),
  salt: "123456789",
  decision: "1",
};

const poseidon = await buildPoseidon();
const cases = [
  ["VALID + APPROVE (expect proof OK)", { ...base }, true],
  ["VALID + REJECT (expect witness FAIL)", { ...base, decision: "0" }, false],
  ["VK_SUBSTITUTION + APPROVE (expect FAIL)", { ...base, proofVkHash: modP(0xa4c1n).toString() }, false],
  ["VK_SUBSTITUTION + REJECT (expect OK)", { ...base, proofVkHash: modP(0xa4c1n).toString(), decision: "0" }, true],
  ["THRESHOLD_MISMATCH + APPROVE (expect FAIL)", { ...base, publicBalance: "900" }, false],
  ["THRESHOLD_MISMATCH + REJECT (expect OK)", { ...base, publicBalance: "900", decision: "0" }, true],
  ["EXPIRED + APPROVE (expect FAIL)", { ...base, currentBlock: "19842202" }, false],
  ["EXPIRED + REJECT (expect OK)", { ...base, currentBlock: "19842202", decision: "0" }, true],
  ["RECIPIENT_MISMATCH + APPROVE (expect FAIL)", { ...base, recipient: ADDR2.toString() }, false],
  ["RECIPIENT_MISMATCH + REJECT (expect OK)", { ...base, recipient: ADDR2.toString(), decision: "0" }, true],
  ["AMOUNT_OVERFLOW + APPROVE (expect FAIL)", { ...base, amount: "1500" }, false],
  ["AMOUNT_OVERFLOW + REJECT (expect OK)", { ...base, amount: "1500", decision: "0" }, true],
];

let pass = 0, fail = 0;
for (const [name, input, shouldProve] of cases) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await groth16.fullProve(input, "../circuits/gatekeeper.wasm", "../circuits/gatekeeper_final.zkey");
    const ms = Date.now() - t0;
    const ok = await groth16.verify(await import("../circuits/verification_key.json", { with: { type: "json" } }).then(m => m.default), publicSignals, proof);
    const verdict = (shouldProve && ok) ? "PASS" : "FAIL(unexpected prove+verify)";
    if (shouldProve && ok) pass++; else fail++;
    console.log(`${verdict} | ${name} | prove ${ms}ms | verify=${ok} | public[0]=${publicSignals[0].slice(0,20)}... | nPub=${publicSignals.length}`);
    if (name.startsWith("VALID + APPROVE")) {
      console.log("  publicSignals:", JSON.stringify(publicSignals));
      const saltF = poseidon.F.e(input.salt);
      const tidF = poseidon.F.e(input.taskId);
      const commit = poseidon.F.toString(poseidon([saltF, tidF]));
      console.log("  Poseidon(salt,taskId) =", commit);
      console.log("  public[0] == Poseidon(salt,taskId)?", commit === publicSignals[0]);
      const commit2 = poseidon.F.toString(poseidon([tidF, saltF]));
      console.log("  public[0] == Poseidon(taskId,salt)?", commit2 === publicSignals[0]);
    }
  } catch (e) {
    const ms = Date.now() - t0;
    const verdict = (!shouldProve) ? "PASS" : "FAIL(unexpected error)";
    if (!shouldProve) pass++; else fail++;
    console.log(`${verdict} | ${name} | ${ms}ms | error: ${String(e.message || e).split("\n")[0].slice(0,160)}`);
  }
}
console.log(`\nTOTAL: ${pass} pass, ${fail} fail out of ${cases.length}`);
