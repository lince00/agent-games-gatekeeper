// Persistent state: proof-reuse seen-set + idempotency cache (task_id -> response).
// Stored as JSON on disk so a restart does not let a reused proof slip through
// or make the platform's retry look like a new task.
// File shape: { seen: [proofTx...], responses: { taskId: { body, decidedAt } } }
// Writes are atomic (temp file + rename). Bounded: keeps the newest 10_000 entries.
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

const MAX_ENTRIES = 10_000;

export class StateStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seen = new Set();
    this.responses = new Map();
    this.load();
  }

  load() {
    try {
      if (!existsSync(this.filePath)) return;
      const data = JSON.parse(readFileSync(this.filePath, "utf8"));
      if (Array.isArray(data.seen)) for (const x of data.seen) this.seen.add(x);
      if (data.responses && typeof data.responses === "object") {
        for (const [k, v] of Object.entries(data.responses)) this.responses.set(k, v);
      }
    } catch (e) {
      console.error(`[state] failed to load ${this.filePath}: ${e.message} (starting empty)`);
    }
  }

  save() {
    try {
      const seen = [...this.seen].slice(-MAX_ENTRIES);
      const responses = Object.fromEntries([...this.responses.entries()].slice(-MAX_ENTRIES));
      const tmp = `${this.filePath}.tmp`;
      writeFileSync(tmp, JSON.stringify({ seen, responses }, null, 2));
      renameSync(tmp, this.filePath);
    } catch (e) {
      console.error(`[state] failed to save: ${e.message}`);
    }
  }

  hasSeenProofTx(proofTx) {
    return this.seen.has(proofTx);
  }

  markProofTxSeen(proofTx) {
    this.seen.add(proofTx);
    this.save();
  }

  getCachedResponse(taskId) {
    return this.responses.get(taskId) ?? null;
  }

  cacheResponse(taskId, body) {
    this.responses.set(taskId, { body, decidedAt: new Date().toISOString() });
    this.save();
  }

  stats() {
    return { seenProofs: this.seen.size, cachedResponses: this.responses.size };
  }
}
