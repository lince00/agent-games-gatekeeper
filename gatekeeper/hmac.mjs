// HMAC-SHA256 helpers for the Agent Games protocol.
// - Inbound: verify `x-agent-games-signature` against the RAW request body,
//   BEFORE any JSON parsing. Hex-encoded, lowercase.
// - Outbound: sign the exact raw response body bytes and send the hex digest
//   in the `x-agent-games-signature` response header.
// The signature format (lowercase hex) is the standard HMAC-SHA256 convention;
// it is NOT documented on the /build page, so confirm it via the dashboard
// preflight: a wrong format fails preflight with a signature error.
import { createHmac, timingSafeEqual } from "node:crypto";

export function hmacHex(secret, rawBody) {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

export function verifySignature(secret, rawBody, headerValue) {
  if (!secret || typeof headerValue !== "string") return false;
  const expected = hmacHex(secret, rawBody);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(headerValue.trim().toLowerCase(), "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
