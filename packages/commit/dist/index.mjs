import {
  applyRule,
  validateRule
} from "./chunk-AW4Z4AWA.mjs";

// src/crypto.ts
import { createHash, createHmac, randomBytes } from "crypto";
function sha256(input) {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
function hmacSha256(keyHex, dataHex) {
  const key = Buffer.from(keyHex, "hex");
  const data = Buffer.from(dataHex, "hex");
  return createHmac("sha256", key).update(data).digest("hex");
}
function hashRule(rule) {
  return sha256(rule);
}
function hashInputs(inputs) {
  const sorted = [...inputs].sort();
  return sha256(sorted.join("\n"));
}
function computeCommitHash(beacon, targetRound, ruleHash, inputsHash, saltHex) {
  const preimage = [beacon, targetRound.toString(), ruleHash, inputsHash, saltHex].join(":");
  return sha256(preimage);
}
function generateSalt() {
  return randomBytes(32);
}
function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}
function fromHex(hex) {
  return new Uint8Array(Buffer.from(hex, "hex"));
}
function deriveOutput(beaconRandomness, ruleHash, inputsHash) {
  const data = sha256(ruleHash + ":" + inputsHash);
  return hmacSha256(beaconRandomness, data);
}

// src/beacon.ts
var DRAND_QUICKNET = {
  id: "drand:quicknet",
  chainHash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  period: 3,
  // 3-second rounds
  genesisTime: 1692803367,
  publicKey: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  relays: [
    "https://api.drand.sh",
    "https://drand.cloudflare.com"
  ]
};
var DrandBeaconSource = class {
  config;
  constructor(config) {
    this.config = { ...DRAND_QUICKNET, ...config };
  }
  /**
   * Compute the drand round number for a given Unix timestamp.
   * round = floor((t - genesis) / period) + 1
   */
  getRound(unixSeconds) {
    if (unixSeconds < this.config.genesisTime) {
      throw new Error(`Timestamp ${unixSeconds} is before genesis ${this.config.genesisTime}`);
    }
    return Math.floor((unixSeconds - this.config.genesisTime) / this.config.period) + 1;
  }
  /**
   * Compute the wall-clock time (Unix seconds) when a round becomes available.
   * time = genesis + (round - 1) * period
   */
  getRoundTime(round) {
    if (round < 1) throw new Error(`Invalid round: ${round}`);
    return this.config.genesisTime + (round - 1) * this.config.period;
  }
  /**
   * Fetch a beacon round from relays with failover.
   * Tries each relay in order; throws if all fail.
   */
  async fetchBeacon(round) {
    const errors = [];
    for (const relay of this.config.relays) {
      try {
        const url = `${relay}/${this.config.chainHash}/public/${round}`;
        const resp = await fetch(url, {
          signal: AbortSignal.timeout(1e4)
        });
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status} from ${relay}`);
        }
        const data = await resp.json();
        if (data.round !== round) {
          throw new Error(`Round mismatch: requested ${round}, got ${data.round}`);
        }
        return {
          round: data.round,
          randomness: data.randomness,
          signature: data.signature
        };
      } catch (err) {
        errors.push(err instanceof Error ? err : new Error(String(err)));
      }
    }
    throw new AggregateError(
      errors,
      `Failed to fetch beacon round ${round} from all ${this.config.relays.length} relays`
    );
  }
  /**
   * Verify a beacon round's BLS12-381 signature cryptographically.
   * 
   * This is REAL cryptographic verification using @noble/curves:
   * 1. Constructs the signed message: SHA-256(round as 8-byte big-endian)
   * 2. Hashes to G1 curve point using the quicknet DST
   * 3. Verifies BLS pairing: e(sig, G2_gen) == e(H(msg), pubkey)
   * 4. Confirms randomness = SHA-256(signature)
   * 
   * No trust in any relay or server required.
   */
  async verifyBeacon(beacon) {
    try {
      const { verifyDrandBeacon } = await import("./bls-verify-V7HGQ3VN.mjs");
      return await verifyDrandBeacon(
        beacon.round,
        beacon.signature,
        beacon.randomness,
        this.config.publicKey
      );
    } catch {
      return false;
    }
  }
};
var OfflineBeaconSource = class {
  config;
  constructor() {
    this.config = {
      ...DRAND_QUICKNET,
      id: "offline",
      relays: []
      // no network needed
    };
  }
  getRound(unixSeconds) {
    if (unixSeconds < this.config.genesisTime) {
      throw new Error(`Timestamp ${unixSeconds} is before genesis ${this.config.genesisTime}`);
    }
    return Math.floor((unixSeconds - this.config.genesisTime) / this.config.period) + 1;
  }
  getRoundTime(round) {
    if (round < 1) throw new Error(`Invalid round: ${round}`);
    return this.config.genesisTime + (round - 1) * this.config.period;
  }
  /**
   * Generate a deterministic beacon from the round number.
   * randomness = SHA-256("offline-beacon:" + round)
   * signature  = SHA-256("offline-sig:" + round)
   * 
   * ⚠️ NOT cryptographically secure — suitable for demos only.
   */
  async fetchBeacon(round) {
    console.warn("\u26A0\uFE0F  Using offline beacon \u2014 not suitable for production");
    const randomness = sha256(`offline-beacon:${round}`);
    const signature = sha256(`offline-sig:${round}`);
    return { round, randomness, signature };
  }
  /**
   * Offline beacons are self-generated, so "verification" just checks
   * the deterministic derivation is consistent.
   */
  async verifyBeacon(beacon) {
    const expectedRandomness = sha256(`offline-beacon:${beacon.round}`);
    const expectedSignature = sha256(`offline-sig:${beacon.round}`);
    return beacon.randomness === expectedRandomness && beacon.signature === expectedSignature;
  }
};
var CachedBeaconSource = class {
  config;
  inner;
  cache = /* @__PURE__ */ new Map();
  constructor(inner) {
    this.inner = inner;
    this.config = inner.config;
  }
  getRound(unixSeconds) {
    return this.inner.getRound(unixSeconds);
  }
  getRoundTime(round) {
    return this.inner.getRoundTime(round);
  }
  async fetchBeacon(round) {
    const cached = this.cache.get(round);
    try {
      const beacon = await this.inner.fetchBeacon(round);
      this.cache.set(round, beacon);
      return beacon;
    } catch (err) {
      if (cached) {
        return cached;
      }
      throw err;
    }
  }
  async verifyBeacon(beacon) {
    return this.inner.verifyBeacon(beacon);
  }
  /** Check if a round is in the cache. */
  has(round) {
    return this.cache.has(round);
  }
  /** Pre-populate the cache (e.g. from stored receipts). */
  seed(beacon) {
    this.cache.set(beacon.round, beacon);
  }
  /** Clear all cached entries. */
  clear() {
    this.cache.clear();
  }
};
function createDefaultBeacon() {
  return new DrandBeaconSource();
}
var BEACON_REGISTRY = /* @__PURE__ */ new Map([
  ["drand:quicknet", () => new DrandBeaconSource()],
  ["offline", () => new OfflineBeaconSource()]
]);
function getBeaconSource(id) {
  const factory = BEACON_REGISTRY.get(id);
  if (!factory) {
    throw new Error(`Unknown beacon: ${id}. Available: ${[...BEACON_REGISTRY.keys()].join(", ")}`);
  }
  return factory();
}
function registerBeacon(id, factory) {
  BEACON_REGISTRY.set(id, factory);
}

// src/commitment.ts
function createCommitment(opts) {
  const {
    rule,
    inputs,
    revealAfter,
    beacon: beaconId = "drand:quicknet",
    salt: providedSalt,
    metadata
  } = opts;
  if (!rule || typeof rule !== "string") {
    throw new Error("rule must be a non-empty string (canonical JSON)");
  }
  if (!Array.isArray(inputs) || inputs.length === 0) {
    throw new Error("inputs must be a non-empty array of strings");
  }
  if (typeof revealAfter !== "number" || revealAfter < 1) {
    throw new Error("revealAfter must be a positive number of seconds");
  }
  const beacon = getBeaconSource(beaconId);
  const nowSeconds = Math.floor(Date.now() / 1e3);
  const revealTime = nowSeconds + revealAfter;
  const targetRound = beacon.getRound(revealTime);
  const ruleHash = hashRule(rule);
  const inputsHash = hashInputs(inputs);
  const salt = providedSalt ?? generateSalt();
  const saltHex = toHex(salt);
  const commitHash = computeCommitHash(beaconId, targetRound, ruleHash, inputsHash, saltHex);
  const id = commitHash.slice(0, 32);
  return {
    id,
    beacon: beaconId,
    targetRound,
    ruleHash,
    inputsHash,
    commitHash,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    salt: saltHex,
    rule,
    inputs,
    metadata
  };
}

// src/resolve.ts
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function resolveCommitment(commitment, opts = {}) {
  const beacon = getBeaconSource(commitment.beacon);
  const maxWaitMs = opts.maxWaitMs ?? 15e3;
  const deadline = Date.now() + maxWaitMs;
  const roundTime = beacon.getRoundTime(commitment.targetRound);
  const now = Math.floor(Date.now() / 1e3);
  if (now < roundTime) {
    const waitSeconds = roundTime - now;
    if (!opts.wait) {
      throw new Error(
        `Target round ${commitment.targetRound} hasn't elapsed yet. Available at ${new Date(roundTime * 1e3).toISOString()} (${waitSeconds}s from now). Tip: pass { wait: true } (or use waitAndResolve) to wait automatically.`
      );
    }
    const waitMs = (roundTime - now) * 1e3 + 500;
    if (Date.now() + waitMs > deadline) {
      throw new Error(
        `Target round ${commitment.targetRound} is ${waitSeconds}s away, which exceeds maxWaitMs=${maxWaitMs}. Increase maxWaitMs or resolve later.`
      );
    }
    await sleep(waitMs);
  }
  let beaconRound;
  for (; ; ) {
    try {
      beaconRound = await beacon.fetchBeacon(commitment.targetRound);
      break;
    } catch (err) {
      if (opts.wait && Date.now() + 1e3 < deadline) {
        await sleep(1e3);
        continue;
      }
      const msg = err instanceof AggregateError ? err.message : err instanceof Error ? err.message : String(err);
      throw new Error(
        `Beacon fetch failed: ${msg}. For offline demos, use beaconId: 'offline' in CommitmentOptions.`
      );
    }
  }
  const verified = await beacon.verifyBeacon(beaconRound);
  const output = deriveOutput(
    beaconRound.randomness,
    commitment.ruleHash,
    commitment.inputsHash
  );
  let selection = null;
  try {
    const parsed = JSON.parse(commitment.rule);
    if (parsed.type && ["uniform", "shuffle", "index"].includes(parsed.type)) {
      const { applyRule: applyRule2 } = await import("./rules-CYM5GTRS.mjs");
      selection = applyRule2(commitment.rule, commitment.inputs, output);
    }
  } catch {
  }
  return {
    beaconRound: beaconRound.round,
    beaconSignature: beaconRound.signature,
    beaconRandomness: beaconRound.randomness,
    verified,
    output,
    selection
  };
}
async function waitAndResolve(commitment, opts = {}) {
  return resolveCommitment(commitment, { ...opts, wait: true });
}
function createReceipt(commitment, resolution, anchor) {
  return {
    version: "1.0.0",
    commitment,
    anchor: anchor ? { ...anchor, precedence: "onchain" } : void 0,
    resolution,
    precedence: anchor ? "onchain" : "unattested",
    attestation: anchor ? "self-anchored" : "unattested"
  };
}

// src/vdf-verify.ts
import { createHash as createHash2 } from "crypto";
var RSA2048_N = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357n;
function modpow(base, exp, mod) {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = (base % mod + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return result;
}
function isPrime(n) {
  if (n < 2n) return false;
  if (n < 4n) return true;
  if (n % 2n === 0n) return false;
  let d = n - 1n, r = 0;
  while (d % 2n === 0n) {
    d >>= 1n;
    r++;
  }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (a >= n) continue;
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 0; i < r - 1; i++) {
      x = x * x % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}
function hashToPrime(x, y, T, N) {
  const xHex = x.toString(16);
  const yHex = y.toString(16);
  const NPrefix = N.toString(16).slice(0, 16);
  let ctr = 0n;
  while (true) {
    const digest = createHash2("sha256").update(`wesolowski:${xHex}:${yHex}:${T}:${NPrefix}:${ctr}`).digest("hex");
    const candidate = BigInt("0x" + digest.slice(0, 32)) | 1n;
    if (isPrime(candidate)) return candidate;
    ctr++;
  }
}
function seedToGroupElement(seed, N = RSA2048_N) {
  const h = createHash2("sha256").update(seed).digest("hex");
  return BigInt("0x" + h) % (N - 4n) + 2n;
}
function sha2562(input) {
  return createHash2("sha256").update(input, "utf8").digest("hex");
}
function isVDFReceipt(obj) {
  if (!obj || typeof obj !== "object") return false;
  const r = obj;
  return typeof r["commitment_id"] === "string" && typeof r["committed_epoch"] === "number" && typeof r["commitment_time"] === "string";
}
function isRevealReceipt(receipt) {
  return "proof" in receipt && !!receipt.proof?.wesolowski_proof;
}
function checkCommitmentHash(receipt) {
  const preimage = `${receipt.commitment_id}|${receipt.committed_epoch}|${receipt.commitment_time}`;
  const recomputed = sha2562(preimage);
  const stored = receipt.commitment_hash || receipt.commitment_hash || receipt.verification?.commitment_hash;
  if (!stored) {
    return {
      ok: false,
      reason: `No commitment_hash field found (checked top-level and verification.commitment_hash). Recomputed value: ${recomputed}. Cannot confirm integrity without a stored hash.`
    };
  }
  if (recomputed === stored) return { ok: true };
  return {
    ok: false,
    reason: `Commitment hash mismatch: SHA256("${preimage}") = ${recomputed}, stored = ${stored}`
  };
}
function checkTemporalValidity(receipt) {
  const epochAtCommit = "current_epoch_at_commit" in receipt ? receipt.current_epoch_at_commit : receipt.current_epoch;
  if (typeof epochAtCommit !== "number") {
    return { ok: false, reason: "Missing current_epoch / current_epoch_at_commit field" };
  }
  if (receipt.committed_epoch > epochAtCommit) return { ok: true };
  return {
    ok: false,
    reason: `Temporal check failed: committed_epoch (${receipt.committed_epoch}) must be > epoch_at_commit (${epochAtCommit})`
  };
}
function checkValueDerivation(receipt) {
  const { y } = receipt.proof.wesolowski_proof;
  const expected = sha2562(`wesolowski-y|${y}`);
  if (expected === receipt.value) return { ok: true };
  return {
    ok: false,
    reason: `Value derivation mismatch: SHA256("wesolowski-y|"+y) = ${expected}, got ${receipt.value}`
  };
}
function checkSeedToX(proof, N) {
  const { seed, x } = proof.wesolowski_proof;
  try {
    const expectedX = seedToGroupElement(seed, N);
    const actualX = BigInt("0x" + x);
    if (expectedX === actualX) return { ok: true };
    return {
      ok: false,
      reason: `Seed \u2192 x mapping failed: seedToGroupElement("${seed}") produced 0x${expectedX.toString(16).slice(0, 16)}... but receipt has x = ${x}. Formula: (SHA256(seed) mod (N-4)) + 2`
    };
  } catch (err) {
    return { ok: false, reason: `Seed \u2192 x check error: ${err}` };
  }
}
function checkWesolowskiMath(proof, N) {
  try {
    const xB = BigInt("0x" + proof.x);
    const yB = BigInt("0x" + proof.y);
    const piB = BigInt("0x" + proof.pi);
    if (xB === 0n) return { ok: false, reason: "VDF input x is zero \u2014 invalid group element" };
    if (yB === 0n) return { ok: false, reason: "VDF output y is zero \u2014 invalid group element" };
    if (piB === 0n) return { ok: false, reason: "VDF proof \u03C0 is zero \u2014 invalid proof element" };
    const l = hashToPrime(xB, yB, proof.T, N);
    const r = modpow(2n, BigInt(proof.T), l);
    const lhs = modpow(piB, l, N) * modpow(xB % N, r, N) % N;
    const rhs = yB % N;
    if (lhs === rhs) return { ok: true };
    return {
      ok: false,
      reason: `Wesolowski verification failed: \u03C0^\u2113 \xB7 x^r \u2262 y (mod N). The VDF output cannot be confirmed as correct. lhs (first 16 hex) = ${lhs.toString(16).slice(0, 16)}, rhs = ${rhs.toString(16).slice(0, 16)}`
    };
  } catch (err) {
    return { ok: false, reason: `Wesolowski math check error: ${err}` };
  }
}
async function verifyVDFReceipt(receipt, options) {
  const N = options?.N ?? RSA2048_N;
  const skipMath = options?.skipMath ?? false;
  const checks = {
    commitmentHashVerified: false,
    temporalValid: false,
    valueDerivationVerified: false,
    seedToXVerified: false,
    wesolowskiMathVerified: false
  };
  const reasons = [];
  if (!receipt || typeof receipt !== "object") {
    return {
      status: "UNVERIFIABLE",
      checks,
      reason: "Receipt is null or not an object"
    };
  }
  const c1 = checkCommitmentHash(receipt);
  checks.commitmentHashVerified = c1.ok;
  if (!c1.ok && c1.reason) reasons.push(c1.reason);
  const c2 = checkTemporalValidity(receipt);
  checks.temporalValid = c2.ok;
  if (!c2.ok && c2.reason) reasons.push(c2.reason);
  if (isRevealReceipt(receipt)) {
    const wp = receipt.proof.wesolowski_proof;
    const c3 = checkValueDerivation(receipt);
    checks.valueDerivationVerified = c3.ok;
    if (!c3.ok && c3.reason) reasons.push(c3.reason);
    const c4 = checkSeedToX(receipt.proof, N);
    checks.seedToXVerified = c4.ok;
    if (!c4.ok && c4.reason) reasons.push(c4.reason);
    if (!skipMath) {
      const c5 = checkWesolowskiMath(wp, N);
      checks.wesolowskiMathVerified = c5.ok;
      if (!c5.ok && c5.reason) reasons.push(c5.reason);
    } else {
      reasons.push(
        "Wesolowski math verification skipped (skipMath: true). Hash-chain integrity verified only; VDF soundness (T squarings) is NOT confirmed."
      );
    }
  }
  let status;
  if (!checks.commitmentHashVerified || !checks.temporalValid) {
    status = "INVALID";
  } else if (!isRevealReceipt(receipt)) {
    status = "PARTIAL";
  } else {
    const hashesOk = checks.valueDerivationVerified && checks.seedToXVerified;
    if (hashesOk && checks.wesolowskiMathVerified) {
      status = "VALID";
    } else if (hashesOk && skipMath) {
      status = "PARTIAL";
    } else {
      status = "INVALID";
    }
  }
  return {
    status,
    checks,
    reason: reasons.length > 0 ? reasons.join("; ") : void 0
  };
}

// src/verify.ts
function mapVDFResult(vdf) {
  const status = vdf.status === "UNVERIFIABLE" ? "INVALID" : vdf.status;
  return {
    status,
    checks: {
      commitmentIntegrity: vdf.checks.commitmentHashVerified,
      precedenceVerified: vdf.checks.temporalValid,
      beaconVerified: vdf.checks.wesolowskiMathVerified,
      outputVerified: vdf.checks.valueDerivationVerified,
      selectionVerified: false
    },
    reason: vdf.reason
  };
}
function validateAnchorStructure(anchor) {
  if (!anchor.txHash || typeof anchor.txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(anchor.txHash)) {
    return "Invalid txHash format (expected 0x-prefixed 32-byte hex)";
  }
  if (typeof anchor.blockNumber !== "number" || !Number.isInteger(anchor.blockNumber) || anchor.blockNumber <= 0) {
    return "Invalid blockNumber (expected positive integer)";
  }
  if (typeof anchor.blockTimestamp !== "number" || anchor.blockTimestamp <= 0) {
    return "Invalid blockTimestamp (expected positive Unix timestamp)";
  }
  if (typeof anchor.chainId !== "number" || !Number.isInteger(anchor.chainId) || anchor.chainId <= 0) {
    return "Invalid chainId (expected positive integer)";
  }
  return null;
}
async function verifyReceipt(receipt, options) {
  if (isVDFReceipt(receipt)) {
    const vdfResult = await verifyVDFReceipt(receipt);
    return mapVDFResult(vdfResult);
  }
  const checks = {
    commitmentIntegrity: false,
    precedenceVerified: false,
    beaconVerified: false,
    outputVerified: false,
    selectionVerified: false
  };
  const reasons = [];
  let anchorClaimUnverified = false;
  const { commitment, anchor, resolution } = receipt;
  try {
    const recomputedRuleHash = hashRule(commitment.rule);
    const recomputedInputsHash = hashInputs(commitment.inputs);
    if (recomputedRuleHash !== commitment.ruleHash) {
      reasons.push(`Rule hash mismatch: expected ${recomputedRuleHash}, got ${commitment.ruleHash}`);
    } else if (recomputedInputsHash !== commitment.inputsHash) {
      reasons.push(`Inputs hash mismatch: expected ${recomputedInputsHash}, got ${commitment.inputsHash}`);
    } else {
      const recomputedCommitHash = computeCommitHash(
        commitment.beacon,
        commitment.targetRound,
        commitment.ruleHash,
        commitment.inputsHash,
        commitment.salt
      );
      if (recomputedCommitHash === commitment.commitHash) {
        checks.commitmentIntegrity = true;
      } else {
        reasons.push(`Commit hash mismatch: expected ${recomputedCommitHash}, got ${commitment.commitHash}`);
      }
    }
  } catch (err) {
    reasons.push(`Commitment integrity check failed: ${err}`);
  }
  const strictAnchor = options?.strictAnchor !== false;
  if (anchor && receipt.precedence === "onchain") {
    const structError = validateAnchorStructure(anchor);
    if (structError) {
      anchorClaimUnverified = true;
      reasons.push(`Anchor proof structurally invalid: ${structError}`);
    } else if (options?.verifyAnchor) {
      try {
        const anchorValid = await options.verifyAnchor(anchor, commitment.commitHash);
        if (anchorValid) {
          const beacon = getBeaconSource(commitment.beacon);
          const roundTime = beacon.getRoundTime(commitment.targetRound);
          if (anchor.blockTimestamp < roundTime) {
            checks.precedenceVerified = true;
          } else {
            reasons.push("Anchor timestamp does not precede target round time");
          }
        } else {
          anchorClaimUnverified = true;
          reasons.push("Anchor proof rejected by verifyAnchor callback");
        }
      } catch (err) {
        anchorClaimUnverified = true;
        reasons.push(`Anchor verification failed: ${err}`);
      }
    } else {
      anchorClaimUnverified = true;
      if (strictAnchor) {
        reasons.push(
          "Receipt claims on-chain precedence but no verifyAnchor callback provided. Self-reported anchor data cannot be trusted without independent on-chain verification. Pass a verifyAnchor callback, or set strictAnchor: false to accept unverified claims (not recommended)."
        );
      } else {
        reasons.push(
          "Anchor proof present but not independently verified (strictAnchor: false). Self-reported anchor data accepted without on-chain verification \u2014 NOT suitable for audit/compliance."
        );
        anchorClaimUnverified = false;
      }
    }
  } else if (receipt.precedence === "unattested") {
    reasons.push("Precedence is unattested \u2014 commitment timing cannot be independently verified");
  }
  if (resolution) {
    try {
      const beacon = getBeaconSource(commitment.beacon);
      if (commitment.beacon === "offline") {
        reasons.push(
          "Offline beacon used \u2014 no BLS signature present. Offline mode produces deterministic sha256 outputs, not drand BLS12-381 signatures. Offline receipts cannot be cryptographically attested; do not use in audit contexts."
        );
      } else {
        const beaconRound = await beacon.fetchBeacon(commitment.targetRound);
        if (beaconRound.randomness !== resolution.beaconRandomness || beaconRound.signature !== resolution.beaconSignature) {
          reasons.push("Beacon randomness/signature does not match fetched round");
        } else {
          const blsValid = await beacon.verifyBeacon(beaconRound);
          if (blsValid) {
            checks.beaconVerified = true;
          } else {
            reasons.push(
              "Beacon data matches relay response but BLS12-381 signature failed cryptographic verification. Possible relay compromise, signature forgery, or malformed beacon data. Fail-closed: beaconVerified set to false."
            );
          }
        }
      }
    } catch (err) {
      reasons.push(`Beacon verification failed: ${err}`);
    }
  }
  if (resolution) {
    try {
      const recomputedOutput = deriveOutput(
        resolution.beaconRandomness,
        commitment.ruleHash,
        commitment.inputsHash
      );
      if (recomputedOutput === resolution.output) {
        checks.outputVerified = true;
      } else {
        reasons.push(`Output mismatch: expected ${recomputedOutput}, got ${resolution.output}`);
      }
    } catch (err) {
      reasons.push(`Output verification failed: ${err}`);
    }
  }
  if (resolution && checks.outputVerified) {
    try {
      const parsed = JSON.parse(commitment.rule);
      if (parsed.type && ["uniform", "shuffle", "index"].includes(parsed.type)) {
        const { applyRule: applyRule2 } = await import("./rules-CYM5GTRS.mjs");
        const recomputedSelection = applyRule2(commitment.rule, commitment.inputs, resolution.output);
        if (JSON.stringify(recomputedSelection) === JSON.stringify(resolution.selection)) {
          checks.selectionVerified = true;
        } else {
          reasons.push("Selection does not match rule application to output");
        }
      } else {
        checks.selectionVerified = false;
        reasons.push("Custom rule \u2014 selection verification requires operator-provided verification function");
      }
    } catch (err) {
      reasons.push(`Selection verification failed: ${err}`);
    }
  }
  let status;
  const coreChecks = checks.commitmentIntegrity && checks.beaconVerified && checks.outputVerified;
  if (anchorClaimUnverified) {
    status = "INVALID";
  } else if (coreChecks && checks.selectionVerified) {
    status = checks.precedenceVerified ? "VALID" : "PARTIAL";
  } else if (coreChecks && !checks.selectionVerified) {
    status = "PARTIAL";
  } else {
    status = "INVALID";
  }
  return {
    status,
    checks,
    reason: reasons.length > 0 ? reasons.join("; ") : void 0
  };
}
export {
  CachedBeaconSource,
  DRAND_QUICKNET,
  DrandBeaconSource,
  OfflineBeaconSource,
  RSA2048_N,
  applyRule,
  computeCommitHash,
  createCommitment,
  createDefaultBeacon,
  createReceipt,
  deriveOutput,
  fromHex,
  getBeaconSource,
  hashInputs,
  hashRule,
  isVDFReceipt,
  registerBeacon,
  resolveCommitment,
  sha256,
  toHex,
  validateRule,
  verifyReceipt,
  verifyVDFReceipt,
  waitAndResolve
};
