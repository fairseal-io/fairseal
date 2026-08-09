"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/bls-verify.ts
var bls_verify_exports = {};
__export(bls_verify_exports, {
  verifyDrandBeacon: () => verifyDrandBeacon
});
async function getBLS() {
  if (!_bls) {
    _bls = await import("@noble/curves/bls12-381");
  }
  return _bls.bls12_381;
}
async function verifyDrandBeacon(round, signatureHex, randomnessHex, publicKeyHex) {
  try {
    const bls12_381 = await getBLS();
    const roundBytes = Buffer.alloc(8);
    roundBytes.writeBigUInt64BE(BigInt(round));
    const msgHash = (0, import_node_crypto2.createHash)("sha256").update(roundBytes).digest();
    const sigPoint = bls12_381.G1.Point.fromHex(signatureHex);
    const pkPoint = bls12_381.G2.Point.fromHex(publicKeyHex);
    const msgPoint = bls12_381.G1.hashToCurve(msgHash, { DST: DRAND_QUICKNET_DST });
    const g2gen = bls12_381.G2.Point.BASE;
    const p1 = bls12_381.pairing(sigPoint, g2gen);
    const p2 = bls12_381.pairing(msgPoint, pkPoint);
    const valid = bls12_381.fields.Fp12.eql(p1, p2);
    if (!valid) return false;
    const sigBytes = Buffer.from(signatureHex, "hex");
    const expectedRandomness = (0, import_node_crypto2.createHash)("sha256").update(sigBytes).digest("hex");
    return expectedRandomness === randomnessHex;
  } catch {
    return false;
  }
}
var import_node_crypto2, _bls, DRAND_QUICKNET_DST;
var init_bls_verify = __esm({
  "src/bls-verify.ts"() {
    "use strict";
    import_node_crypto2 = require("crypto");
    _bls = null;
    DRAND_QUICKNET_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
  }
});

// src/rules.ts
var rules_exports = {};
__export(rules_exports, {
  applyRule: () => applyRule,
  validateRule: () => validateRule
});
function applyRule(rule, inputs, outputHex) {
  const parsed = JSON.parse(rule);
  const entropy = BigInt("0x" + outputHex);
  switch (parsed.type) {
    case "uniform": {
      const pick = parsed.pick ?? 1;
      if (pick > inputs.length) {
        throw new Error(`Cannot pick ${pick} from ${inputs.length} inputs`);
      }
      if (pick < 1) {
        throw new Error(`pick must be >= 1, got ${pick}`);
      }
      const shuffled = fisherYatesShuffle([...inputs], entropy);
      return pick === 1 ? shuffled[0] : shuffled.slice(0, pick);
    }
    case "shuffle": {
      return fisherYatesShuffle([...inputs], entropy);
    }
    case "index": {
      return Number(entropy % BigInt(inputs.length));
    }
    default:
      throw new Error(`Unknown rule type: ${parsed.type}`);
  }
}
function fisherYatesShuffle(arr, entropy) {
  let e = entropy;
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Number(e % BigInt(i + 1));
    e = e / BigInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
function validateRule(rule) {
  try {
    const parsed = JSON.parse(rule);
    if (!parsed.type) {
      return { valid: false, error: 'Rule must have a "type" field' };
    }
    if (!["uniform", "shuffle", "index"].includes(parsed.type)) {
      return { valid: false, error: `Unknown rule type: ${parsed.type}` };
    }
    return { valid: true };
  } catch {
    return { valid: false, error: "Rule must be valid JSON" };
  }
}
var init_rules = __esm({
  "src/rules.ts"() {
    "use strict";
  }
});

// src/index.ts
var index_exports = {};
__export(index_exports, {
  CachedBeaconSource: () => CachedBeaconSource,
  DRAND_QUICKNET: () => DRAND_QUICKNET,
  DrandBeaconSource: () => DrandBeaconSource,
  OfflineBeaconSource: () => OfflineBeaconSource,
  applyRule: () => applyRule,
  computeCommitHash: () => computeCommitHash,
  createCommitment: () => createCommitment,
  createDefaultBeacon: () => createDefaultBeacon,
  createReceipt: () => createReceipt,
  deriveOutput: () => deriveOutput,
  fromHex: () => fromHex,
  getBeaconSource: () => getBeaconSource,
  hashInputs: () => hashInputs,
  hashRule: () => hashRule,
  registerBeacon: () => registerBeacon,
  resolveCommitment: () => resolveCommitment,
  sha256: () => sha256,
  toHex: () => toHex,
  validateRule: () => validateRule,
  verifyReceipt: () => verifyReceipt
});
module.exports = __toCommonJS(index_exports);

// src/crypto.ts
var import_node_crypto = require("crypto");
function sha256(input) {
  return (0, import_node_crypto.createHash)("sha256").update(input, "utf8").digest("hex");
}
function hmacSha256(keyHex, dataHex) {
  const key = Buffer.from(keyHex, "hex");
  const data = Buffer.from(dataHex, "hex");
  return (0, import_node_crypto.createHmac)("sha256", key).update(data).digest("hex");
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
  return (0, import_node_crypto.randomBytes)(32);
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
      const { verifyDrandBeacon: verifyDrandBeacon2 } = await Promise.resolve().then(() => (init_bls_verify(), bls_verify_exports));
      return await verifyDrandBeacon2(
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
async function resolveCommitment(commitment) {
  const beacon = getBeaconSource(commitment.beacon);
  const roundTime = beacon.getRoundTime(commitment.targetRound);
  const now = Math.floor(Date.now() / 1e3);
  if (now < roundTime) {
    const waitSeconds = roundTime - now;
    throw new Error(
      `Target round ${commitment.targetRound} hasn't elapsed yet. Available at ${new Date(roundTime * 1e3).toISOString()} (${waitSeconds}s from now)`
    );
  }
  let beaconRound;
  try {
    beaconRound = await beacon.fetchBeacon(commitment.targetRound);
  } catch (err) {
    const msg = err instanceof AggregateError ? err.message : err instanceof Error ? err.message : String(err);
    throw new Error(
      `Beacon fetch failed: ${msg}. For offline demos, use beaconId: 'offline' in CommitmentOptions.`
    );
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
      const { applyRule: applyRule2 } = await Promise.resolve().then(() => (init_rules(), rules_exports));
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

// src/verify.ts
async function verifyReceipt(receipt) {
  const checks = {
    commitmentIntegrity: false,
    precedenceVerified: false,
    beaconVerified: false,
    outputVerified: false,
    selectionVerified: false
  };
  const reasons = [];
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
  if (anchor && receipt.precedence === "onchain") {
    try {
      const beacon = getBeaconSource(commitment.beacon);
      const roundTime = beacon.getRoundTime(commitment.targetRound);
      if (anchor.blockTimestamp < roundTime) {
        checks.precedenceVerified = true;
      } else {
        reasons.push(
          `Anchor timestamp (${anchor.blockTimestamp}) does not precede target round time (${roundTime})`
        );
      }
    } catch (err) {
      reasons.push(`Precedence check failed: ${err}`);
    }
  } else if (receipt.precedence === "unattested") {
    reasons.push("Precedence is unattested \u2014 commitment timing cannot be independently verified");
  }
  if (resolution) {
    try {
      const beacon = getBeaconSource(commitment.beacon);
      const beaconRound = await beacon.fetchBeacon(commitment.targetRound);
      if (beaconRound.randomness === resolution.beaconRandomness && beaconRound.signature === resolution.beaconSignature) {
        checks.beaconVerified = true;
      } else {
        reasons.push("Beacon randomness/signature does not match fetched round");
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
        const { applyRule: applyRule2 } = await Promise.resolve().then(() => (init_rules(), rules_exports));
        const recomputedSelection = applyRule2(commitment.rule, commitment.inputs, resolution.output);
        if (JSON.stringify(recomputedSelection) === JSON.stringify(resolution.selection)) {
          checks.selectionVerified = true;
        } else {
          reasons.push("Selection does not match rule application to output");
        }
      } else {
        checks.selectionVerified = resolution.selection !== null;
        if (!checks.selectionVerified) {
          reasons.push("Custom rule \u2014 selection verification requires operator algorithm");
        }
      }
    } catch (err) {
      reasons.push(`Selection verification failed: ${err}`);
    }
  }
  let status;
  const coreChecks = checks.commitmentIntegrity && checks.beaconVerified && checks.outputVerified;
  if (coreChecks && checks.selectionVerified) {
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

// src/index.ts
init_rules();
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  CachedBeaconSource,
  DRAND_QUICKNET,
  DrandBeaconSource,
  OfflineBeaconSource,
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
  registerBeacon,
  resolveCommitment,
  sha256,
  toHex,
  validateRule,
  verifyReceipt
});
