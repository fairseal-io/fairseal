# @fairseal/core

> Part of [FairSeal](https://fairseal.io) — formerly OpenRNG.

> VEO-2 types, schema, and shared primitives for the FairSeal ecosystem.

**VEO** = Verifiable Execution Object — a standard format for recording, proving, and explaining AI decisions.

## Install

```bash
npm install @fairseal/core
```

## Quick Start

```typescript
import { createVEO, validateVEO, createVEOHash } from '@fairseal/core';

// Create a VEO for an AI execution
const veo = createVEO({
  provider_id: 'my-service',
  execution: {
    prompt_hash: 'sha256-of-prompt',
    output_hash: 'sha256-of-output',
    model_id: 'gpt-4o',
    latency_ms: 412,
    cost: { total_tokens: 1500, cost_usd: 0.003 },
  },
  confidence: { score: 850, grade: 'AA' },
});

// Validate
const { valid, errors } = validateVEO(veo);

// Hash (for anchoring)
const hash = createVEOHash(veo);
```

## Object Classes

| Class | Name | Use Case |
|---|---|---|
| VEO-2A | Raw Execution | Single AI call (chat, completion, inference) |
| VEO-2B | Composite Execution | Multi-step chains, agent pipelines |
| VEO-2C | Anchored Execution | With blockchain proof / Merkle anchor |
| VEO-2D | Governed Execution | With policy assertions, human approvals |

## VEO Lifecycle

```
created → signed → anchored → indexed → verified
```

## Full Spec

- [RFC-0002: VEO-2](https://github.com/fairseal-io/fairseal/blob/main/docs/rfc/RFC-0002-VEO2.md)
- [JSON Schema](https://github.com/fairseal-io/fairseal/blob/main/schemas/veo-2.schema.json)
- [Example VEO objects](https://github.com/fairseal-io/fairseal/tree/main/docs/rfc/veo-2-examples)

## Related Packages

| Package | Purpose |
|---|---|
| `@fairseal/core` | Types, schema, validation (this package) |
| `@fairseal/verify` | Verify any VEO object |
| `@fairseal/auto` | Auto-instrument AI SDK calls |

## License

MIT — [FairSeal](https://fairseal.io)
