# @fairseal/auto

> Part of [FairSeal](https://fairseal.io) — formerly OpenRNG.

> Auto-instrument AI SDK calls to emit VEO-2 objects. One line, zero code changes.

## Install

```bash
npm install @fairseal/auto @fairseal/core
```

## Quick Start

```typescript
import OpenAI from 'openai';
import { auto } from '@fairseal/auto';

// Wrap your existing client — one line
const client = auto(new OpenAI());

// Use exactly as before — VEOs are emitted automatically
const response = await client.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'What is the capital of France?' }],
});
// response is unchanged — same OpenAI response object
// but a VEO-2 record was created in the background
```

## With Anthropic

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { auto } from '@fairseal/auto';

const client = auto(new Anthropic());

const message = await client.messages.create({
  model: 'claude-4-sonnet',
  messages: [{ role: 'user', content: 'Hello' }],
});
```

## With Signing

```typescript
import { auto } from '@fairseal/auto';
import { generateSigningKeys } from '@fairseal/core';

const keys = generateSigningKeys();
const client = auto(new OpenAI(), {
  privateKey: keys.privateKey,
  provider: 'my-service',
});
// Every VEO is now Ed25519-signed and independently verifiable
```

## Accessing VEOs

```typescript
import { auto, MemoryStore } from '@fairseal/auto';

const store = new MemoryStore();
const client = auto(new OpenAI(), { store });

await client.chat.completions.create({ ... });

// Get all recorded VEOs
const veos = store.list();
console.log(veos[0].execution?.model_id); // 'gpt-4o'
console.log(veos[0].execution?.cost);     // { total_tokens: 150 }
```

## Callback on Every VEO

```typescript
const client = auto(new OpenAI(), {
  onVEO: (veo) => {
    console.log('AI call recorded:', veo.object_id);
    // Send to your observability pipeline, database, etc.
  },
});
```

## What Gets Captured

Every instrumented call produces a VEO with:

| Field | Source |
|---|---|
| `execution.prompt_hash` | SHA-256 of the prompt/messages |
| `execution.output_hash` | SHA-256 of the response |
| `execution.model_id` | Model from the request |
| `execution.latency_ms` | Measured response time |
| `execution.cost` | Token usage from response |
| `execution.tool_calls` | Tool/function calls if any |
| `confidence.score` | 700 (success) or 100 (error) |
| `lifecycle.state` | 'created' or 'signed' |

## Instrumented Methods

| SDK | Methods |
|---|---|
| OpenAI | `chat.completions.create`, `completions.create`, `embeddings.create`, `images.generate` |
| Anthropic | `messages.create` |
| Generic | `create`, `generate`, `complete` |

## Safety Guarantees

- **Never breaks your API calls** — VEO emission errors are caught and logged, never thrown
- **No SDK dependency** — works with any client object via ES Proxy
- **Zero performance impact** — VEO creation happens after the API call returns

## Related Packages

| Package | Purpose |
|---|---|
| `@fairseal/core` | Types, schema, signing, validation |
| `@fairseal/auto` | Auto-instrumentation (this package) |

## License

MIT — [FairSeal](https://fairseal.io)
