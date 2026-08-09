# GLI Pre-Consultation — Draft Materials

## Contact Points

GLI doesn't have a formal "pre-submission consultation" program like medical device regulators. The approach is:

1. **Ask GLI** — General inquiry through gaminglabs.com contact form
2. **Direct engagement** — Request a "Technical Consultation" for novel RNG technology
3. **Conference meetings** — GLI attends ICE, G2E, iGB L!VE — good for initial introductions

### GLI Office Locations (APAC)
- **Manila** — Philippines (closest to Taiwan)
- **Sydney** — Australia
- **Macau** — China

### Alternative: iTech Labs
- Based in Melbourne, Australia
- Accepted by MGA, AGCO (Ontario), many APAC regulators
- May be more receptive to novel approaches (smaller, more flexible)
- Contact: info@itechlabs.com

## Draft Email (for Ned to review and send)

---

**To:** askgli@gaminglabs.com (or iTech Labs equivalent)
**Subject:** Technical Consultation Request — Novel Provably Fair RNG Architecture (Beacon-Committed Seed Model)

Dear GLI Technical Team,

We are FairSeal (fairseal.io), a developer tools company building verifiable randomness infrastructure for the gaming industry. We are seeking a pre-certification technical consultation regarding a novel RNG architecture that we believe satisfies GLI-19 v3.0 requirements while providing player-verifiable fairness.

**Technology Summary:**
Our "Seed Commitment Model" differs from traditional server-seed PF by using a publicly verifiable external randomness beacon (drand, BLS12-381 signed) as the entropy source. The game operator commits their server seed before the beacon round, and the final RNG output is derived via HMAC-SHA256 of the server seed and beacon output.

**Key Question for Consultation:**
We have designed two modes:
- **Mode A:** Player-provided seed participates in the HMAC derivation path. This prevents dealer grinding but means player input is part of the RNG computation.
- **Mode B:** Player seed is recorded as a commitment witness only — it does not enter the HMAC derivation. RNG output is determined solely by server seed + beacon.

We would like your guidance on whether Mode A's player seed inclusion would present concerns under GLI-19 Section 3.3.2(b) (Known Input Attack resistance), and whether Mode B satisfies the strictest reading of GLI-19 for software RNG certification.

**What We're Requesting:**
A 30-60 minute technical consultation (video call) with your RNG certification team to review our architecture before formal submission. We can provide:
- Full technical specification (RFC document)
- Working demo (play.fairseal.io)
- GLI-19 compliance mapping (section-by-section analysis)
- Source code for review

**About Us:**
- 5 PCT patent applications filed (ISR favorable for primary application)
- npm packages: @fairseal/commit, @fairseal/core, @fairseal/verify
- Live demo: play.fairseal.io (Sic Bo, Slots, Gacha — all with verifiable proof chains)
- x402 micropayment infrastructure operational

We are based in Taipei, Taiwan and are flexible on timing for APAC or global teams.

Best regards,
[Ned]
FairSeal
ned@aeom.com
fairseal.io

---

## Notes for Ned
- Don't mention AEOM or bratops — keep it pure FairSeal identity
- Emphasize Mode B as the "safe" option for regulated markets
- The consultation is about validating our approach BEFORE spending money on full certification
- Budget: GLI consultations typically cost $5,000-$15,000 USD
- Timeline: expect 2-4 weeks for scheduling after initial inquiry
