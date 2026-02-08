# Oracle prompt: PoH red-team / anti-gaming

We need PoH to be robust against tampering and gaming by clever adversaries.

Current system primitives:
- Signed proof bundle (agent DID key)
- URM reference (content-addressed hash)
- Hash-linked event chain
- Signed gateway receipts (clawproxy), allowlisted signer DIDs
- Receipt binding enforcement (run_id + event_hash_b64u)
- Optional attestations (future)

Task:
1) Red-team the system: list the top 25 ways a worker could try to cheat (forge, replay, downgrade, confuse, exploit verification gaps, abuse streaming, exploit policy hash confusion, etc.).
2) For each attack, state:
   - what evidence gets corrupted
   - whether current verification catches it
   - proposed mitigation (prefer fail-closed)
3) Identify any “hard” unsolved problems and recommend compensating controls (marketplace policies, stake, human review).
4) Propose a set of automated verification checks we should add to clawverify and/or clawbounties (beyond what exists).

Output format:
- Table: Attack → Impact → Current coverage → Mitigation.
- Then: top 10 engineering changes.
