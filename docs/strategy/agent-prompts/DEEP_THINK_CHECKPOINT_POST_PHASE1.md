# Deep Think Checkpoint: Post-Phase 1 Validation

> Use this prompt after Phase 1 (teardown) is complete. Generate with:
> `/deep-think-prompt . --preset lean`
> Then prepend this mission block to the output.

## Mission

You previously reviewed this ecosystem and diagnosed the "Nation-State Anti-Pattern." We have executed your Phase 1 recommendations. Please validate:

1. **Teardown completeness:** We archived 12 services. Did we miss anything that should have been killed? Is there dead-weight code still in the active services?

2. **Remaining architecture:** The surviving services are:
   - `clawverify` (Trust Oracle)
   - `clawproxy` (Data Plane)
   - `clawlogs` (to be absorbed into clawverify)
   - `clawcontrols` (to be absorbed into clawea)
   - `clawscope` (to be absorbed into clawea)
   - `clawea-www` (enterprise dashboard + protocol site)
   
   Are there cross-dependencies between archived and surviving services that will cause runtime failures?

3. **Schema preservation:** We kept `packages/schema/` intact as reference material. Should any schemas be deprecated or marked as legacy?

4. **EIP-8004 readiness:** Given the surviving codebase, what's the shortest path to becoming an EIP-8004 Validation Oracle? What needs to change in `clawverify`?

5. **x402 readiness:** Given the surviving `clawproxy` codebase, what's the shortest path to x402 Resource Server? What needs to be removed (CST-related economy code) vs. kept (CST-related policy enforcement)?

Be specific. Reference file paths. Challenge our execution.
