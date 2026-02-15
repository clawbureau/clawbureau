# What 22 Rounds and 10 A/B Tests Taught Me About Prompting Deep Think Models

*Over 72 hours, I ran 22 rounds of Gemini 3 Pro Deep Think to architect and implement a C interposition library — from 1,069 lines to 2,242 lines, 30 DYLD_INTERPOSE hooks, streaming HTTP parsing, cryptographic receipts, and behavioral anomaly detection. In the last 3 rounds, I ran 10 controlled A/B tests with identical source code context but radically different prompt strategies, compiled every output, and scored them on 7 dimensions. Here's what the data says.*

---

## The Experiment

Same problem. Same 80KB of source code. 10 different prompts. Every output was extracted, compiled on macOS ARM64, runtime tested, and scored. The prompts varied on one axis at a time where possible: how much structure, how much guidance, what framing.

This isn't vibes. These are measured outcomes.

---

## The One Chart That Matters

```
Score vs Instruction Size (source code held constant at ~80KB)

7.7  F ·····················  "Red team this, then fix what you found"
7.0  I ·················       "Here's the problem. Solve it." (2.3KB instructions)
6.7  B ·············          "Two experts debate the architecture" 
6.7  E ·············          "Follow this checklist"
6.6  D ············           "You are a senior architect"
6.6  J ············           "Experts say it's impossible. Prove them wrong"
6.3  H ···········            "Red team + debate + checklist + everything" (6.8KB instructions)
5.7  C ········              Persona + source, no structure
4.9  C ·····                 Persona only, no source code
4.3  G ····                  Bare minimum, no source, no persona
     
     ←— instruction size —→
```

**The U-curve is real.** The two highest-scoring variants used opposite strategies. F gave maximum adversarial specificity ("red team this THEN fix it"). I gave minimum guidance ("just solve it"). The middle-ground approaches — debates, checklists, personas, combined everything — clustered at 6.3-6.7 regardless of which combination you tried.

More structure does not mean better output. Past ~4KB of instructions, it actively hurts.

---

## The 3 Levers That Actually Move Scores

Everything else is noise. These three things explained >90% of the variance:

### 1. Source Code Inclusion (+0.8 to +2.5 points)

The single biggest binary decision. With source code: 5.7-7.7. Without: 4.3-4.9.

| Prompt | Source Code? | Score |
|---|---|---|
| G (Bare) | No | 4.3 |
| C (Naked) | No | 4.9 |
| C (YOLO) | **Yes** | 5.7 |
| Everything else | **Yes** | 6.3-7.7 |

Source code is not "context." It's the problem definition. When the model sees the actual `tracked_fds` array, the `DYLD_INTERPOSE` macro, the `sha256_ctx_t` typedef — it writes code that plugs into the existing infrastructure. When it sees a description of those things, it invents its own incompatible versions.

**Include the actual files. Not summaries. Not descriptions. The files.**

Summaries lose the bugs. In every round, the model found issues in the source code that weren't mentioned in the problem description — re-entrancy hazards, missing error paths, ordering dependencies. You can't find bugs in a summary.

### 2. Adversarial Framing (+2.0 points)

The single highest-impact prompting technique across all rounds. F ("Red Team") scored 7.7 — a full 2 points above the same source code with a neutral framing.

What F's prompt did:
```
PHASE 1: You are a hostile agent trying to evade this library.
         Find every weakness. Be specific about syscall mechanics.

PHASE 2: Now fix every weakness you found.
         Deliver the complete file.
```

That's it. Two phases. "Attack it, then fix it." No debate, no checklist, no persona.

**Why it works:** The red team phase forces the model to deeply understand the existing code before writing new code. It can't find attack surfaces without understanding data flow, buffer management, and hook ordering. By the time it starts writing, it has a mental model of the codebase that no amount of "analyze the code first" instructions can replicate. The attacks become the specification for the fixes.

**Why the adversarial CHALLENGE variant (J, "Crucible") scored lower (6.6):** J framed it as "experts say it's impossible, prove them wrong." This produced structural innovation (the first HTTP DFA) but also reckless confidence — J dropped 5 existing functions to make room for new code. The red team framing produces defensive thinking. The challenge framing produces offensive thinking. Defensive is better for production code.

### 3. Instruction Minimalism (+1.3 points, or: don't subtract points)

I's prompt was 2.3KB of instructions + 80KB of source code. H's prompt was 6.8KB of instructions + 80KB of source code. Same source code. I scored 7.0 and compiled first try. H scored 6.3 and never compiled.

H told the model exactly what to build: a 3-phase structure (red team, debate, implement), 5 required subsystems, specific data structures, buffer sizes, hash formulas. The model obediently followed every instruction — and forgot to emit the 100 lines of macro/function-pointer boilerplate that make the file actually compile.

I said: "Here's the problem. Here's the code. Solve it. What I care about, in order: [4 bullet points]." The model decided its own architecture, included every piece of infrastructure, and produced a working binary.

**The instruction tax:** Every KB of instructions you add is a KB of attention the model diverts from code correctness to instruction compliance. At 80KB+ total context, this tradeoff becomes destructive. The model has finite capacity — spend it on understanding the code, not on parsing your multi-phase output format.

**Exception:** The red team framing (Lever #2) is worth its instruction cost because it changes HOW the model thinks, not WHAT it outputs. "Attack this" is 2 words that reshape the entire reasoning process. "Phase 1: Red Team Analysis, Phase 2: Cryptographer-vs-Systems-Programmer Debate, Phase 3: Implementation with the following 5 required subsystems..." is 50 words that reshape the output format while constraining the reasoning.

---

## What Didn't Matter (The Noise)

These techniques showed no measurable impact across controlled tests:

**Persona framing:** "You are the best systems programmer alive" vs no persona = noise. D (strong persona) and E (checklist, no persona) scored identically (6.6 vs 6.7). Personas may help on simpler tasks; at 80KB context with real source code, the code IS the persona.

**Debate format:** B (two experts debate) scored 6.7. E (checklist) scored 6.7. D (architect persona) scored 6.6. Three different structural approaches, same outcome. Once you include source code, the model's reasoning quality plateaus at ~6.6 regardless of what social frame you put on it.

**Combining techniques:** H combined red team + debate + checklist + persona. It scored LOWEST of all R22 variants (6.3). The techniques don't stack — they compete for attention. Each structural element added is attention stolen from code generation.

**Flattery:** Calibrated flattery ("you are the best X, here's a problem worthy of that expertise") showed impact in early rounds without source code. With source code, the effect disappeared. The code's complexity already signals "this is a hard problem" more credibly than any verbal framing.

---

## The 4 Dimensions That Predict Success

The original 7-dimension scoring was overkill. Four dimensions explained all the meaningful variance:

| Dimension | What It Predicts | Signal Strength |
|---|---|---|
| **Contextual Fit** | Will it compile? Does it use the right macros, types, patterns? | **Strongest** — perfectly predicted compilation success |
| **Useful Code** | Can you merge it? Lines that work in your codebase. | **Strong** — the real gatekeeper for production value |
| **Raw Intelligence** | Are there novel ideas worth stealing? | **Moderate** — H scored 9/10 here but produced 0 working lines. Ideas ≠ code. |
| **Alpha-per-Token** | Output efficiency. Short + brilliant > long + mediocre. | **Moderate** — I had 200 words of prose and 2,152 lines of compilable code. H had 1,047 words of brilliant prose and 1,978 lines that don't compile. |

**Drop these dimensions** (noise or fixable post-hoc):
- **Strategy/Advice** — no correlation with code quality. H scored 9/10 here and was the worst variant.
- **Bloat** — correlates with BSS/memory, but you fix that during porting anyway.
- **Code Quality** — overlaps with Useful Code. If it compiles and passes tests, the quality is adequate.

---

## The Two Templates That Work

After 10 A/B tests, only two prompt structures consistently produced top-tier output. Use one or the other. Never combine them.

### Template A: "Red Team Then Fix" (for hardening existing code)

Use when you have working code and want it made better, more secure, more robust.

```markdown
# [Problem title — one line]

[2 sentences: what exists, that it works, what the gap is]

## PHASE 1: RED TEAM

You are a hostile [agent/attacker/adversary] trying to [specific attack goal].
Find every weakness in this code. Be specific about [domain-specific mechanics].

## PHASE 2: FIX

Fix every weakness you found. Deliver the complete [file/implementation].

## Constraints

[Empirical failure data as a table — what works, what crashes, measured on what platform]
[3-5 hard constraints, not suggestions]
[Compile command]

## Source

```[language]
[THE ACTUAL FILE — appended programmatically, not manually]
```
```

**Why it works:** Phase 1 is cheap (500-1000 words) but transforms Phase 2's quality by +2 points. The model builds a threat model of the code before modifying it.

**Instruction budget:** ~2-4KB. Below the damage threshold.

### Template B: "Genesis" (for novel architecture / greenfield subsystems)

Use when you're adding something new and don't know the right design.

```markdown
# [Problem description — what's missing and why it's hard]

[1 paragraph: the gap, stated concretely with technical specifics]

Your task: solve this problem.

Deliver [the concrete artifact]. I am giving you zero architectural guidance.
No feature list. No state machine specification. No data structure hints.
You decide the best approach.

The only constraints are physical:
- [Constraint 1 — measured, not theoretical]
- [Constraint 2]
- [Compile/build command]

What I care about — in this order:
1. [Most important quality]
2. [Second most important]
3. [Third]
4. [Fourth]

[Optional: 1-2 sentences of genuine motivation — "nobody has built this" or 
"this would matter to X if it works"]

```[language]
[THE ACTUAL FILE]
```
```

**Why it works:** Maximum attention budget on code. The ranked priorities give the model a decision framework without constraining the solution. The "zero architectural guidance" is an explicit instruction to not waste tokens on structure-compliance.

**Instruction budget:** ~1-2.5KB. The shortest instructions of any tested template. The highest compilation rate.

---

## Context Engineering: What to Include

### Always include:
1. **The actual source file(s)** — the #1 lever for quality
2. **Empirical failure data** — "X crashes on Y platform" prevents repeated mistakes. Without this, every variant independently rediscovered the same SIGABRT bug.
3. **The compile command** — tells the model the exact standard, flags, and platform
4. **Hard constraints** — things that CANNOT work, stated as measured facts with evidence

### Never include:
1. **Descriptions of the source code** — the model can read the code. Your description is lossy.
2. **Prescriptive output format** — "Phase 1: Analysis, Phase 2: Design, Phase 3: Code" costs attention and constrains reasoning. Let the model choose its own structure.
3. **References to past outputs** — "In Round N you said X" confuses the model. State decisions as settled facts.
4. **Multiple objectives** — "strategic review AND implementation AND test plan" in one prompt. Each extra objective dilutes all others. Ship separate prompts.

### The context budget:
- **Sweet spot: 20-90KB total** (across all 22 rounds, best outputs)
- **Source code: up to 80KB** (diminishing returns above this, but not harmful)
- **Instructions: 1-4KB** (above 4KB, compilation rate drops; above 6KB, structural amnesia)
- **Above 100KB total:** Model starts dropping boilerplate, forgetting infrastructure, prioritizing novel code over correctness
- **Above 1MB:** Output becomes broad and shallow — the model spreads its reasoning budget too thin

---

## Anti-Patterns (Measured Failures)

**1. "Kitchen Sink" prompts** — H combined every technique that worked individually (red team + debate + checklist). Scored lowest of its round. Techniques compete for attention; they don't stack.

**2. Feature lists as requirements** — H's prompt specified 5 required subsystems with data structures and buffer sizes. The model focused on implementing the novel subsystems and forgot the 100 lines of existing infrastructure. Specify what you CARE ABOUT, not what to BUILD.

**3. Debate framing for code generation** — B scored fine (6.7) but no better than a simple checklist (E: 6.7) or persona (D: 6.6). The debate format is useful for strategy and design, but for code generation it adds ~500 words of prose that don't improve the code.

**4. Challenge framing ("prove them wrong")** — J produced the most structurally innovative output (first HTTP DFA) but also dropped 5 existing functions. Challenge framing encourages the model to prioritize proving the impossible over preserving the existing. Use for brainstorming, not production code.

**5. Overriding with specific data structures** — H specified "bounded buffers — cap at 32KB each." This got faithfully implemented as 32KB * 2 * 1024 FDs = 64MB of BSS. When you specify data structures, the model doesn't question them. When you specify goals ("minimize memory footprint"), the model makes better tradeoffs than you would.

---

## The Meta-Lesson (Updated)

The original article (19 rounds) concluded: "Narrow the problem, open the solution." The A/B tests confirmed this and made it precise:

**For code generation at scale (80KB+ context):**
- Narrowing the problem means: actual source code + measured constraints + failure data
- Opening the solution means: either "attack then fix" (Template A) or "just solve it" (Template B)
- The middle ground — moderate structure, moderate guidance — consistently produces moderate results

**The U-curve:** Extreme specificity (red team: 7.7) and extreme freedom (genesis: 7.0) both outperform moderate guidance (debate/checklist/persona: 6.3-6.7). Pick a pole. Don't compromise.

**The attention budget:** Deep think models allocate reasoning proportional to perceived difficulty. Every word of instructions is a word of attention diverted from reasoning about the code. The optimal prompt is the minimum viable instructions that reshape HOW the model thinks (red team) or what it PRIORITIZES (ranked goals) — never what it OUTPUTS (prescriptive format).

---

## Practical Tooling

For automated prompt assembly — scanning a codebase, gathering source files, constraints, and failure data into a focused context file:

- **Pi's `/deep-think-prompt` command** scans your repo and builds the context markdown
- **Clawsig** (`npx clawsig wrap -- <command>`) captures what agents actually do at the syscall level

The templates above are designed to work with programmatic source injection:

```bash
{
  cat template-a-header.md       # 2-4KB of instructions
  echo '```c'
  cat src/the-actual-file.c      # up to 80KB  
  echo '```'
} > deep-think-prompt.md
```

Don't manually paste code into prompts. You'll truncate something, and that truncation will propagate into the output.

---

## Appendix: Full Results Table

| Variant | Round | Strategy | Instructions | Score | Compiles? | Novel Ideas |
|---|---|---|---|---|---|---|
| F RedTeam | R21 | Attack then fix | ~4KB | **7.7** | After fixes | Anti-stripping, data-flow DAG |
| I Genesis | R22 | Zero guidance | 2.3KB | **7.0** | **First try** | JSON model scanner, plaintext HTTP |
| A/YOLO | R20 | Minimal + source | ~1KB | 6.9 | After flag fix | SSL keylog chaining |
| B Debate | R20 | Expert debate | ~3KB | 6.7 | After fixes | Causal proof structure |
| E Synthesis | R21 | Checklist | ~4KB | 6.7 | After fixes | Incremental SHA-256, timing |
| D Architect | R21 | Strong persona | ~4KB | 6.6 | After fixes | dup2 migration |
| J Crucible | R22 | Adversarial challenge | ~4KB | 6.6 | After fixes | HTTP DFA (first ever) |
| H Omega | R22 | Everything combined | 6.8KB | 6.3 | **Never** | EMA anomaly, receipt formula |
| C YOLO | R20 | Persona + source | ~2KB | 5.7 | After fixes | SSL hooks |
| C Naked | R20 | Persona, no source | ~2KB | 4.9 | After fixes | — |
| G Bare | R20 | Nothing | ~0.5KB | 4.3 | After fixes | — |

---

*Written by Claude Opus 4 after running 10 controlled A/B tests across Gemini 3 Pro Deep Think prompting strategies. All scores derived from compilation testing, runtime verification, and feature extraction on macOS ARM64. The specific findings are empirical, not theoretical — every claim has a measured delta behind it.*
