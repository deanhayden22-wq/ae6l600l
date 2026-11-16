# ROM review & patch pipeline: design

Written 2026-11-15. **Status: proposal. Nothing here is built yet.**
Goal: (1) confirm the current mapping with independent re-derivation from bytes,
and (2) lay the groundwork for new code patches. **The constraint over both is
that we cannot bench-test, so a bad flash is found on the car.** Every stage below
exists to move a failure from the car to a script or a reviewer.

Template: `~/src/sdlc-automation/pipeline` (the `dev` runner). We take its *shape*,
not its code. See "Why not run `dev` directly".

---

## Baseline on 2026-11-15 (Linux, this checkout, `6f30c57`)

| gate | result |
|---|---|
| `verify_disasm_v2.py --quiet` | baseline clean: 29 accepted (28 symbolic, 1 accepted), exit 0 |
| `coverage_map.py --check` | registry is current |
| `doc_coherence.py` | no stale file |

The repo's gates all assume Windows (`check.ps1`). They run unchanged under
`python3` on Linux; only the wrapper is missing.

---

## What we take from the sdlc pipeline, and what we don't

**Taken.**
- One **herdr workspace per work item**, four panes: runner, Claude (planner /
  tracer), a **non-Claude reviewer** (Codex by default, Gemini as fallback; both
  installed), and a builder in its own worktree for patch items.
- **Claude is never reviewed by Claude.** Every claim the project relies on was
  written by Claude; the blind audit (`docs/exploration/claim_audit/`) found 52
  contradicted statements using Claude to check Claude. A different vendor is the
  cheapest independence we can buy.
- **State lives in files** (`.pipeline/items/<slug>.*`, git-excluded), never in
  herdr or the runner. A crashed runner resumes from what is on disk.
- **The reviewer reads and judges; it never edits the subject.** It writes only its
  own section or report.
- **Human gates** with the owner, and the rule that the runner never waits silently.
- Objections are appended as `### Pass N`, never rewritten.

**Not taken.**
- `dev.mjs` itself. It is 3,983 lines bound to the cref org: GitHub PR checks,
  Playwright, terraform, `C:\repos` roots, route.mjs. Its README also says the
  pipeline is never used to change itself, and `sdlc-automation` should not grow a
  ROM mode. A small runner in this repo (target: a few hundred lines) driving the
  `herdr` CLI directly is less risk than either.
- PR-as-gate. Here the gate is the **flash-safety report**, not CI.

## Why not run `dev` directly

`dev` items end in "merge the PR". Ours end in "write a corrections item" (verify)
or "a bin that is safe to flash" (patch). Neither has CI to fall back on, and the
plan template (`Contracts affected`, `Playwright spec`) would be noise every time.

---

## Roles

| pane | agent | may | may not |
|---|---|---|---|
| runner | `scripts/pipeline/run.py` | sequence stages, run mechanical gates, prompt the owner | edit any analysis |
| tracer | Claude, main checkout | read, decode, write the item file and draft corrections | flash anything, edit definition XMLs |
| reviewer | Codex (or Gemini) | read files; run the **read-only decode whitelist** (below) | edit anything but its own section/report; git; network |
| builder | Claude, worktree `../ae6l600l-<slug>` | assemble a patch into a *new* bin under `out/` | touch `rom/`, touch `definitions/`, flash |

**Read-only decode whitelist for the reviewer** (new; the sdlc reviewer runs no
scripts at all). Codex has no file tools, and "verify against bytes" is impossible
without decoding. Allowed: `cat`, `sed -n`, `rg`, `ls`, `xxd`, `git log/show/diff`,
`python3 scripts/sh2e_disasm.py`, `python3 -c` importing only `defs` / `desc_types`
read functions. See open question 2.

**No agent flashes. Ever.** The pipeline's last output is a bin plus a signed-off
safety report; the owner flashes it with ECUFlash by hand.

---

## Track A: verify (confirm the current mapping)

Unit of work: **one claim** = one `corrections.md` item, one doc section, or one
label/table identity, as `claim_audit.py` already defines it.

```
A0 select   runner     pick the next claim by priority (below)
A1 blind    reviewer   given ONLY the addresses + a byte-built evidence pack
                       (claim_audit's pack, reused); derives the mechanism
A1' blind   tracer     same pack, separately, without the reviewer's answer
A2 compare  runner     statement-by-statement: agree / contradict / not addressed
A3 settle   tracer     hand-decode every contradiction from bytes (rule 1, 8)
A4 critique reviewer   checks the settlement's operands and cites (Pass N)
G  gate     owner      accept -> corrections item + relabel + coverage_map rerun
```

The two blind readers are from different vendors and never see each other or the
claim. **Agreement of two blind readers is the evidence class this project does
not have today**; it is stronger than `[TRACED]`, which means only that an address
was decoded. Proposed new label tag: `[CONFIRMED-2V]`.

Exit criterion for an item: `verify_disasm_v2`, `coverage_map --check` and
`doc_coherence` all clean after the change, and the label provenance re-stamped.

### Priority order

1. **Dependency closure of every live and planned patch.** For the two patches on
   the car (`0x09A3C2` SSM read, `0x0F1000` launch) and any patch in Track B: every
   RAM variable they read or write, every function they hook or return into, every
   calibration constant they load. A patch built on a wrong identity is the most
   likely way to hurt the engine.
2. RAM identities with no `VERIFIED-BOTH` that a tuning decision has used.
3. The open contradictions from `claim_audit/report.md` not yet closed by a
   corrections item (item 100 closed one).
4. Then breadth: open-holes item 7 (947 unnamed tables), slice by slice.

---

## Track B: patch (groundwork, then patches)

```
B1 plan      tracer    plan file: goal, hook site, inputs/outputs (each RAM address
                       with its flag), ROM + RAM allocation, disable switch,
                       shadow-mode design, rollback bin
B1b critic   reviewer  objections, Pass N: wrong identities, clobbered registers,
                       hook-site side effects, unhandled callers
G1  gate     owner     approve the plan
B2  build    builder   assemble into out/<slug>/<base>-<slug>.bin; never edits rom/
B3  gates    runner    the flash-safety gate (all mechanical, below)
B4  verdict  reviewer  re-decodes the patched bin independently, judges B3 evidence
G2  gate     owner     shadow bin -> flash -> log -> review
G3  gate     owner     live bin -> flash -> log -> review
```

### Shadow first, then live: the bench-test substitute

A new patch ships **twice**:

1. **Shadow bin.** The patch runs and writes its result to a free RAM address that
   the SSM read patch can log, but the hook site's behaviour is unchanged (the
   result is computed and discarded). Drive, log, compare the shadow value against
   what the patch *would* have done. A wrong identity, a wrong scale or a crash
   loop shows up in a log, not in the engine.
2. **Live bin**, only after the shadow log is reviewed with `reviewing-a-new-log`.
   It carries a **calibration-byte disable switch**, so the next rollback is a table
   edit, not a code change.

### The flash-safety gate (B3): every check is a script, and every one must pass

| # | check | why |
|---|---|---|
| 1 | **Byte-diff whitelist**: every byte that differs from the base rev lies inside a range the plan declared (patch code, its literal redirects, its cal bytes, the checksum words) | catches a stray write, a wrong offset, an off-by-one in the assembler |
| 2 | **Checksum** valid, computed by a validator proven on all 19 flashed-and-driven bins in `rom/` as positive controls | today the repo has no checksum tool: `patch_rom.py:929` says "fix in ECUFlash" |
| 3 | **Never-touch regions** untouched: vectors, boot / reflash path, ROM ID, the checksum table itself except its sum words | the realistic brick is losing the ability to reflash, not a bad table |
| 4 | **SH-2E legality**: the whole patch decodes with `sh2e_disasm.py`; zero SH-2A-only ops (`CLAUDE.md` list); no branch or PC-relative op in a delay slot; literal pools aligned; every branch target inside the patch or a decoded function entry | Ghidra will happily decode what this chip cannot run |
| 5 | **Calling convention**: r8-r15, PR, fr12-fr15 saved/restored on every path; stack balanced on every path | a clobbered callee-saved register corrupts the host task silently |
| 6 | **Allocation registry**: the patch's ROM range and RAM range do not overlap each other, either live patch, or anything with a writer (`find_writers.py`) or reader | there is no registry today; the 0xFF hole already holds `0x0F1000` |
| 7 | **Every input/output RAM address is `VERIFIED-BOTH`** or `[CONFIRMED-2V]` | the failure class in "Found during the survey" below |
| 8 | **Emulated run**: the patched function executed in Ghidra's p-code emulator (SH-2A language, so check 4 still has to gate it) over a grid of input values, compared with the plan's expected outputs | the closest thing to a bench we can build |
| 9 | **Shadow/live parity**: the live bin differs from the shadow bin only at the declared switch-over bytes | proves what was logged is what goes live |

---

## Phase 0: build before any new patch (in order)

1. **DONE 2026-11-15** `scripts/check.sh`: the Linux twin of `check.ps1`, plus the
   checksum gate.
2. **DONE 2026-11-15** `scripts/rom_checksum.py`. The rule comes from the ECU's own
   check (`0x01002A`; corrections item 101), not from a tuning tool. It passes all
   19 bins, and `--selftest` flips a byte in every used range of every bin and
   requires a failure. `--fix OUT` never writes in place or into `rom/`.
3. **DONE 2026-11-15** `docs/allocation.json` + `scripts/rom_allocation.py`.
   `--audit` accounts for every off-table byte in all 18 flashed revs. That
   surfaced three calibration edits nobody had listed, one of them unexplained
   (open-holes item 9). `--free`: 195 KB of 0xFF in 7 runs, which is "unclaimed",
   not "proven unused". No RAM is proven free yet.
4. **DONE 2026-11-15** `scripts/patch_lint.py` (gates 1-5). `--live` passes both
   patches on the car, using specs in `docs/patch-specs/`. Seven mutations
   (branch in a delay slot, SH-2A word, undeclared clobber, missing push, wrong
   exit, stray byte, bad checksum) are each caught by the gate meant to catch
   them. Building it found the SSM handler's real entry (`0x09A3AC`) and two
   PC-relative loads in the launch hook's delay slots (dead, accepted with reasons).
5. **DONE 2026-11-15** Emulation (gate 8). Ghidra and Java are not on the Linux
   box, so `scripts/sh2e_emu.py` is a dedicated SH-2E emulator. Its decoder is
   separate from `sh2e_disasm.py`, and every executed instruction is cross-checked
   against it. Four oracles that don't depend on it pass:
   - the ECU's checksum routine vs `rom_checksum.py`, real and mutated bins
   - `float_clamp_range`, 550 cases
   - the ROM divide, 1,013 cases; this also corrected its label (item 102)
   - `table_lookup` vs `desc_types` interpolation, 3,261 points across 120
     descriptors of three cell types

   `scripts/patch_emulate.py` runs the launch patch over a 432-point grid against
   an oracle written from `rev-limit-patch.md`; all points pass. Five code
   mutants are each caught. One of them is only caught at the exact stored
   threshold speed, which is now a grid point.
6. **DONE 2026-11-15 (Track A)** `pipeline/run.py` + `pipeline/agent-files/`
   (`RULES`, `BLIND`, `settle`, `critique`, `apply`).
   - `new` builds the records (`.pipeline/items/<slug>/`, git-excluded) and two
     blind workspaces **outside the repo**. Outside, because Claude Code loads
     every parent `CLAUDE.md`, and this repo's is full of the claims under test.
   - Each blind workspace holds only the ROM, the decoder, the definitions and the
     pack. The pack now carries raw bytes, stock vs current.
   - `new` then opens a herdr workspace with four panes and starts `stages` in it.
   - Proven so far: a dry run on open-holes item 9, and a full simulated run with
     fake agents (blind, settle, objection, fix round, clean pass, accept, apply,
     commit question).
   - **Not yet run against real agents in herdr.** Start one from a herdr pane:

     ```
     python3 pipeline/run.py new afc-clamp-zeroed --addrs 0x0357C8,0x0357CC,0xFFFF7904 \
         --claim-file docs/open-holes.md --section "## 9."
     ```
   - Track B's runner (plan, critique, build, gates, verdict) is still to do. Its
     gates exist: `patch_lint.py`, `rom_allocation.py --check-claims`,
     `patch_emulate.py`.
7. Recovery-path check, owner side: confirm how this ECU is recovered after an
   interrupted or rejected flash with the tools you own, *before* the first
   code-patch flash. This is the one thing no script here can establish.

---

## MerpMod is out of scope and untrusted (owner, 2026-11-15)

`merp mod/` and `scripts/patch_rom.py` are excluded from both tracks: not a
reference, not a patch candidate, not an input to the allocation registry. If
MerpMod comes back, it enters Track B as a new item and passes every gate from B1.

For that day, the reason it is untrusted: `patch_rom.py` (last changed
2026-04-04, before corrections 9-26) assembles `P_IAT = FFFF63F8` (now **engine
load**) and `P_ATMO_PRESS = FFFF67EC` (now a **uint16 DTC counter**) into
`ComputeMassAirFlow` (`patch_rom.py:36-38`, emitted at `:611`, `:623`), and its
`P_MAP = FFFF6898` is **atmospheric pressure** (corrections item 11), not manifold
pressure (`FFFF620C`, item 9). It also places its RAM at `0xFFFFC000`, past the end
of on-chip RAM (`0xFFFFBFFF`, `CLAUDE.md` rule 4).

---

## Open questions for the owner

1. **Where the runner lives.** (a) In this repo, `scripts/pipeline/`, driving
   `herdr` directly *(recommended: the subject and its gates are here, and `dev`
   stays cref-only)*; (b) a ROM mode in `sdlc-automation`.
2. **Reviewer decode rights.** (a) The read-only whitelist above *(recommended:
   without it the reviewer cannot check bytes, and checking bytes is the job)*;
   (b) no execution, as in sdlc, reviewer works from decoded listings the runner
   prepares.
3. **First patch to aim Track B at.** Not stated anywhere in the repo, and MerpMod
   is out (above). Extending the launch patch is the only other candidate seen.
   Which one, or none until Phase 0 is done?
4. **Shadow-first for every code patch?** *(Recommended: yes, no exceptions; it is
   the only stage that tests on the real chip without risking it.)*
