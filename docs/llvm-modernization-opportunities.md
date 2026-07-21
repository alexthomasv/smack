# LLVM Modernization Opportunities

This document tracks the next SMACK modernization slice after the LLVM 22 port
and the opt-in NewPM pipeline. The goal is to find useful LLVM features and
efficiency work with evidence first, then make isolated implementation changes.

The matching probe is `tools/llvm_feature_audit.py`. It runs a small fixture set
through legacy `llvm2bpl`, optionally through the NewPM build, captures
`--smack-pipeline-report` JSON, records `opt-22 --print-passes`, and writes
`audit.json` plus `audit.md`. Timings are report-only diagnostics, not budgets.

## Current Baseline

- SMACK is pinned to LLVM 22 in `bin/versions`; the local toolchain may report a
  nearby LLVM 22 patch release through `llvm-config-22 --version`.
- The legacy pipeline remains the production `llvm2bpl` path.
- `-DSMACK_NEW_PM=ON` enables the full NewPM path for equivalence and audit work.
- Memory uses a fail-closed SVF Andersen component partition. A module stays
  split only when every translated address has a concrete component and every
  pointer source is supported by both SVF and the modular Boogie encoding;
  otherwise it uses one universal mutable map.
- CI already runs ruff, C++ gtests, Python tests, and the regression matrix; the
  audit adds artifacts only and must not fail because one runner is slower.

## Ranked Opportunities

| ID | Area | Why It Matters | First Action |
| --- | --- | --- | --- |
| `bpl-output-streaming` | Efficiency | Early reports show Boogie emission dominates translator time on small and medium fixtures, and both BPL printers stage output in `std::ostringstream` before writing it. | Prototype direct streaming from `Program::print` to the destination stream, then require byte-for-byte BPL equality and timing comparison. |
| `newpm-analysis-preservation` | NewPM | Many SMACK NewPM siblings conservatively return `PreservedAnalyses::none()` after mutation. More precise preservation may reduce repeated analysis work once NewPM is the default candidate. | Audit each pass for DominatorTree, LoopInfo, and module-analysis preservation before changing pass order. |
| `llvm-standard-instrumentations` | Observability | LLVM already provides NewPM instrumentation helpers; SMACK now has custom report callbacks and should compare them against upstream facilities. | Prototype `StandardInstrumentations` / time profiling behind the existing report flag and keep the current JSON schema stable unless the replacement is clearly better. |
| `llvm22-ptrtoaddr` | LLVM IR | LLVM 22 introduced `ptrtoaddr`, which separates address extraction from pointer provenance capture. SMACK still has explicit ptr-to-int cleanup. | Add focused IR fixtures for `ptrtoaddr`; do not alter pointer lowering until those fixtures preserve expected BPL behavior. |
| `llvm-attributor-candidates` | LLVM features | LLVM 22 exposes inference passes such as Attributor that may simplify IR before translation, but verifier semantics can be fragile. | Run candidate passes only in exploratory builds and diff emitted BPL before considering production use. |
| `memory-separation-certificates` | Memory model | More maps help Boogie only when every pair is proved address-disjoint for every defined execution. | Preserve the current SVF component certificate and its universal fallback; add precision only with a regression that refutes the one-map reference and a proof that the new source cannot cross components. |

## Report-Only Workflow

```sh
python3 tools/llvm_feature_audit.py \
  --legacy-llvm2bpl build-llvm22c/llvm2bpl \
  --newpm-llvm2bpl build-newpm/llvm2bpl \
  --out-dir build/llvm-audit
```

Expected outputs:

- `audit.json`: machine-readable LLVM/tool paths, fixture reports, pass inventory,
  and opportunity records.
- `audit.md`: compact human summary for CI artifacts.
- `*.legacy.json` and `*.newpm.json`: raw per-fixture pipeline reports.
- `*.legacy.bpl` and `*.newpm.bpl`: generated BPL for follow-up diffing.

## Memory Model Invariant

- Production translation uses SVF Andersen only. For every pointer `p`, its
  points-to objects are unioned into one equivalence component; SVF field
  objects are also unioned with their base allocation. Two different Boogie
  maps therefore require disjoint concrete SVF object sets.
- The split is fail-closed. Unresolved or black-hole targets, `inttoptr`,
  pointer formals/returns/loads/globals, allocation wrappers, unsupported calls
  or intrinsics, unstable/linker-defined globals, erased address spaces,
  variadic pointer extraction, pointer freeze/atomics, an IR-epoch mismatch,
  and a second module in the same process all select one universal map.
- All maps are mutable. LLVM `noalias`, alias scopes, TBAA, constant-memory
  status, field windows, an external oracle, and entry-reachability do not
  create components. In particular, argument `noalias` permits read/read
  overlap and cannot prove the address-disjointness required by separate maps.
- Every devirtualized indirect call retains a residual unknown-target branch.
  That branch has a modifies-all Boogie summary, and any IR rewrite after SVF
  invalidates the exact snapshot and forces universal memory.
- `--no-memory-splitting` is the explicit opt-out and always selects one map.
  `--smack-memory-partition-report` records the component count, fallback
  evidence, unsupported origins, unresolved targets, and snapshot status.
- LLVM `MemorySSA` is useful for future sparse memory-use evidence, but it is
  intraprocedural and should be treated as a complement to pointer partitioning,
  not a drop-in replacement for SeaDsa-derived regions.
- Future precision work should first strengthen Boogie procedure/allocation
  contracts so pointer formals, returns, loads, and allocation results remain
  constrained at modular call boundaries. Those contracts can safely remove
  individual fallback gates once their generated Boogie obligations pass the
  one-map differential regressions.

## References

- [LLVM 22 release notes](https://releases.llvm.org/22.1.0/docs/ReleaseNotes.html)
- [LLVM New Pass Manager](https://releases.llvm.org/22.1.0/docs/NewPassManager.html)
- [`opt` command guide](https://releases.llvm.org/22.1.0/docs/CommandGuide/opt.html)
- [LLVM `StandardInstrumentations`](https://llvm.org/doxygen/classllvm_1_1StandardInstrumentations.html)
- [LLVM optimization remarks](https://llvm.org/docs/Remarks.html)
- [LLVM MemorySSA](https://www.llvm.org/docs/MemorySSA.html)
- [LLVM Alias Analysis Infrastructure](https://llvm.org/docs/AliasAnalysis.html)
- [LLVM 21.1 `noalias` semantics](https://releases.llvm.org/21.1.0/docs/LangRef.html#noalias)
- [SMACK: Decoupling Source Language Details from Verifier Implementations](https://soarlab.org/papers/2014_cav_re.pdf)
- [Data Structure Analysis: An Efficient Context-Sensitive Heap Analysis](https://llvm.org/pubs/2003-04-29-DataStructureAnalysisTR.html)
- [Unification-based Pointer Analysis without Oversharing](https://arxiv.org/abs/1906.01706)
- [SVF: Static Value-Flow Analysis Framework](https://svf-tools.github.io/SVF/)
- [cclyzer++](https://galoisinc.github.io/cclyzerpp/)
- [PhASAR](https://github.com/secure-software-engineering/phasar)
- [Phoenix: A Modular and Versatile Framework for C/C++ Pointer Analysis](https://arxiv.org/abs/2602.01720)
- [A Segmented Memory Model for Symbolic Execution](https://srg.doc.ic.ac.uk/files/papers/segmem-esecfse-19.pdf)
- [Byte-Precise Verification of Low-Level List Manipulation](https://www.fit.vut.cz/person/vojnar/public/Publications/dpv-sas-13.pdf)
