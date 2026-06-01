# Changelog

## 1.0.0 (2026-06-01)


### Features

* **devirt:** re-implement devirtualization on SVF's Andersen call graph ([091a009](https://github.com/alexthomasv/smack/commit/091a009ea77ea70e8027c686aa8a83bf49ed2c16))
* emit structured source context ([9f11cb8](https://github.com/alexthomasv/smack/commit/9f11cb8ebbf514c002fac7592164be09bce7503e))
* **fuzz+audit:** third fuzzer + Phase 2.2 Boogie canonicalizer ([cc563a6](https://github.com/alexthomasv/smack/commit/cc563a6c69207d35eee3e52e8eea4d48391b8ba4))
* **fuzz:** libFuzzer harness for bitcode parse + OSS-Fuzz scaffold ([2bd914f](https://github.com/alexthomasv/smack/commit/2bd914f408deb99c54aed92c0a302f7d35362e3d))
* **packaging:** expose public API + __version__ on smack package ([0aef5b9](https://github.com/alexthomasv/smack/commit/0aef5b91dfae11b7b28650948ce8b876912b7ced))
* **packaging:** mark smack as PEP 561 inline-typed ([9b70110](https://github.com/alexthomasv/smack/commit/9b70110e156f306dc4858be3ef47b03c143e1fc1))
* **packaging:** smack.cli __init__ re-exports VResult/VProperty ([caf25cf](https://github.com/alexthomasv/smack/commit/caf25cfff3b1c33a2f61bc140de4542d603e27b6))
* **packaging:** smack.diffprod __init__ re-exports orchestrators ([0b74caf](https://github.com/alexthomasv/smack/commit/0b74cafd243d0e5db89f7b0cb080cfb53cc2c21f))
* **packaging:** smack.pipeline __init__ re-exports stage entry points ([c0fc531](https://github.com/alexthomasv/smack/commit/c0fc5318d602f07305385c2877c6b753fe155f09))
* **packaging:** smack.svcomp __init__ re-exports verify_bpl_svcomp ([fed0ffb](https://github.com/alexthomasv/smack/commit/fed0ffb67936cd539c6e120778534115c1f8de59))
* **packaging:** smack.verifier __init__ re-exports Command + builders ([822a18f](https://github.com/alexthomasv/smack/commit/822a18f12db2b510a65afad658e6c6268b509a1c))
* **packaging:** support `python -m smack` invocation ([4e7f1e8](https://github.com/alexthomasv/smack/commit/4e7f1e8d2f6321373219aee5d492cc55347663fb))
* **partition:** replace sea-dsa with SVF union-find memory partitioner ([7aa1b12](https://github.com/alexthomasv/smack/commit/7aa1b124f08db2342b35c6c6971a78cd2746c04a))
* **smack:** emit provenance annotations ([7357982](https://github.com/alexthomasv/smack/commit/7357982ec19a5cda883be7fe3b9ee3231d99305e))
* **svf:** unresolved-pointer audit + keep static SVF cache ([677b7a3](https://github.com/alexthomasv/smack/commit/677b7a31088f01586f1a5237a058ef0e69e0af5e))
* **tools:** devirt + memory partition comparison harnesses ([8ff1dd3](https://github.com/alexthomasv/smack/commit/8ff1dd336a9e349ecb0447a9e0e74fc481c0b3b6))
* **translator:** LLVM 22 NewPM siblings, sea-dsa bridge, gtest suite ([82acaaa](https://github.com/alexthomasv/smack/commit/82acaaaf6e4043de93bd94305601c74c5b148749))
* **typing:** annotate top.py + utils.py + frontend.py; widen mypy ([0b5d491](https://github.com/alexthomasv/smack/commit/0b5d491739453ea2204167cb5bb7cb2e3a852ed1))


### Bug Fixes

* **devirt:** early-devirt mode + SVF over-approx type-filtering ([333bfa1](https://github.com/alexthomasv/smack/commit/333bfa1559151e133d7db0313e425fa5e3b3131d))
* **svcomp:** break circular import via PEP 562 lazy attribute ([34aa22e](https://github.com/alexthomasv/smack/commit/34aa22eeb40ea1d2f75a57baaef58352629a773d))
* **svf-regions:** sound region partition (vtable/GHASH severance) + always-on catch-all ([0d81f0e](https://github.com/alexthomasv/smack/commit/0d81f0e64958930b2cdf828e63ea36bd72515247))
* **svf:** build SVF on the final module (drop early CodifyStaticInits dep) ([325db2b](https://github.com/alexthomasv/smack/commit/325db2bb4b4b495904bfc13e070d0f42daef73ca))
* **svf:** collapse field-objects to their base in the region union-find ([482a30e](https://github.com/alexthomasv/smack/commit/482a30e0c3e5dcc14a52dc6b3874cf9e9ba7f911))
* **versions:** pin Python version fallback to LLVM-21 to match bin/versions ([da58918](https://github.com/alexthomasv/smack/commit/da58918add0895961a7945fa534ce6c90198eae7))

## Changelog

All notable changes are recorded here. This file is **maintained by
release-please** (`.github/workflows/release-please.yml`); manual edits
on `main` will be overwritten when the bot opens its next release PR.

The format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
with sections gated by the conventional-commit type configured in
`.release-please-config.json`.

## Unreleased

- Initial seed of this file. release-please bootstraps the first
  versioned section on the next `feat:` / `fix:` commit landing on
  `main`.
