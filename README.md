# LicenseAudit

A monorepo **license and vulnerability auditor** that walks a project's
resolved dependency lockfile and emits a compliance report plus a
CycloneDX SBOM of the audited project. Its defining property is checked
at compile time: **the code that walks the repository it audits gets it
through a read-only capability.** That is not a code-review promise or a
runtime sandbox. The [Capa](https://github.com/nelsonduarte) compiler
checks it: the audit functions receive the tree as `ReadOnlyFs`, a
capability that declares a single `read` method, and the compiler refuses
a call to `write` or `remove` on it.

## The problem

Every organisation that ships software built on open source owns two
recurring obligations, usually held by two different teams:

- **License compliance (the OSPO / legal axis).** A strong-copyleft
  license (GPL-3.0) or a network-copyleft one (AGPL-3.0) linked into a
  proprietary product is a distribution risk that can force source
  disclosure. A license nobody has classified is an un-triaged risk. Under
  the EU Cyber Resilience Act and standard OpenChain practice, an
  organisation must be able to show, per release, that every dependency's
  license was assessed against a policy.

- **Known vulnerabilities (the security axis).** A dependency pinned to a
  version with a published advisory (a Log4Shell-class RCE, a prototype
  pollution, a deserialisation bug) is a live exposure. The lockfile has
  already resolved exactly which versions ship; the question is whether any
  of them is on a known-bad list.

Today both are answered by tools you have to TRUST not to do more than they
claim. A license scanner or an SBOM generator runs with ambient authority:
it can read your source, but nothing stops it writing to your tree, reading
files outside the repo, or reaching the network. "It only audits" is a
statement about intent, not a checked property.

## What LicenseAudit does

Given a normalised dependency lockfile, a license policy and a local OSV
advisory feed, it:

1. **Parses** the lockfile into typed `Dependency` records (name, pinned
   version, declared SPDX license, ecosystem), using the capability-free `capa_csv`
   RFC 4180 reader so a quoted license expression never corrupts a row.
2. **Evaluates license conformance** (the primary axis) against a policy
   that marks each SPDX id `allow` / `review` / `deny`. A `deny` license
   (strong or network copyleft) is a violation; a license absent from the
   policy is `unknown`, treated as a violation to **fail closed**; a
   `review` license (weak copyleft) is a gate surfaced for a recorded human
   decision.
3. **Cross-references vulnerabilities** (the secondary axis): each
   dependency at its pinned version is joined against a local OSV feed; a
   name+version match is a finding, weighted by severity.
4. **Summarises risk** into the counts a decision-maker acts on and a
   fail-closed verdict (PASS only when there are zero violations and zero
   vulnerabilities).
5. **Writes** a human compliance report and a **CycloneDX 1.5 SBOM of the
   audited project** to `out/`, through a filesystem view scoped to `out/`
   that is disjoint from the audited tree.

It ships two sample repositories so both outcomes are visible: a
`violating_repo` (license violations + vulnerabilities, verdict FAIL) and a
`clean_repo` (verdict PASS).

## What makes "an auditor that only reads" checkable

### 1. The read-only capability: a write call does not compile

The repository under audit is reached through `ReadOnlyFs`, a user-defined
capability declared in `readfs.capa`:

```capa
pub capability ReadOnlyFs
    fun read(self, path: String) -> Result<String, IoError>
```

That is the whole declared surface: one `read` method, nothing that
mutates. A call to `write` or `remove` on a `ReadOnlyFs` is not a runtime
failure: it does not type-check. `leaky_licenseaudit.capa` is the
counter-example that makes the compiler say so:

```
$ python -m capa --check leaky_licenseaudit.capa
leaky_licenseaudit.capa:28:11: error: capability 'ReadOnlyFs' has no method 'write'
leaky_licenseaudit.capa:36:11: error: capability 'ReadOnlyFs' has no method 'write'
leaky_licenseaudit.capa:44:11: error: capability 'ReadOnlyFs' has no method 'remove'
leaky_licenseaudit.capa: 3 errors            # exit code 1
```

The bridge from the real filesystem to this view (`make_read_view`) narrows
a built-in `Fs` to the `data/` prefix and keeps it in a field of the
implementor; the analyzer refuses reaching that field through a value
typed `ReadOnlyFs`. Two independent narrowings therefore apply to the
audited tree: **path attenuation** (the view sees `data/`) and **method
attenuation** (the view declares only `read`). The write path for the
report and SBOM is a *separate* `Fs` scoped to `out/`.

The capability manifest records the read-only surface:

```
$ python -m capa --manifest licenseaudit.capa | jq '.user_defined_capabilities'
[
  { "name": "ReadOnlyFs", "methods": ["read"], "implementors": ["FsReadView"] }
]
```

One capability, one method.

### 2. Capability discipline: the auditor holds no `Net`

`main` acquires exactly `Fs` and `Stdio`, and nothing else. It never
acquires `Net`, `Env`, `Proc`, `Db`, `Clock`, `Random` or `Unsafe`. The
compiler checks it and the manifest records it:

```
$ python -m capa --manifest licenseaudit.capa \
    | jq '.functions[] | select(.source_name=="main")
          | {declared: .declared_capabilities, excluded: .provably_excluded_capabilities}'
{
  "declared": ["Stdio", "Fs"],
  "excluded": ["Clock", "Db", "Env", "Net", "Proc", "Random", "ReadOnlyFs", "Unsafe"]
}
```

"This auditor cannot phone home with what it read" is a checked fact: with
no `Net` capability anywhere in the program, no code path reaches the
network.

### 3. The artefacts

`./generate.sh` produces, with timestamps pinned by `SOURCE_DATE_EPOCH`,
two distinct families. Do not confuse them:

| Artefact | Emitted by | What it is |
| --- | --- | --- |
| `out/violating_report.txt`, `out/clean_report.txt` | running LicenseAudit | the human compliance reports |
| `out/violating_sbom.cyclonedx.json`, `out/clean_sbom.cyclonedx.json` | running LicenseAudit | the SBOM of the **audited project** (the program's output) |
| `sbom/manifest.json` | `capa --manifest` | LicenseAudit's own capability surface + the `ReadOnlyFs` declaration |
| `sbom/sbom.cyclonedx.json` | `capa --cyclonedx` | CycloneDX 1.5 SBOM of **LicenseAudit itself** |
| `sbom/sbom.spdx.json` | `capa --spdx` | SPDX 2.3 companion |
| `sbom/provenance.slsa.json` | `capa --provenance` | SLSA build provenance |

The `out/*sbom*.json` are what LicenseAudit *produces* about the code it
audits; the `sbom/*.json` are what the compiler *records* about LicenseAudit.

## Distinction from SupplyGate

A companion demo, SupplyGate, INGESTS a finished SBOM and gates on
vulnerabilities. LicenseAudit is the step before: it INGESTS raw dependency
manifests / lockfiles, makes **license conformance** the primary axis, and
PRODUCES an SBOM as output. The two compose (LicenseAudit's `out/` SBOM is a
valid SupplyGate input) and do not overlap.

## The two sample outcomes

```
$ python -m capa --run licenseaudit.capa
== capa_licenseaudit: license + vulnerability auditor ==
  violating_repo: FAIL (3 license violations, 6 vulns)
  clean_repo: PASS (0 license violations, 0 vulns)
```

The `violating_repo` report names the GPL-3.0 and AGPL-3.0 copyleft
violations, the unclassified `ImageMagick` license, the MPL-2.0 dependency
held for review, six vulnerable dependencies (two critical, including a
Log4Shell-class RCE), and a remediation checklist. The `clean_repo` report
is a clean PASS. Both are in `out/`.

## Layout

| Path | Role |
| --- | --- |
| `domain.capa` | the typed model: dependency, policy, advisory, findings, errors |
| `readfs.capa` | the `ReadOnlyFs` capability and its bridge from `Fs` (the read-only view) |
| `manifest.capa` | parse the lockfile CSV into `Dependency`s (no capability) |
| `policy.capa` | parse the policy and evaluate license conformance (no capability) |
| `osv.capa` | parse the OSV feed and cross-reference dependencies (no capability) |
| `risk.capa` | fold findings into the risk summary + verdict (no capability) |
| `report.capa` | build the human compliance report string (no capability) |
| `sbom.capa` | build the CycloneDX SBOM of the audited project (no capability) |
| `licenseaudit.capa` | the orchestrator: read (ReadOnlyFs) -> audit -> write (Fs) |
| `leaky_licenseaudit.capa` | counter-example: the mutation the compiler rejects |
| `data/` | two sample repos, the license policy, the OSV feed |
| `out/` | sample reports + audited-project SBOMs |
| `sbom/` | sample manifest + SBOMs + provenance for LicenseAudit itself |
| `capa_csv` (git dep) | capability-free; fetched + GPG/SLSA-verified by `capa install` into `vendor/` (RFC 4180 CSV) |

The input formats are deliberately simple, ecosystem-neutral CSV: a
normalised lockfile (`name,version,license,ecosystem`), a policy
(`spdx,disposition,category,note`) and a flattened OSV export
(`id,package,version,severity,summary`). A real monorepo auditor normalises
`package-lock.json`, `Cargo.lock` and `requirements.txt` into the lockfile
shape, and resolves OSV affected-ranges into the flattened feed, upstream of
the compliance pass shown here.

## Run it

All commands use the local Capa compiler; substitute `python -m capa` for
`capa` if the installed `capa` is not the build you intend.

```sh
# One-time: fetch + verify the git dependency (needs capa >= 1.15.1).
# `capa install` clones capa_csv at its signed tag, verifies the tag's
# GPG signature against the verify_key in capa.toml and its SLSA
# provenance, writes capa.lock, and vendors the source under vendor/.
# Import the publisher key first (see capa_csv's SECURITY.md). capa_csv
# holds zero capabilities, so this adds a verified supply
# chain without widening the {Fs, Stdio} surface.
python -m capa install

# Type-check + capability check (clean)
python -m capa --check licenseaudit.capa

# Run the auditor. Writes out/*_report.txt and out/*_sbom.cyclonedx.json.
python -m capa --run licenseaudit.capa

# Watch the capability checker reject a mutation of the audited tree
python -m capa --check leaky_licenseaudit.capa    # 3 errors, exit code 1

# Regenerate the reports, audited-project SBOMs and the compiler SBOM family
./generate.sh
```

### Other backends

LicenseAudit runs unchanged on the Wasm backend and as a stock Wasm
component. The reports and audited-project SBOMs are **byte-identical**
between the Python and Wasm backends (modulo LF/CRLF).

```sh
python -m capa --wasm --run licenseaudit.capa               # identical output
python -m capa --wasm --component --run licenseaudit.capa   # as a Wasm component
```

**WASI Preview 2 note.** The stock `--wasi` backend is **not** supported for
this program in the current compiler (Capa 1.16.0), by design of the
read-only view, not by accident. The `--wasi` static-preopen ceiling resolves a
filesystem path only when it reaches the built-in `Fs` sink as a
compile-time literal. Here the path is routed through the `ReadOnlyFs`
capability method (`ro.read("data/...")` -> `self.fs.read(path)`), so the
literal is not visible at the `Fs` sink and the ceiling treats it as
dynamic. The current WASI increment (Fs layer b1) then supports neither
mixing literal and dynamic paths in one program nor more than one
`--preopen` directory, and LicenseAudit needs a read directory (`data/`) and
a disjoint write directory (`out/`). Making `--wasi` run would mean giving up
either the read-only capability wrapper (the point of the design) or the
minimal `{Fs, Stdio}` surface (dynamic paths pull in `Env`). Rather than
weaken the design to satisfy a backend the compiler cannot yet serve for
this idiom, the program keeps the strong shape and runs on the other three
backends. This is a known compiler limitation, reported upstream.

## Dependencies

One dependency, **capability-free**, resolved as a **verified git
dependency** in `capa.toml`:

- `capa_csv` - RFC 4180 CSV parsing (the lockfile / policy / OSV reader).

It is pinned to a **GPG-signed release tag** with the publisher's
`verify_key`. `capa install` (needs `capa >= 1.15.1`) fetches it at that
tag, verifies the tag's **GPG signature** against `verify_key` and its
**SLSA build provenance** (via `gh attestation verify` against the public
Sigstore log), records the resolved commit SHA in `capa.lock`, and vendors
the source under `vendor/` (git-ignored, not committed). A force-pushed
tag or a substituted commit is rejected before the code is ever compiled.

```toml
[dependencies.capa_csv]
git = "https://github.com/nelsonduarte/capa_csv"
tag = "v0.1.1"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

This is the verifiable supply chain Capa is about, made concrete: the
dependency is **cryptographically verified at install time**, not trusted
by convention, and its pinned, signed provenance is recorded in
`capa.lock`. It holds no authority, so the LicenseAudit capability surface
stays `{Fs, Stdio}`, and the SBOM shows it does not widen it.

## Licence

MIT. See `LICENSE`. The sample lockfiles, policy and advisory feed are
fictitious; the advisory ids and package names are illustrative and do not
reference real published advisories except where a class of bug (Log4Shell)
is named for recognisability.
