#!/bin/sh
# Regenerate the LicenseAudit machine-verifiable artefacts:
#
#   out/violating_report.txt              compliance report, violating repo
#   out/clean_report.txt                  compliance report, clean repo
#   out/violating_sbom.cyclonedx.json     CycloneDX SBOM of the violating repo
#   out/clean_sbom.cyclonedx.json         CycloneDX SBOM of the clean repo
#   sbom/manifest.json                    LicenseAudit's own capability manifest
#   sbom/sbom.cyclonedx.json              CycloneDX 1.5 SBOM of LicenseAudit
#   sbom/sbom.spdx.json                   SPDX 2.3 SBOM companion
#   sbom/provenance.slsa.json             SLSA build provenance
#
# Two families of artefact, do not confuse them:
#
#   * out/*sbom*.json  is the SBOM of the AUDITED PROJECT, produced by
#     RUNNING LicenseAudit over a lockfile. This is the program's output.
#   * sbom/*.json      is the capability SBOM of LICENSEAUDIT ITSELF,
#     EMITTED BY THE COMPILER from the same source. It proves the auditor's
#     surface is exactly {Fs, Stdio} and that the audited tree is reached
#     through a read-only capability.
#
# Determinism comes from SOURCE_DATE_EPOCH (reproducible-builds.org): the
# compiler stamps the SBOM build time from this fixed instant, so the
# compiler-emitted artefacts are byte-reproducible. Bump it by writing a
# new UTC epoch to sbom/SOURCE_DATE_EPOCH and rerunning this script.
#
# Run every Capa invocation through the LOCAL compiler:
#     python -m capa ...   (from a checkout of the Capa compiler)
# The examples below assume `capa` resolves to that build.
set -e

SOURCE_DATE_EPOCH="$(tr -d '\r' < sbom/SOURCE_DATE_EPOCH)"
export SOURCE_DATE_EPOCH

mkdir -p out sbom

# Run the auditor (Python backend) to produce the reports + audited-project
# SBOMs over both sample repositories.
capa --run licenseaudit.capa

# Emit the compiler-side proof artefacts for LicenseAudit itself.
capa --manifest   licenseaudit.capa > sbom/manifest.json
capa --cyclonedx  licenseaudit.capa > sbom/sbom.cyclonedx.json
capa --spdx       licenseaudit.capa > sbom/sbom.spdx.json
capa --provenance licenseaudit.capa > sbom/provenance.slsa.json

echo "regenerated out/ and sbom/ (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
