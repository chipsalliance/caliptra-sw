# Caliptra Firmware Release Process

This document describes the steps required to perform a firmware release for Caliptra components (ROM, FMC, and Runtime Firmware).

---

## 1. Update Versions in caliptra-sw

Push version changes to the caliptra-sw repository.

### Required Updates

- Update version numbers in:
  - builder/src/version.rs
- Update expected values in:
  - test/tests/fips_test_suite/common.rs
- Update versions in the appropriate README files:
  - rom/dev/README.md
  - fmc/README.md
  - runtime/README.md

### Commit Changes

- Push changes in a single commit titled:
  - Updating <ROM, FMC, RT FW> version to x.y.z

---

## 2. Perform Release on GitHub

### Run Release Workflow

- Run the nightly release GitHub Action.
- Wait for the workflow to complete successfully.

### Update GitHub Release

Once the workflow passes:

- Update the existing GitHub release:
  - Update the release title (e.g. ROM-1.2.3)
  - Uncheck "Set as a pre-release"
  - Check "Set as the latest release"
- Select "Update release"

---

## 3. Tag the Release

### Create Git Tags

Create a new git tag corresponding to the released component:

- ROM:
  - rom-x.y.z
- FMC:
  - fmc-x.y.z
- Runtime Firmware:
  - rt-x.y.z

### Push Tags

- Push the new git tag(s) to origin.

---

## 4. Notify Users

### External Updates

- Update version information on the Caliptra site.
- Post an announcement on the Caliptra blog.

---
