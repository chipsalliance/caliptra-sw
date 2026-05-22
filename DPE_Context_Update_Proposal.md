# DPE Context Update Proposal

## Summary

This proposal introduces three related changes:

1. Deprecate `STASH_MEASUREMENT` as a standalone Runtime mailbox command and use `AUTHORIZE_AND_STASH` for authorization, stashing, and stash update flows.
2. Support updating an already-stashed DPE measurement by `measurement_id`, including measurements stored in retired DPE contexts.
3. Allow Runtime replay of ROM-originated stashed measurements even when the ROM measurement log contains duplicate `tci_type` values.

This proposal requires a narrowly scoped `caliptra-dpe` `DeriveContext` flag for ROM measurement log replay. Runtime will use that flag only for ROM-originated measurements that may have duplicate `tci_type` values. Runtime will handle `UPDATE_STASH` by directly updating the persisted DPE state stored in DCCM; no new DPE update command is required.

## 1. Deprecate `STASH_MEASUREMENT`

`STASH_MEASUREMENT` should be retired as a standalone Runtime semantic path. New integrations should use `AUTHORIZE_AND_STASH` for both authorization and stashing.

Today, both commands eventually provide the same key inputs to DPE `DeriveContext`. The existing Runtime command names this value `fw_id`, and the legacy `STASH_MEASUREMENT` command names this value `metadata`. The unified API should expose it as `measurement_id`:

```text
STASH_MEASUREMENT.metadata    -> measurement_id -> DPE DeriveContext.tci_type
STASH_MEASUREMENT.measurement -> DPE DeriveContext.data
STASH_MEASUREMENT.svn         -> DPE DeriveContext.svn

AUTHORIZE_AND_STASH.measurement_id -> Image Metadata Entry lookup key when authorization is requested
AUTHORIZE_AND_STASH.measurement_id -> DPE DeriveContext.tci_type when stashing or updating
AUTHORIZE_AND_STASH.measurement or computed image digest -> DPE DeriveContext.data
AUTHORIZE_AND_STASH.svn       -> DPE DeriveContext.svn
```

The measurement may represent firmware, configuration, policy, device state, or another measured object, so `fw_id` is too narrow for the new command semantics.

In the proposed `AUTHORIZE_AND_STASH` request, `measurement_id` is the caller-provided measurement identifier and is used as the DPE `tci_type` for stash and update operations. When authorization is requested, Runtime will also use `measurement_id` to select the corresponding Image Metadata Entry (IME) in the Image Metadata Collection (IMC).

`STASH_MEASUREMENT` can remain temporarily as a compatibility wrapper that internally calls the same stash implementation as `AUTHORIZE_AND_STASH` with `SKIP_AUTH`. The command should be documented as deprecated rather than removed immediately.

## Recommended `AUTHORIZE_AND_STASH` Flag Model

```text
flags = 0
  authorize + create new stash context
  preserves current AUTHORIZE_AND_STASH behavior

SKIP_STASH
  authorize only
  no DPE context is created or updated

SKIP_AUTH
  create new stash context only
  replacement for STASH_MEASUREMENT

UPDATE_STASH
  authorize + update existing stash context selected by measurement_id
  updates an existing DPE context instead of creating a new one

UPDATE_STASH | SKIP_AUTH
  update existing stash context only
  no Image Metadata Entry authorization is performed

SKIP_AUTH | SKIP_STASH
  invalid
  no operation requested

UPDATE_STASH | SKIP_STASH
  invalid
  UPDATE_STASH requests a DPE measurement update, while SKIP_STASH requests no DPE measurement operation

Any reserved or undefined flag bit
  invalid
```

When `UPDATE_STASH` is not set, stashing creates a new DPE context using the normal Runtime stash path. Runtime-created stash contexts continue to use regular DPE `DeriveContext`, where `tci_type` uniqueness is enforced.

When `UPDATE_STASH` is set, the command updates an existing DPE context instead of creating a new one. The update path uses `measurement_id` as the DPE `tci_type`, same as the normal stash path.

## 2. ROM Measurement Log Replay and Duplicate `tci_type` Values

ROM also accepts `STASH_MEASUREMENT` requests. ROM does not create DPE contexts directly. Instead, ROM:

```text
1. Extends PCR31 with the measurement.
2. Records the measurement in the ROM measurement log.
3. Stores the request metadata in the measurement log entry.
```

Runtime later replays the ROM measurement log and creates the corresponding DPE contexts. During replay, the ROM measurement log entry metadata is treated as the `measurement_id` and used as the DPE `tci_type`.

This creates a compatibility issue. ROM currently does not check whether the metadata value, now treated as `measurement_id`, is unique. Therefore, it is possible for ROM to successfully record multiple stashed measurements with the same metadata value, but for Runtime to later fail when replaying the log into DPE because normal DPE `DeriveContext` rejects duplicate `tci_type` values.

To avoid boot-time replay failures caused by ROM-accepted measurements, Runtime should allow ROM-originated stashed measurements to create DPE contexts with duplicate `tci_type` values during ROM measurement log replay.

## `tci_type` Uniqueness Rules

The uniqueness policy should be split by measurement origin:

```text
ROM-originated stashed measurements:
  Duplicate tci_type values are allowed during Runtime replay of the ROM measurement log.

Runtime-originated stashed measurements:
  tci_type uniqueness remains enforced.
  AUTHORIZE_AND_STASH / Runtime stash flows must not create a new DPE context if the requested measurement_id already exists as the tci_type of any non-inactive DPE context.
```

This preserves compatibility with ROM behavior while keeping Runtime-created DPE contexts uniquely addressable.

## `caliptra-dpe` `DeriveContext` Flag for Duplicate Replay

`caliptra-dpe` should add a restricted `DeriveContext` flag for ROM measurement log replay:

```text
ALLOW_DUPLICATE_TCI_TYPE
```

Runtime should set this flag only while replaying ROM-originated measurement log entries. Runtime should reject external or generic DPE invocations that attempt to set this flag. When the flag is set, `DeriveContext` allows the new context's `tci_type` to duplicate an existing non-inactive context's `tci_type`. All other `DeriveContext` behavior remains unchanged.

The flag applies only to non-recursive context creation during ROM measurement log replay. It does not change recursive `DeriveContext` behavior.

All existing context-construction invariants remain enforced, including:

```text
parent_idx / children links are consistent
only the latest replayed context is the active default context
previous replayed contexts are Retired
inactive contexts remain fully inactive
context.locality matches context.tci.locality
TCI current and cumulative values are computed consistently with DPE extend semantics
```

Normal Runtime-created stash operations continue to use regular DPE `DeriveContext` without this flag and continue to enforce `tci_type` uniqueness.

## 3. `UPDATE_STASH` Behavior

Because ROM-originated measurements may have duplicate `tci_type` values, `tci_type` can no longer be treated as globally unique in all cases.

Any command that updates an existing stashed measurement by `measurement_id` must check how many non-inactive DPE contexts have that `measurement_id` as their `tci_type`.

The update command should use the following lookup rule:

```text
matches = all contexts where:
  context.state != Inactive
  context.tci.tci_type == measurement_id
```

Then:

```text
matches.len() == 0:
  fail, no matching context

matches.len() == 1:
  update the matched context

matches.len() > 1:
  fail, duplicate tci_type
```

This means a stashed measurement can be updated by `measurement_id` only when that value uniquely identifies one active or retired DPE context by `tci_type`.

If that `tci_type` is duplicated, the command must fail rather than guessing which context to update.

## Update Semantics

`UPDATE_STASH` should update the matched context using extend semantics rather than replace semantics:

```text
new_tci_cumulative = SHA384(old_tci_cumulative || new_measurement)
new_tci_current = new_measurement
```

The context state must be preserved:

```text
Active remains Active
Retired remains Retired
Inactive contexts are never updated
```

## Effect on Future CDI / CertifyKey

No descendant recomputation is required.

DPE computes the measurement hash later when a caller requests operations such as `CertifyKey` or `Sign`, by walking the context ancestry.

Future CDI, key, and certificate derivation will observe the updated TCI data during the ancestry walk.
