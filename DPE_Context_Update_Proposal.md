# DPE Context Update Proposal

## Summary

This proposal introduces two related changes:

1. Add v2 stash commands: `STASH_MEASUREMENT_V2`, which creates a stashed DPE measurement and returns a Runtime-generated 16-byte `measurement_handle`, and `AUTHORIZE_AND_STASH_V2`, which preserves the existing authorize-and-stash flow and returns a `measurement_handle` when it creates a stashed DPE measurement.
2. Add `UPDATE_STASH`, a new mailbox command that takes a `measurement_handle` and updates the corresponding stashed DPE measurement.

The existing `STASH_MEASUREMENT` and `AUTHORIZE_AND_STASH` commands remain intact for compatibility. Runtime keeps a persistent side table that maps each valid `measurement_handle` to the DPE context index it identifies. `UPDATE_STASH` resolves the handle through that Runtime-owned table and updates the persisted DPE state stored in DCCM. No new public DPE update command is required.

## 1. Preserve Existing Commands

The current commands remain unchanged:

```text
STASH_MEASUREMENT
  Existing create-only stash command.
  Existing request and response format remain unchanged.
  Does not return a measurement_handle.
  Measurements created by this command cannot be updated by UPDATE_STASH.

AUTHORIZE_AND_STASH
  Existing authorize-and-optional-stash command.
  Existing request, response, and flags remain unchanged.
  Does not return a measurement_handle.
  Measurements created by this command cannot be updated by UPDATE_STASH.
```

New callers that need update support should use `STASH_MEASUREMENT_V2` or `AUTHORIZE_AND_STASH_V2`. Only measurements with a valid Runtime-issued `measurement_handle` are updatable.

Today, `STASH_MEASUREMENT` and `AUTHORIZE_AND_STASH` both provide the same key inputs to DPE `DeriveContext`:

```text
STASH_MEASUREMENT.metadata    -> stash label -> DPE DeriveContext.tci_type
STASH_MEASUREMENT.measurement -> DPE DeriveContext.data
STASH_MEASUREMENT.svn         -> DPE DeriveContext.svn

AUTHORIZE_AND_STASH.fw_id -> Image Metadata Entry lookup key when authorization is requested
AUTHORIZE_AND_STASH.fw_id -> stash label -> DPE DeriveContext.tci_type when stashing
AUTHORIZE_AND_STASH.measurement or computed image digest -> DPE DeriveContext.data
AUTHORIZE_AND_STASH.svn   -> DPE DeriveContext.svn
```

The stash label may represent firmware, configuration, policy, device state, or another measured object. It is useful for DPE TCI typing and IME lookup, but it must not be used to select an existing context for update. It is caller-provided, predictable, and may be duplicated by ROM-originated measurements.

## 2. `STASH_MEASUREMENT_V2`

`STASH_MEASUREMENT_V2` should be the updatable version of `STASH_MEASUREMENT`.

The request should match `STASH_MEASUREMENT`:

```text
metadata: u8[4]
measurement: u8[48]
context: u8[48]
svn: u32
```

The response should include the DPE result and a measurement handle:

```text
dpe_result: u32
measurement_handle: u8[16]
```

On success, Runtime creates the stashed DPE context using the existing stash path, extends PCR31 as today, stores a fresh non-zero `measurement_handle` for the created context index, and returns the handle.

On failure, Runtime returns an all-zero `measurement_handle`.

Current ROM support for `STASH_MEASUREMENT_V2` is out of scope. Future ROMs may support `STASH_MEASUREMENT_V2` before Runtime is loaded, but that would require a ROM measurement log extension that records the generated `measurement_handle` so Runtime can install the handle-to-context-index mapping during replay.

## 3. `AUTHORIZE_AND_STASH_V2`

`AUTHORIZE_AND_STASH_V2` should be the updatable version of `AUTHORIZE_AND_STASH`.

The request should match `AUTHORIZE_AND_STASH`:

```text
fw_id: u8[4]
measurement: u8[48]
context: u8[48]
svn: u32
flags: u32
source: u32
image_size: u32
```

The existing `SKIP_STASH` behavior should be preserved:

```text
flags = 0
  authorize + create new stash context
  returns a newly generated measurement_handle when authorization succeeds

SKIP_STASH
  authorize only
  no DPE context is created or updated
  response measurement_handle is all zero

Any reserved or undefined flag bit
  invalid
```

The response should include the authorization result and the measurement handle:

```text
auth_req_result: u32
measurement_handle: u8[16]
```

When authorization succeeds and stashing is not skipped, Runtime creates the stashed DPE context, stores a fresh non-zero `measurement_handle` for the created context index, and returns the handle.

When authorization fails or `SKIP_STASH` is set, Runtime returns an all-zero `measurement_handle`.

## 4. Measurement Handle Mapping

Runtime should store the handle mapping as DPE-side persistent metadata, parallel to the existing context tag side tables:

```text
measurement_handle_valid: [U8Bool; MAX_HANDLES]
measurement_handles: [[u8; 16]; MAX_HANDLES]
```

Each valid entry maps one opaque `measurement_handle` to the DPE context at the same index in `fw.dpe.state.contexts`. The DPE context index is not returned to the caller.

Handle generation rules:

```text
1. Generate 16 random bytes using the TRNG in Runtime.
2. Reject the all-zero handle value.
3. Check the candidate against all currently valid handles.
4. If it collides, retry handle generation.
5. If Runtime cannot produce a unique handle, fail the command.
```

A 16-byte random handle is a bearer capability for updating one stashed DPE measurement. It prevents a caller from selecting an update target by guessing or reusing a public `fw_id`, `metadata`, or `tci_type` value. If the handle is disclosed to another caller with access to `UPDATE_STASH`, that caller can request updates to the mapped measurement, so callers must treat the handle as sensitive.

Runtime should keep the handle side table in sync with DPE context lifetime. A valid handle entry is only valid while the DPE context at the same index is active or retired. When Runtime clears or reuses a DPE context, it must also clear the handle entry at that index.

## 5. `UPDATE_STASH`

`UPDATE_STASH` is a new mailbox command that updates an existing v2-created stashed DPE measurement selected by `measurement_handle`.

The request should include:

```text
measurement_handle: u8[16]
measurement: u8[48]
svn: u32
```

The response should include a status result for the update. The exact response shape can mirror existing mailbox status conventions, but the command must fail if the handle is invalid or the mapped context cannot be updated.

The update command should use the following lookup rule:

```text
index = the entry where:
  measurement_handle_valid[index] == true
  measurement_handles[index] == request.measurement_handle
```

Then:

```text
request.measurement_handle == [0; 16]:
  fail, invalid handle

no matching index:
  fail, no matching handle

matching index and contexts[index].state != Inactive:
  update the mapped context

matching index and contexts[index].state == Inactive:
  clear the stale mapping and fail, no matching active or retired context
```

`UPDATE_STASH` must not identify the target context by stash label, `fw_id`, `metadata`, DPE `tci_type`, or DPE `ContextHandle`. The `measurement_handle` is the lookup authority.

Only v2 stash commands create measurement-handle table entries. Measurements created by legacy `STASH_MEASUREMENT` or legacy `AUTHORIZE_AND_STASH` return no handle, so callers have no valid `measurement_handle` to provide to `UPDATE_STASH` for those measurements.

## Update Semantics

`UPDATE_STASH` should update the matched context using extend semantics rather than replace semantics:

```text
new_tci_cumulative = SHA384(old_tci_cumulative || new_measurement)
new_tci_current = new_measurement
```

On a successful update, Runtime should also extend PCR31 with the request `measurement`, matching the existing stash path.

The context state and identity fields must be preserved:

```text
Active remains Active
Retired remains Retired
Inactive contexts are never updated
tci_type is not changed by UPDATE_STASH
locality is not changed by UPDATE_STASH
parent_idx / children links are not changed by UPDATE_STASH
measurement_handle mapping is not changed by UPDATE_STASH
```

Runtime should apply the request `svn` using the same SVN handling used when creating a stashed measurement.

## Effect on Future CDI / CertifyKey

No descendant recomputation is required.

DPE computes the measurement hash later when a caller requests operations such as `CertifyKey` or `Sign`, by walking the context ancestry.

Future CDI, key, and certificate derivation will observe the updated TCI data during the ancestry walk.
