````markdown
# DPE Context Update Proposal

## Summary

This proposal introduces two related changes:

1. Deprecate `STASH_MEASUREMENT` as a standalone mailbox command and use `AUTHORIZE_AND_STASH` for both authorization and stashing flows.
2. Add a new command to update an already-stashed DPE measurement by `tci_type`, including measurements stored in retired DPE contexts.

## 1. Deprecate `STASH_MEASUREMENT`

`STASH_MEASUREMENT` should be retired as a standalone semantic path. New integrations should use `AUTHORIZE_AND_STASH` for both authorization and stashing.

Today, both commands eventually provide the same key inputs to DPE `DeriveContext`:

```text
STASH_MEASUREMENT.metadata    -> DPE DeriveContext.tci_type
STASH_MEASUREMENT.measurement -> DPE DeriveContext.data
STASH_MEASUREMENT.svn         -> DPE DeriveContext.svn

AUTHORIZE_AND_STASH.fw_id     -> auth-manifest lookup key
AUTHORIZE_AND_STASH.fw_id     -> DPE DeriveContext.tci_type when stashing
AUTHORIZE_AND_STASH.measurement or computed image digest -> DPE DeriveContext.data
AUTHORIZE_AND_STASH.svn       -> DPE DeriveContext.svn
```

Since `fw_id` and `metadata` are already used the same way for `DeriveContext.tci_type`, `AUTHORIZE_AND_STASH` can become the single command for authorization and stashing.

## Recommended `AUTHORIZE_AND_STASH` Flag Model

```text
flags = 0
  authorize + stash
  preserves current AUTHORIZE_AND_STASH behavior

SKIP_STASH
  authorize only

SKIP_AUTH
  stash only
  replacement for STASH_MEASUREMENT

UPDATE_STASH
  update an existing DPE context (via DPE tci_type)

SKIP_AUTH | SKIP_STASH
  invalid
  no operation requested
```

`STASH_MEASUREMENT` can remain temporarily as a compatibility wrapper that internally calls the same stash implementation as `AUTHORIZE_AND_STASH` with `SKIP_AUTH`. The command should be documented as deprecated rather than removed immediately.


## UPDATE_STASH Behavior

```text
1. Convert the input identifier to DPE tci_type using the same mapping as stash.
2. Search DPE contexts for a context where:
     context.state != Inactive
     context.tci.tci_type == tci_type
3. If no context is found, return not found / invalid argument.
4. If more than one context is found, return internal error.
   This should not happen because DeriveContext already enforces tci_type uniqueness among non-inactive contexts.
5. Update the matched context using extend semantics:
     tci_current = new_measurement
     tci_cumulative = HASH(old_tci_cumulative || new_measurement)
6. Leave context state unchanged:
     Active remains Active
     Retired remains Retired
```

This supports both active/current context updates and retired ancestor context updates.

For example, in a DPE chain:

```text
A -> B -> C
```

where `A` and `B` are retired and `C` is the active default context, `UPDATE_STASH` can update `B` by looking up `B.tci_type`.

## Why `tci_type` Works as the Identifier

DPE `DeriveContext` already rejects reuse of a `tci_type` across non-inactive contexts. Retired contexts still count as non-inactive.

Therefore, `tci_type` is a stable identifier for any active or retired stashed context.

This avoids relying on DPE handles. DPE handles do not work for retired contexts because retired contexts have invalid handles.

## Authorization Model

`UPDATE_STASHED_MEASUREMENT` should be Caliptra/runtime-owned and likely PL0-only.

It should not rely on normal DPE handle ownership because the command is specifically intended to update contexts that may be retired and no longer have valid handles.

```text
DPE handle-based update:
  Caller proves ownership with a DPE handle.

UPDATE_STASHED_MEASUREMENT:
  Runtime authorizes the operation by mailbox privilege and policy.
```

## Extend Semantics

The update should use extend semantics rather than replace semantics:

```text
new_tci_cumulative = SHA384(old_tci_cumulative || new_measurement)
new_tci_current = new_measurement
```

This matches the existing DPE measurement-extension model and records that the context evolved after the original stash operation.

## Effect on Future CDI / CertifyKey

No descendant recomputation is required.

DPE computes the measurement hash later when a caller requests operations such as `CertifyKey` or `Sign`, by walking the context ancestry.

Therefore, if `B` is updated after `C` already exists:

```text
A -> B -> C
```

future CDI, key, and certificate derivation for `C` will observe the updated `B` TCI data during the ancestry walk.

## PCR31 Caveat

This command updates DPE context state, but it cannot rewrite PCR31 history. PCR extension is append-only.

Recommended behavior:

```text
Updating a stashed measurement updates DPE context state only.
It does not rewrite prior PCR31 extensions.

If audit visibility is required, the update command may extend PCR31 with the new measurement or with an update event digest, but the old PCR value remains part of PCR history.
```

Suggested position:

```text
UPDATE_STASHED_MEASUREMENT affects future DPE-derived CDI, certificate, and key material.
It does not alter past PCR31 measurements.
```
````

## caliptra-dpe Changes
Updating a stashed measurement by `tci_type` requires new support in `caliptra-dpe`.

Today, `caliptra-dpe` has `UpdateContextMeasurementCmd`, but it is handle-authorized. It requires a valid parent context handle and updates only an active direct child selected by `tci_type`. That does not support the stash chain case where the target context may be retired and no longer has a valid handle.

To support this proposal, `caliptra-dpe` should add a new vendor command or internal primitive:

```text
UpdateContextMeasurementByTciType
```

The command should:

```text
1. Take tci_type and new_measurement as input.
2. Search all DPE contexts for:
     context.state != Inactive
     context.tci.tci_type == tci_type
3. Allow the target context to be Active or Retired.
4. Reject Inactive contexts.
5. Update the matched context using extend semantics:
     tci_current = new_measurement
     tci_cumulative = SHA384(old_tci_cumulative || new_measurement)
6. Preserve the context state:
     Active remains Active
     Retired remains Retired
```

This new primitive is needed because retired contexts cannot be addressed through normal DPE handles.

The existing `UpdateContextMeasurementCmd` should either remain unchanged, or be extended only with a clearly separated mode. A separate `UpdateContextMeasurementByTciType` command is preferred because it keeps the existing handle-authorized update semantics intact.