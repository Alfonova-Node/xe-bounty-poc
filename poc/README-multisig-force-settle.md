# PoC: Multisig Threshold Bypass via lease_force_settle

## Vulnerability

`core/multisig.go:143` — `IsSpendingOp()` does NOT include `BlockLeaseForceSettle`.

```go
func IsSpendingOp(t BlockType) bool {
    switch t {
    case BlockSend, BlockBurn, BlockLease, BlockLeaseRenew, BlockMultisigOpen, BlockMultisigUpdate, BlockMint:
        return true
    default:
        return false  // <-- BlockLeaseForceSettle lands here
    }
}
```

`core/ledger.go:1502-1517` — when `IsSpendingOp` returns false AND the block
doesn't change representative, verification falls through to `VerifyMultisigAny`:

```go
threshold := IsSpendingOp(b.Type)
if !threshold {
    changes, _ := l.changesRepresentative(b)
    threshold = changes
}
if threshold {
    VerifyMultisig(...)   // requires ks.Threshold valid sigs
} else {
    VerifyMultisigAny(...) // ANY SINGLE valid sig from keyset suffices
}
```

## Impact

A multisig account with threshold M-of-N (e.g. 3-of-5) can have its active
leases force-settled by ANY SINGLE key holder, bypassing the M-of-N governance.

Effects:
1. Lease terminated unilaterally (consumer gets escrow back, no XE emission)
2. Provider reputation hit with `EventLeaseUnfulfilled` — permanent negative mark
3. Governance violation: one rogue key holder can sabotage all active leases

## Attack Scenario

1. Alice, Bob, Carol, Dave, Eve form a 3-of-5 multisig consumer account
2. Account creates a compute lease with Provider P (escrow locked in XCU)
3. Eve (single key holder, acting alone) submits `lease_force_settle` after
   expiry + grace + gap window
4. Node validates: `IsSpendingOp(BlockLeaseForceSettle)` = false →
   `VerifyMultisigAny` → Eve's single signature passes
5. Lease marked Unfulfilled, Provider P reputation damaged
6. Alice/Bob/Carol never consented

## Fix

Add `BlockLeaseForceSettle` to `IsSpendingOp`:

```go
case BlockSend, BlockBurn, BlockLease, BlockLeaseRenew, BlockLeaseForceSettle,
     BlockMultisigOpen, BlockMultisigUpdate, BlockMint:
    return true
```

Also consider: `BlockLeaseCancel` and `BlockLeaseSettle` are similarly excluded.
`BlockLeaseCancel` refunds escrow (financial impact), `BlockLeaseSettle` releases
emission + stake. Both should require full threshold.

## Severity

MEDIUM — governance bypass, reputation damage, no direct fund theft.
Escalates to HIGH if combined with reputation-gated protocol features.

## Files

- `core/multisig.go:143-150` — IsSpendingOp
- `core/multisig.go:117-141` — VerifyMultisigAny
- `core/ledger.go:1502-1517` — verifyBlockCredential threshold logic
- `core/ledger.go:2013-2131` — validateAndAddLeaseForceSettle