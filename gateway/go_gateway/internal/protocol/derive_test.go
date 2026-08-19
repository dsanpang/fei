package protocol

import (
	"bytes"
	"testing"
)

// The NASM implant (derive_agent_psk) must produce the identical subkey.
func TestDeriveAgentPSK(t *testing.T) {
	master := bytes.Repeat([]byte{0xAB}, 32)
	agentID := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	key1, err := DeriveAgentPSK(master, agentID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length %d", len(key1))
	}
	key2, _ := DeriveAgentPSK(master, agentID)
	if !bytes.Equal(key1, key2) {
		t.Fatal("derivation not deterministic")
	}
	other := agentID
	other[0] ^= 1
	key3, _ := DeriveAgentPSK(master, other)
	if bytes.Equal(key1, key3) {
		t.Fatal("different agents derived the same key")
	}
	if bytes.Equal(key1, master) {
		t.Fatal("derived key equals master")
	}
}
