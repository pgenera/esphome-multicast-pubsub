package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeDecodePlaintextRoundtrip(t *testing.T) {
	pkt, err := EncodePacket("home/x", []byte("hello"), encodingRaw, nil, 0, 0)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	d, err := DecodePacket(pkt, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.TopicCRC != TopicCRC32("home/x") {
		t.Errorf("crc mismatch: got %x want %x", d.TopicCRC, TopicCRC32("home/x"))
	}
	if !bytes.Equal(d.Payload, []byte("hello")) {
		t.Errorf("payload mismatch: got %q", d.Payload)
	}
	if d.WasEncrypted {
		t.Errorf("WasEncrypted should be false for plaintext")
	}
}

func TestEncodeDecodeEncryptedRoundtrip(t *testing.T) {
	key := DeriveKey("hunter2")
	payload := []byte("secret message")
	pkt, err := EncodePacket("home/x", payload, encodingRaw, key, 1_700_000_000, 0xDEADBEEF)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Bytes 4-7 (TOPIC_CRC32) must be zero on the wire.
	if !bytes.Equal(pkt[4:8], []byte{0, 0, 0, 0}) {
		t.Errorf("cleartext header CRC leaked: %x", pkt[4:8])
	}
	// Byte 10 (ENC_MODE) = XXTEA.
	if pkt[10] != encModeXXTEA {
		t.Errorf("enc_mode byte = %x, want %x", pkt[10], encModeXXTEA)
	}
	d, err := DecodePacket(pkt, key)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.TopicCRC != TopicCRC32("home/x") {
		t.Errorf("recovered crc mismatch")
	}
	if !bytes.Equal(d.Payload, payload) {
		t.Errorf("payload mismatch: got %q want %q", d.Payload, payload)
	}
	if !d.WasEncrypted {
		t.Errorf("WasEncrypted should be true")
	}
	// The replay fields survive the ciphertext roundtrip.
	if d.Timestamp != 1_700_000_000 || d.Nonce != 0xDEADBEEF {
		t.Errorf("replay fields mismatch: ts=%d nonce=%08x", d.Timestamp, d.Nonce)
	}
}

func TestEncryptedWrongKeyDoesNotRecoverCRC(t *testing.T) {
	key := DeriveKey("right")
	bad := DeriveKey("wrong")
	pkt, err := EncodePacket("home/x", []byte("payload"), encodingRaw, key, 1_700_000_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodePacket(pkt, bad)
	if err != nil {
		t.Fatalf("decode: %v", err) // shouldn't fail at decode level
	}
	if d.TopicCRC == TopicCRC32("home/x") {
		t.Errorf("wrong key recovered the correct CRC -- integrity check broken")
	}
}

func TestEncryptedNoKeyRejected(t *testing.T) {
	key := DeriveKey("k")
	pkt, _ := EncodePacket("t", []byte("x"), encodingRaw, key, 1_700_000_000, 1)
	if _, err := DecodePacket(pkt, nil); err == nil {
		t.Error("expected error decoding encrypted packet without key")
	}
}

func TestEncryptedEmptyPayload(t *testing.T) {
	key := DeriveKey("k")
	pkt, err := EncodePacket("t", nil, encodingRaw, key, 1_700_000_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	// 12 header + 12 prefix-only ciphertext (crc+ts+nonce, no payload) = 24.
	if len(pkt) != 24 {
		t.Errorf("len = %d, want 24", len(pkt))
	}
	d, err := DecodePacket(pkt, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Payload) != 0 {
		t.Errorf("payload should be empty, got %q", d.Payload)
	}
}

func TestUnknownEncModeRejected(t *testing.T) {
	pkt, _ := EncodePacket("t", nil, encodingRaw, nil, 0, 0)
	pkt[10] = 0x7F
	if _, err := DecodePacket(pkt, nil); err == nil {
		t.Error("expected error on unknown enc_mode")
	}
}

// Pinned known-answer test: the same passphrase + topic + payload that
// tests/unit/reference.py produces must be byte-for-byte identical to the
// Go encoding. Locks the Go XXTEA and packet layout to the Python wire
// reference (which is the source of truth that C++ also matches).
func TestEncryptedKnownVectorMatchesPythonReference(t *testing.T) {
	// Pinned with a fixed timestamp + nonce so the ciphertext is deterministic.
	// Regenerate via tests/unit/reference.py encode(..., timestamp=1700000000,
	// nonce=0xDEADBEEF) if the wire layout ever changes.
	expected, _ := hex.DecodeString("4d5001000000000005000100c16a7834e0076941935c7a00fba865daf8e76f51")
	key := DeriveKey("hunter2")
	pkt, err := EncodePacket("home/x", []byte("hello"), encodingRaw, key, 1_700_000_000, 0xDEADBEEF)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt, expected) {
		t.Errorf("Go encoding diverged from Python reference\n got:  %x\n want: %x", pkt, expected)
	}
}

func TestXXTEACiphertextLen(t *testing.T) {
	cases := []struct {
		in, out int
	}{
		{0, 12}, {1, 16}, {3, 16}, {4, 16}, {5, 20}, {8, 20}, {9, 24}, {100, 112},
	}
	for _, c := range cases {
		if got := XXTEACiphertextLen(c.in); got != c.out {
			t.Errorf("XXTEACiphertextLen(%d) = %d, want %d", c.in, got, c.out)
		}
	}
}
