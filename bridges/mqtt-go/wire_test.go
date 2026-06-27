package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// A fixed 12-byte nonce for deterministic encodings in tests.
var testNonce = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

func TestEncodeDecodePlaintextRoundtrip(t *testing.T) {
	pkt, err := EncodePacket("home/x", []byte("hello"), encodingRaw, nil, 0, nil)
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
	pkt, err := EncodePacket("home/x", payload, encodingRaw, key, 1_700_000_000, testNonce)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Bytes 4-7 (TOPIC_CRC32) must be zero on the wire.
	if !bytes.Equal(pkt[4:8], []byte{0, 0, 0, 0}) {
		t.Errorf("cleartext header CRC leaked: %x", pkt[4:8])
	}
	if pkt[10] != encModeAEAD {
		t.Errorf("enc_mode byte = %x, want %x", pkt[10], encModeAEAD)
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
	if d.Timestamp != 1_700_000_000 {
		t.Errorf("timestamp = %d, want 1700000000", d.Timestamp)
	}
}

func TestEncryptedWrongKeyFailsAuth(t *testing.T) {
	key := DeriveKey("right")
	bad := DeriveKey("wrong")
	pkt, err := EncodePacket("home/x", []byte("payload"), encodingRaw, key, 1_700_000_000, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePacket(pkt, bad); err == nil {
		t.Error("wrong key should fail AEAD authentication")
	}
}

func TestTamperFailsAuth(t *testing.T) {
	key := DeriveKey("k")
	pkt, _ := EncodePacket("home/x", []byte("value"), encodingRaw, key, 1_700_000_000, testNonce)
	pkt[len(pkt)-1] ^= 0x01 // flip a tag bit
	if _, err := DecodePacket(pkt, key); err == nil {
		t.Error("tampered packet should fail authentication")
	}
}

func TestEncryptedNoKeyRejected(t *testing.T) {
	key := DeriveKey("k")
	pkt, _ := EncodePacket("t", []byte("x"), encodingRaw, key, 1_700_000_000, testNonce)
	if _, err := DecodePacket(pkt, nil); err == nil {
		t.Error("expected error decoding encrypted packet without key")
	}
}

func TestEncryptedEmptyPayload(t *testing.T) {
	key := DeriveKey("k")
	pkt, err := EncodePacket("t", nil, encodingRaw, key, 1_700_000_000, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	// 12 header + 36 body (12 nonce + 8 prefix + 0 payload + 16 tag) = 48.
	if len(pkt) != 48 {
		t.Errorf("len = %d, want 48", len(pkt))
	}
	d, err := DecodePacket(pkt, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Payload) != 0 {
		t.Errorf("payload should be empty, got %q", d.Payload)
	}
}

func TestBadNonceLengthRejected(t *testing.T) {
	key := DeriveKey("k")
	if _, err := EncodePacket("t", []byte("x"), encodingRaw, key, 1, []byte("short")); err == nil {
		t.Error("expected error on wrong nonce length")
	}
}

func TestUnknownEncModeRejected(t *testing.T) {
	pkt, _ := EncodePacket("t", nil, encodingRaw, nil, 0, nil)
	pkt[10] = 0x7F
	if _, err := DecodePacket(pkt, nil); err == nil {
		t.Error("expected error on unknown enc_mode")
	}
}

// Pinned known-answer test: the same passphrase + topic + payload + nonce that
// tests/unit/reference.py produces must be byte-for-byte identical to the Go
// encoding. Locks the Go AEAD and packet layout to the Python wire reference
// (which the C++ side also matches, both being RFC 8439).
func TestEncryptedKnownVectorMatchesPythonReference(t *testing.T) {
	expected, _ := hex.DecodeString(
		"4d5001000000000005000100000102030405060708090a0b70f08085036261950d7497b37a76184b4659c2e378ab6352115516ec59")
	key := DeriveKey("hunter2")
	pkt, err := EncodePacket("home/x", []byte("hello"), encodingRaw, key, 1_700_000_000, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt, expected) {
		t.Errorf("Go encoding diverged from Python reference\n got:  %x\n want: %x", pkt, expected)
	}
}

func TestAEADBodyLen(t *testing.T) {
	cases := []struct {
		in, out int
	}{
		{0, 36}, {1, 37}, {5, 41}, {100, 136},
	}
	for _, c := range cases {
		if got := AEADBodyLen(c.in); got != c.out {
			t.Errorf("AEADBodyLen(%d) = %d, want %d", c.in, got, c.out)
		}
	}
}
