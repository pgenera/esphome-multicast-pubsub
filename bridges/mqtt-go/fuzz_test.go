package main

import (
	"encoding/binary"
	"testing"
)

// Fuzz targets for the bridge's parsing surfaces. The invariant for all
// three is "must not panic, must terminate, must return either a valid
// result or an error" -- the bridge runs on untrusted-network input
// (multicast) and untrusted-broker input (MQTT payloads from unknown
// producers), so a panic anywhere here is a DoS vector.
//
// Seed corpus shape follows the project rule: random bytes AND
// mutated-valid AND "valid envelope, invalid payload" -- the last category
// catches the bugs random-bytes never reach because the front-of-message
// magic check rejects everything else.

func fuzzSchema(tb testing.TB) *Schema {
	tb.Helper()
	s, err := NewSchema("fuzz", []SchemaField{
		{Name: "b", Type: "bool", Tag: 1},
		{Name: "i32", Type: "int32", Tag: 2},
		{Name: "u64", Type: "uint64", Tag: 3},
		{Name: "s32", Type: "sint32", Tag: 4},
		{Name: "f", Type: "float", Tag: 5},
		{Name: "str", Type: "string", Tag: 6},
		{Name: "bin", Type: "bytes", Tag: 7},
		{Name: "nums", Type: "int32", Tag: 8, Repeated: true},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// FuzzDecodePacket exercises the on-wire datagram parser. Seeds cover:
//  1. valid plaintext packet,
//  2. valid encrypted packet,
//  3. valid-magic-and-version envelope with arbitrary body bytes (the
//     "valid envelope, invalid payload" category),
//  4. raw random short strings (the mutator will expand them).
func FuzzDecodePacket(f *testing.F) {
	// (1) a real plaintext datagram
	plain, err := EncodePacket("home/test", []byte("hello"), encodingRaw, nil, 0, 0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(plain)
	// (2) a real encrypted datagram
	key := DeriveKey("passphrase")
	enc, err := EncodePacket("home/test", []byte("hello"), encodingRaw, key, 1_700_000_000, 0xABCDEF01)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(enc)
	// (3) valid header envelope + 16 arbitrary body bytes -- the parser
	// has to walk past the magic/version checks to find issues in the
	// length/CRC/enc_mode handling.
	envelope := make([]byte, headerLen+16)
	envelope[0] = wireMagic0
	envelope[1] = wireMagic1
	envelope[2] = wireVersion
	envelope[3] = encodingProto
	binary.LittleEndian.PutUint16(envelope[8:10], 16) // pay_len matches body
	envelope[10] = encModeNone
	f.Add(envelope)
	// "valid envelope" with mismatched length declaration
	mismatched := make([]byte, headerLen+16)
	mismatched[0] = wireMagic0
	mismatched[1] = wireMagic1
	mismatched[2] = wireVersion
	mismatched[3] = encodingRaw
	binary.LittleEndian.PutUint16(mismatched[8:10], 9999)
	f.Add(mismatched)
	// (4) raw nonsense
	f.Add([]byte{})
	f.Add([]byte{'M', 'P'})
	f.Add([]byte("not even close"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try both no-key and with-key paths; both must be panic-free.
		_, _ = DecodePacket(data, nil)
		_, _ = DecodePacket(data, key)
	})
}

// FuzzDecodeProto runs the proto-body decoder against arbitrary bytes
// claiming to match a fixed schema. The decoder must reject malformed
// varints, truncated length-delim fields, and oversized lengths without
// panicking or allocating unbounded memory.
func FuzzDecodeProto(f *testing.F) {
	s := fuzzSchema(f)
	// Seed: full encode of every supported field type.
	body, err := EncodeProto(s, map[string]any{
		"b": true, "i32": int64(-7), "u64": uint64(1 << 50),
		"s32": int64(-100), "f": float64(2.5), "str": "hi",
		"bin": []byte{0xde, 0xad}, "nums": []any{int64(1), int64(2), int64(3)},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(body)
	// Valid tag with truncated value (varint header, no body).
	f.Add([]byte{0x08}) // tag=1 wire=0, but no varint payload follows
	// Valid len-delim tag with a huge length claim.
	f.Add([]byte{0x32, 0xff, 0xff, 0xff, 0x7f}) // tag=6 (string), len=~2^31
	// Random byte salads.
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeProto(s, data)
	})
}

// FuzzJSONToProto checks that JSON parsing + type coercion never panics
// on hostile input. The encoder must reject unknown fields, type
// mismatches, oversize numbers etc. as errors -- never as a crash.
func FuzzJSONToProto(f *testing.F) {
	s := fuzzSchema(f)
	// Seed: valid JSON exercising every type.
	f.Add([]byte(`{"b":true,"i32":-7,"u64":1234,"s32":-1,"f":2.5,"str":"hi","bin":"AAEC","nums":[1,2,3]}`))
	// "Valid envelope" -- looks like an object the schema knows, but with
	// wrong scalar types in each slot.
	f.Add([]byte(`{"b":"not a bool","i32":"text","u64":-1,"s32":1.5,"f":"nan","str":42,"bin":"!!!","nums":"oops"}`))
	// Unknown field -- must error (typo safety), not crash.
	f.Add([]byte(`{"surprise":1}`))
	// Non-object root.
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`"hello"`))
	f.Add([]byte(`null`))
	// Garbage.
	f.Add([]byte(``))
	f.Add([]byte(`{`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = JSONToProto(s, data)
	})
}
