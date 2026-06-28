// Wire-format primitives for mpubsub. Mirrors
// components/mpubsub/{topic_hash,wire_format}.{h,cpp} and the
// Python reference at tests/unit/reference.py. Keep these three in lockstep.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
)

const (
	wireMagic0    byte = 'M'
	wireMagic1    byte = 'P'
	wireVersion   byte = 0x01
	headerLen          = 12
	maxDatagram        = 1232 // IPv6 min MTU (1280) - 40 (IPv6) - 8 (UDP).
	maxPayload         = maxDatagram - headerLen
	encodingRaw   byte = 0x00
	encodingProto byte = 0x01

	// EncMode lives in header byte 10.
	encModeNone  byte = 0x00
	encModeXXTEA byte = 0x01

	// XXTEA-256 constants.
	xxteaDelta uint32 = 0x9E3779B9

	// Bytes prepended to the XXTEA plaintext, ahead of the user payload:
	// TOPIC_CRC32 (4) + TIMESTAMP (4) + NONCE (4). The CRC is the integrity
	// tag; the timestamp + nonce feed receiver-side replay rejection.
	xxteaPrefixLen = 12
)

// XXTEACiphertextLen is the on-wire ciphertext length for a plaintext mpubsub
// payload of `plaintextLen` bytes. The plaintext is `[crc32 || timestamp ||
// nonce] (12 bytes) || payload`, zero-padded up to a multiple of 4 bytes
// (XXTEA word size). The 12-byte prefix already clears XXTEA's 2-word (8-byte)
// minimum, so no separate floor is needed.
func XXTEACiphertextLen(plaintextLen int) int {
	needed := plaintextLen + xxteaPrefixLen
	return (needed + 3) &^ 3
}

// DeriveKey hashes a passphrase to a 32-byte XXTEA-256 key. Matches the
// `hashlib.sha256(key).digest()` convention used by ESPHome's
// packet_transport component (which mpubsub's C++ side reuses).
func DeriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// xxteaMX matches esphome::xxtea (the authoritative on-device cipher): a
// 256-bit key with index k[(p ^ e) & 7] and e = sum>>2, not the 128-bit-style
// k[(p & 3) ^ e]. The bridge must match it to interoperate with devices.
func xxteaMX(z, y, sum uint32, p, e int, k []uint32) uint32 {
	return ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p^e)&7] ^ z))
}

// xxteaEncrypt encrypts `words` in place using `key` (8 uint32s).
func xxteaEncrypt(words []uint32, key []uint32) {
	n := len(words)
	if n < 2 {
		return
	}
	rounds := 6 + 52/n
	var sum uint32
	z := words[n-1]
	for r := 0; r < rounds; r++ {
		sum += xxteaDelta
		e := int(sum >> 2)
		var y uint32
		for p := 0; p < n-1; p++ {
			y = words[p+1]
			words[p] += xxteaMX(z, y, sum, p, e, key)
			z = words[p]
		}
		y = words[0]
		words[n-1] += xxteaMX(z, y, sum, n-1, e, key)
		z = words[n-1]
	}
}

// xxteaDecrypt decrypts `words` in place using `key` (8 uint32s).
func xxteaDecrypt(words []uint32, key []uint32) {
	n := len(words)
	if n < 2 {
		return
	}
	rounds := 6 + 52/n
	sum := uint32(rounds) * xxteaDelta
	y := words[0]
	for r := 0; r < rounds; r++ {
		e := int(sum >> 2)
		var z uint32
		for p := n - 1; p > 0; p-- {
			z = words[p-1]
			words[p] -= xxteaMX(z, y, sum, p, e, key)
			y = words[p]
		}
		z = words[n-1]
		words[0] -= xxteaMX(z, y, sum, 0, e, key)
		y = words[0]
		sum -= xxteaDelta
	}
}

func bytesToWordsLE(b []byte) []uint32 {
	if len(b)%4 != 0 {
		return nil
	}
	out := make([]uint32, len(b)/4)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[i*4 : i*4+4])
	}
	return out
}

func wordsToBytesLE(words []uint32) []byte {
	out := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(out[i*4:i*4+4], w)
	}
	return out
}

// Scope is the low nibble of the IPv6 multicast scope field (RFC 4291 §2.7).
type Scope uint8

const (
	ScopeLinkLocal Scope = 0x2
	ScopeSiteLocal Scope = 0x5
	ScopeOrgLocal  Scope = 0x8
)

func ParseScope(s string) (Scope, error) {
	switch s {
	case "link-local", "":
		return ScopeLinkLocal, nil
	case "site-local":
		return ScopeSiteLocal, nil
	case "organization-local", "org-local":
		return ScopeOrgLocal, nil
	default:
		return 0, fmt.Errorf("unknown scope %q (want link-local/site-local/organization-local)", s)
	}
}

// TopicToGroup derives the IPv6 multicast group for a topic. Matches
// components/mpubsub/topic_hash.cpp byte-for-byte.
func TopicToGroup(topic string, scope Scope) net.IP {
	digest := sha256.Sum256([]byte(topic))
	addr := make(net.IP, 16)
	addr[0] = 0xFF
	// T-bit (0x1, transient) per RFC 4291 §2.7.
	addr[1] = (0x1 << 4) | (byte(scope) & 0x0F)
	copy(addr[2:], digest[:14])
	return addr
}

// TopicCRC32 is the IEEE CRC-32 of the UTF-8 topic, matching
// zlib.crc32 and the C++ topic_crc32 helper.
func TopicCRC32(topic string) uint32 {
	return crc32.ChecksumIEEE([]byte(topic))
}

// EncodePacket builds the 12-byte header + payload datagram. When `key` is
// non-nil (32 bytes), the body is XXTEA-256 ciphertext over
// `[crc32 || timestamp || nonce] || payload || zero pad`; the cleartext
// TOPIC_CRC32 field is zeroed and PAY_LEN holds the plaintext length.
//
// `timestamp` (unix epoch seconds) and `nonce` feed the receiver's replay
// rejection and are ignored for plaintext (key == nil). A timestamp of 0
// marks "the sender had no synchronized clock" and is dropped by a
// replay-checking receiver.
func EncodePacket(topic string, payload []byte, encoding byte, key []byte, timestamp, nonce uint32) ([]byte, error) {
	if encoding != encodingRaw && encoding != encodingProto {
		return nil, fmt.Errorf("unknown encoding 0x%02x", encoding)
	}
	crc := TopicCRC32(topic)
	var (
		body    []byte
		encMode byte
		hdrCRC  uint32
	)
	if key == nil {
		if len(payload) > maxPayload {
			return nil, fmt.Errorf("payload too large (%d > %d)", len(payload), maxPayload)
		}
		body = payload
		encMode = encModeNone
		hdrCRC = crc
	} else {
		if len(key) != 32 {
			return nil, fmt.Errorf("xxtea key must be 32 bytes, got %d", len(key))
		}
		clen := XXTEACiphertextLen(len(payload))
		if headerLen+clen > maxDatagram {
			return nil, fmt.Errorf("encrypted payload too large (%d -> %d-byte ciphertext)",
				len(payload), clen)
		}
		plain := make([]byte, clen)
		// 12-byte prefix: crc | timestamp | nonce, all little-endian.
		binary.LittleEndian.PutUint32(plain[0:4], crc)
		binary.LittleEndian.PutUint32(plain[4:8], timestamp)
		binary.LittleEndian.PutUint32(plain[8:12], nonce)
		copy(plain[xxteaPrefixLen:], payload)
		// plain[12+len(payload):] is already zero (Go zero-initializes slices).
		words := bytesToWordsLE(plain)
		xxteaEncrypt(words, bytesToWordsLE(key))
		body = wordsToBytesLE(words)
		encMode = encModeXXTEA
		hdrCRC = 0
	}
	buf := make([]byte, headerLen+len(body))
	buf[0] = wireMagic0
	buf[1] = wireMagic1
	buf[2] = wireVersion
	buf[3] = encoding
	binary.LittleEndian.PutUint32(buf[4:8], hdrCRC)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(payload)))
	buf[10] = encMode
	// buf[11] reserved, already zero.
	copy(buf[headerLen:], body)
	return buf, nil
}

// DecodedPacket is the result of a successful parse.
type DecodedPacket struct {
	TopicCRC     uint32
	Encoding     byte
	EncMode      byte
	WasEncrypted bool
	Payload      []byte // decrypted plaintext if WasEncrypted, raw body otherwise
	// Timestamp and Nonce are the replay fields recovered from an encrypted
	// packet's ciphertext prefix; both are 0 for plaintext packets.
	Timestamp uint32
	Nonce     uint32
}

var (
	errTooShort          = errors.New("datagram too short")
	errBadMagic          = errors.New("bad magic")
	errBadVersion        = errors.New("unsupported version")
	errUnknownEncoding   = errors.New("unknown encoding")
	errLengthMismatch    = errors.New("length mismatch")
	errUnknownEncMode    = errors.New("unknown enc_mode")
	errCiphertextTooShort = errors.New("ciphertext too short")
	errEncryptedNoKey    = errors.New("encrypted packet but no key configured")
)

// DecodePacket parses a datagram. When the packet is encrypted (ENC_MODE ==
// XXTEA), `key` must be the 32-byte XXTEA-256 key; the recovered topic CRC
// comes from the first 4 bytes of the decrypted plaintext and Payload is
// the plaintext slice. WasEncrypted indicates which path produced the
// result so callers can enforce per-route "require_encryption" policies.
func DecodePacket(data []byte, key []byte) (*DecodedPacket, error) {
	if len(data) < headerLen {
		return nil, errTooShort
	}
	if data[0] != wireMagic0 || data[1] != wireMagic1 {
		return nil, errBadMagic
	}
	if data[2] != wireVersion {
		return nil, errBadVersion
	}
	enc := data[3]
	if enc != encodingRaw && enc != encodingProto {
		return nil, errUnknownEncoding
	}
	encMode := data[10]
	if encMode != encModeNone && encMode != encModeXXTEA {
		return nil, errUnknownEncMode
	}
	hdrCRC := binary.LittleEndian.Uint32(data[4:8])
	payloadLen := binary.LittleEndian.Uint16(data[8:10])
	// data[11] reserved; receivers ignore for forward-compat.
	if encMode == encModeXXTEA {
		expected := headerLen + XXTEACiphertextLen(int(payloadLen))
		if len(data) != expected {
			return nil, errCiphertextTooShort
		}
		if key == nil {
			return nil, errEncryptedNoKey
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("xxtea key must be 32 bytes, got %d", len(key))
		}
		words := bytesToWordsLE(data[headerLen:])
		xxteaDecrypt(words, bytesToWordsLE(key))
		plain := wordsToBytesLE(words)
		crc := binary.LittleEndian.Uint32(plain[0:4])
		ts := binary.LittleEndian.Uint32(plain[4:8])
		nonce := binary.LittleEndian.Uint32(plain[8:12])
		return &DecodedPacket{
			TopicCRC:     crc,
			Encoding:     enc,
			EncMode:      encMode,
			WasEncrypted: true,
			Payload:      plain[xxteaPrefixLen : xxteaPrefixLen+int(payloadLen)],
			Timestamp:    ts,
			Nonce:        nonce,
		}, nil
	}
	if int(payloadLen)+headerLen != len(data) {
		return nil, errLengthMismatch
	}
	return &DecodedPacket{
		TopicCRC:     hdrCRC,
		Encoding:     enc,
		EncMode:      encMode,
		WasEncrypted: false,
		Payload:      data[headerLen:],
	}, nil
}
