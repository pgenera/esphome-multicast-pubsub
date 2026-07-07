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

	"golang.org/x/crypto/chacha20poly1305"
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
	encModeNone byte = 0x00
	encModeAEAD byte = 0x01 // ChaCha20-Poly1305 (RFC 8439)

	// AEAD sizes (RFC 8439).
	aeadNonceLen = chacha20poly1305.NonceSize // 12
	aeadTagLen   = chacha20poly1305.Overhead  // 16
	// Bytes prepended to the AEAD plaintext (encrypted + authenticated),
	// ahead of the user payload: TOPIC_CRC32 (4) + TIMESTAMP (4).
	aeadPrefixLen = 8
)

// AEADBodyLen is the on-wire encrypted-body length for a payload of
// `payloadLen` bytes: the 12-byte nonce, the ciphertext (8-byte prefix +
// payload, no padding -- ChaCha20 is a stream cipher), and the 16-byte tag.
func AEADBodyLen(payloadLen int) int {
	return aeadNonceLen + aeadPrefixLen + payloadLen + aeadTagLen
}

// DeriveKey hashes a passphrase to a 32-byte AEAD key. Matches the
// `hashlib.sha256(key).digest()` convention used by ESPHome's
// packet_transport component (which mpubsub's C++ side reuses).
func DeriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
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

func writeHeader(buf []byte, encoding byte, hdrCRC uint32, payloadLen int, encMode byte) {
	buf[0] = wireMagic0
	buf[1] = wireMagic1
	buf[2] = wireVersion
	buf[3] = encoding
	binary.LittleEndian.PutUint32(buf[4:8], hdrCRC)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(payloadLen))
	buf[10] = encMode
	buf[11] = 0 // reserved
}

// EncodePacket builds the 12-byte header + body datagram. When `key` is
// non-nil (32 bytes), the body is ChaCha20-Poly1305:
// `[AEAD_NONCE (12)] || ciphertext || [TAG (16)]` where the ciphertext
// encrypts `[crc32 (4)] || [timestamp (4)] || payload` and the 12-byte
// cleartext header is the AAD; the cleartext TOPIC_CRC32 field is zeroed and
// PAY_LEN holds the plaintext length.
//
// `timestamp` (unix epoch seconds) feeds the receiver's freshness check and
// `nonce` (the 12-byte AEAD nonce) is its per-message identity. Both are
// ignored for plaintext (key == nil). A timestamp of 0 marks "the sender had
// no synchronized clock" and is dropped by a replay-checking receiver.
func EncodePacket(topic string, payload []byte, encoding byte, key []byte, timestamp uint32, nonce []byte) ([]byte, error) {
	if encoding != encodingRaw && encoding != encodingProto {
		return nil, fmt.Errorf("unknown encoding 0x%02x", encoding)
	}
	crc := TopicCRC32(topic)
	if key == nil {
		if len(payload) > maxPayload {
			return nil, fmt.Errorf("payload too large (%d > %d)", len(payload), maxPayload)
		}
		buf := make([]byte, headerLen+len(payload))
		writeHeader(buf, encoding, crc, len(payload), encModeNone)
		copy(buf[headerLen:], payload)
		return buf, nil
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("aead key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != aeadNonceLen {
		return nil, fmt.Errorf("aead nonce must be %d bytes, got %d", aeadNonceLen, len(nonce))
	}
	if headerLen+AEADBodyLen(len(payload)) > maxDatagram {
		return nil, fmt.Errorf("encrypted payload too large (%d -> %d-byte body)",
			len(payload), AEADBodyLen(len(payload)))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, headerLen+aeadNonceLen, headerLen+AEADBodyLen(len(payload)))
	writeHeader(buf, encoding, 0, len(payload), encModeAEAD)
	copy(buf[headerLen:], nonce)
	plaintext := make([]byte, aeadPrefixLen+len(payload))
	binary.LittleEndian.PutUint32(plaintext[0:4], crc)
	binary.LittleEndian.PutUint32(plaintext[4:8], timestamp)
	copy(plaintext[aeadPrefixLen:], payload)
	// Seal appends ciphertext||tag to buf; AAD is the 12-byte header.
	buf = aead.Seal(buf, nonce, plaintext, buf[0:headerLen])
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
	// packet; both are 0 for plaintext. Nonce is the low 32 bits of the
	// (random) AEAD nonce, used as the de-dup identity.
	Timestamp uint32
	Nonce     uint32
}

var (
	errTooShort        = errors.New("datagram too short")
	errBadMagic        = errors.New("bad magic")
	errBadVersion      = errors.New("unsupported version")
	errUnknownEncoding = errors.New("unknown encoding")
	errLengthMismatch  = errors.New("length mismatch")
	errUnknownEncMode  = errors.New("unknown enc_mode")
	errBodyLenMismatch = errors.New("encrypted body length mismatch")
	errEncryptedNoKey  = errors.New("encrypted packet but no key configured")
	errAuthFailed      = errors.New("AEAD authentication failed (wrong key or tampered packet)")
)

// DecodePacket parses a datagram. When the packet is encrypted (ENC_MODE ==
// AEAD), `key` must be the 32-byte ChaCha20-Poly1305 key; the body is
// authenticated and decrypted, the topic CRC + timestamp come from the
// decrypted prefix, and Payload is the plaintext slice. WasEncrypted
// indicates which path produced the result so callers can enforce per-route
// "require_encryption" policies.
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
	if encMode != encModeNone && encMode != encModeAEAD {
		return nil, errUnknownEncMode
	}
	hdrCRC := binary.LittleEndian.Uint32(data[4:8])
	payloadLen := binary.LittleEndian.Uint16(data[8:10])
	// data[11] reserved; receivers ignore for forward-compat.
	if encMode == encModeAEAD {
		if len(data) != headerLen+AEADBodyLen(int(payloadLen)) {
			return nil, errBodyLenMismatch
		}
		if key == nil {
			return nil, errEncryptedNoKey
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("aead key must be 32 bytes, got %d", len(key))
		}
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		nonce := data[headerLen : headerLen+aeadNonceLen]
		sealed := data[headerLen+aeadNonceLen:] // ciphertext || tag
		plain, err := aead.Open(nil, nonce, sealed, data[0:headerLen])
		if err != nil {
			return nil, errAuthFailed
		}
		return &DecodedPacket{
			TopicCRC:     binary.LittleEndian.Uint32(plain[0:4]),
			Encoding:     enc,
			EncMode:      encMode,
			WasEncrypted: true,
			Payload:      plain[aeadPrefixLen:],
			Timestamp:    binary.LittleEndian.Uint32(plain[4:8]),
			Nonce:        binary.LittleEndian.Uint32(nonce[0:4]),
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
