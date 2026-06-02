// tesla_session_test.go — coverage for the hand-rolled protobuf field
// scanner used by Exchange to demux BLE response frames by
// request_uuid. The scanner is small but load-bearing: if it returns
// the wrong bytes (or never matches), the BLE Exchange loop either
// hands the caller a stale frame or sits forever waiting for one
// that won't arrive.
package services

import (
	"bytes"
	"testing"
)

func TestExtractRoutableUUID_HappyPath(t *testing.T) {
	// Minimal valid RoutableMessage with field 51 (uuid, LEN, 16 bytes).
	// Wire tag for field 51 LEN: (51<<3)|2 = 410 = varint 0x9A 0x03.
	uuid := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	buf := []byte{0x9A, 0x03, 0x10} // tag + length 16
	buf = append(buf, uuid...)

	got := extractRoutableUUID(buf)
	if !bytes.Equal(got, uuid) {
		t.Fatalf("extractRoutableUUID = %x, want %x", got, uuid)
	}
}

func TestExtractRoutableRequestUUID_HappyPath(t *testing.T) {
	// Field 50 LEN tag: (50<<3)|2 = 402 = varint 0x92 0x03.
	uuid := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	buf := []byte{0x92, 0x03, 0x04} // tag + length 4
	buf = append(buf, uuid...)

	got := extractRoutableRequestUUID(buf)
	if !bytes.Equal(got, uuid) {
		t.Fatalf("extractRoutableRequestUUID = %x, want %x", got, uuid)
	}
}

func TestExtractRoutableUUID_SkipsOtherFields(t *testing.T) {
	// Realistic-ish frame: to_destination (field 6 LEN), from_destination
	// (field 7 LEN), flags (field 52 VARINT), THEN uuid (field 51 LEN).
	// Verifies that the scanner steps past unrelated fields of all
	// three wire types (LEN, VARINT) without recursing into them.
	uuid := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := []byte{}
	// to_destination = { domain: 3 }
	buf = append(buf, 0x32, 0x02, 0x08, 0x03)
	// from_destination = { routing_address: 4 bytes of 0xAB }
	buf = append(buf, 0x3A, 0x06, 0x12, 0x04, 0xAB, 0xAB, 0xAB, 0xAB)
	// flags (field 52 = (52<<3)|0 = 416 = 0xA0 0x03) = 2
	buf = append(buf, 0xA0, 0x03, 0x02)
	// uuid (field 51 LEN)
	buf = append(buf, 0x9A, 0x03, 0x04)
	buf = append(buf, uuid...)

	got := extractRoutableUUID(buf)
	if !bytes.Equal(got, uuid) {
		t.Fatalf("extractRoutableUUID = %x, want %x", got, uuid)
	}
}

func TestExtractRoutableUUID_Absent(t *testing.T) {
	// SessionInfoRequest path: no uuid field present.
	buf := []byte{0x32, 0x02, 0x08, 0x03} // just to_destination
	if got := extractRoutableUUID(buf); got != nil {
		t.Fatalf("extractRoutableUUID = %x, want nil", got)
	}
}

func TestExtractRoutableRequestUUID_OnBroadcastFrame(t *testing.T) {
	// VCSEC unsolicited broadcast — no request_uuid. The scanner
	// must NOT misidentify any other field as request_uuid.
	// Frame from a real diagnostic capture (VCSEC CommandStatus
	// broadcast), truncated for the test.
	buf := []byte{
		0x32, 0x02, 0x08, 0x00, // to_destination = BROADCAST
		0x3A, 0x02, 0x08, 0x02, // from_destination = VCSEC
		0x52, 0x1F, // protobuf_message_as_bytes, LEN 31
		// 31 bytes of opaque payload — must NOT be parsed as
		// containing request_uuid (which is a top-level field).
		0x1A, 0x1D, 0x12, 0x16, 0x0A, 0x14,
		0xE1, 0x53, 0xE0, 0x1A, 0x35, 0x90, 0xBA, 0xE1, 0xFA, 0x20,
		0xBB, 0xAD, 0x29, 0x9F, 0x52, 0x6C, 0xBD, 0x7D, 0x2D, 0x24,
		0x18, 0x02, 0x22, 0x01, 0x01,
	}
	if got := extractRoutableRequestUUID(buf); got != nil {
		t.Fatalf("extractRoutableRequestUUID = %x, want nil (no request_uuid in broadcast)", got)
	}
}

func TestExtractRoutableUUID_TruncatedBuffer(t *testing.T) {
	// Tag claims 16 bytes but only 4 follow — must return nil, not
	// read past the buffer.
	buf := []byte{0x9A, 0x03, 0x10, 0x01, 0x02, 0x03, 0x04}
	if got := extractRoutableUUID(buf); got != nil {
		t.Fatalf("extractRoutableUUID on truncated buf = %x, want nil", got)
	}
}

func TestExtractRoutableFromRoutingAddress(t *testing.T) {
	// RoutableMessage with from_destination = { routing_address: 16 bytes }.
	// fromDestination = field 7 LEN (tag 0x3A), length 18 (= 2-byte
	// inner tag/len + 16 payload bytes).
	// Inside: field 2 LEN (tag 0x12), length 16.
	addr := []byte{
		0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
		0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
	}
	buf := []byte{
		0x32, 0x02, 0x08, 0x03, // to_destination = {domain: 3}
		0x3A, 0x12, // fromDestination, LEN 18
		0x12, 0x10, // routing_address, LEN 16
	}
	buf = append(buf, addr...)
	buf = append(buf, 0x9A, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF) // + uuid

	got := extractRoutableFromRoutingAddress(buf)
	if !bytes.Equal(got, addr) {
		t.Fatalf("extractRoutableFromRoutingAddress = %x, want %x", got, addr)
	}
}

func TestExtractRoutableFromRoutingAddress_DomainVariant(t *testing.T) {
	// from_destination = { domain: 2 } — routing_address absent.
	// Wire: 0x3A 0x02 0x08 0x02. Scanner should return nil since
	// the inner Destination oneof selected `domain` (field 1),
	// not `routing_address` (field 2).
	buf := []byte{0x3A, 0x02, 0x08, 0x02}
	if got := extractRoutableFromRoutingAddress(buf); got != nil {
		t.Fatalf("extractRoutableFromRoutingAddress = %x, want nil", got)
	}
}

func TestExtractRoutableToRoutingAddress(t *testing.T) {
	// Response frame: to_destination = { routing_address: 16 bytes },
	// from_destination = { domain: 2 (VCSEC) }.
	addr := []byte{
		0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
		0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
	}
	buf := []byte{
		0x32, 0x12, // to_destination, LEN 18
		0x12, 0x10, // routing_address, LEN 16
	}
	buf = append(buf, addr...)
	buf = append(buf, 0x3A, 0x02, 0x08, 0x02) // from_destination = {domain: 2}

	got := extractRoutableToRoutingAddress(buf)
	if !bytes.Equal(got, addr) {
		t.Fatalf("extractRoutableToRoutingAddress = %x, want %x", got, addr)
	}
}

func TestExtractRoutableToRoutingAddress_BroadcastFrame(t *testing.T) {
	// The exact VCSEC broadcast we saw in production: to=BROADCAST
	// (domain:0), from=VCSEC (domain:2). Neither destination has a
	// routing_address, so extractor must return nil — letting the
	// demux loop skip the frame instead of mis-claiming it.
	buf := []byte{
		0x32, 0x02, 0x08, 0x00, // to_destination = BROADCAST
		0x3A, 0x02, 0x08, 0x02, // from_destination = VCSEC
		0x52, 0x1F, // protobuf_message_as_bytes, LEN 31
		0x1A, 0x1D, 0x12, 0x16, 0x0A, 0x14,
		0xE1, 0x53, 0xE0, 0x1A, 0x35, 0x90, 0xBA, 0xE1, 0xFA, 0x20,
		0xBB, 0xAD, 0x29, 0x9F, 0x52, 0x6C, 0xBD, 0x7D, 0x2D, 0x24,
		0x18, 0x02, 0x22, 0x01, 0x01,
	}
	if got := extractRoutableToRoutingAddress(buf); got != nil {
		t.Fatalf("extractRoutableToRoutingAddress on BROADCAST = %x, want nil", got)
	}
}

func TestReadVarint(t *testing.T) {
	cases := []struct {
		in     []byte
		val    uint64
		consum int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x01}, 1, 1},
		{[]byte{0x7F}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0x9A, 0x03}, 410, 2},   // field 51 LEN tag
		{[]byte{0x92, 0x03}, 402, 2},   // field 50 LEN tag
		{[]byte{0xFF, 0xFF, 0x03}, 65535, 3},
		{[]byte{0x80}, 0, 0}, // truncated continuation
		{[]byte{}, 0, 0},
	}
	for _, c := range cases {
		v, n := readVarint(c.in)
		if v != c.val || n != c.consum {
			t.Errorf("readVarint(%x) = (%d, %d), want (%d, %d)", c.in, v, n, c.val, c.consum)
		}
	}
}
