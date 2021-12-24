package server

import "testing"

func TestDNSHeaderEncodeQuery(t *testing.T) {
	h := DNSHeader{
		ID:               42,
		Type:             QRQuery,
		OpCode:           QueryOp,
		RecursionDesired: true,
		QuestionsCount:   1,
	}
	expected := []byte{0x00, 0x2a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// 0000 0001 0000 0000
	// .
	//  ...
	//      .
	//       .
	//        .
	//           .
	buf := make([]byte, 12)
	h.Encode(buf)

	t.Logf("buf: %v\n", buf)
	t.Logf("expected: %v\n", expected)

	for i := 0; i < 12; i++ {
		if buf[i] != expected[i] {
			t.Errorf("buf not equal to expected. %d != %d", buf[i], expected[i])
		}
	}
}

func TestDNSHeaderReadFrom(t *testing.T) {
	expected := DNSHeader{
		ID:               42,
		Type:             QRQuery,
		OpCode:           QueryOp,
		RecursionDesired: true,
		QuestionsCount:   1,
	}

	encoded := []byte{0x00, 0x2a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	h := DNSHeader{}
	h.ReadFrom(encoded)

	if h != expected {
		t.Errorf("expected and gotten DNSHeader are not equal.\ngotten: %v\nexpected: %v\n", h, expected)
	}
}

func TestDNSHeaderEncodeResponse(t *testing.T) {
	h := DNSHeader{
		ID:               42,
		Type:             QRResponse,
		OpCode:           IQueryOp,
		RecursionDesired: true,
		QuestionsCount:   1,
	}
	expected := []byte{0x00, 0x2a, 0x89, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// 0000 0001 0000 0000
	// .
	//  ...
	//      .
	//       .
	//        .
	//           .

	buf := make([]byte, 12)
	h.Encode(buf)

	t.Logf("buf: %v\n", buf)
	t.Logf("expected: %v\n", expected)

	for i := 0; i < 12; i++ {
		if buf[i] != expected[i] {
			t.Errorf("buf not equal to expected. %d != %d", buf[i], expected[i])
		}
	}
}

func TestDNSHeaderEncodeResponseNotImplemented(t *testing.T) {
	h := DNSHeader{
		ID:               42,
		Type:             QRResponse,
		OpCode:           IQueryOp,
		ResponseCode:     NotImplemented,
		RecursionDesired: true,
		QuestionsCount:   1,
	}
	expected := []byte{0x00, 0x2a, 0x89, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// 0000 0001 0000 0000
	// .
	//  ...
	//      .
	//       .
	//        .
	//           .

	buf := make([]byte, 12)
	h.Encode(buf)

	t.Logf("buf: %v\n", buf)
	t.Logf("expected: %v\n", expected)

	for i := 0; i < 12; i++ {
		if buf[i] != expected[i] {
			t.Errorf("buf not equal to expected. %d != %d", buf[i], expected[i])
		}
	}
}
