package server

import (
	"testing"
)

func TestEncodeDomainName(t *testing.T) {
	domainName := "kausm.in"
	expected := []byte("\x05kausm\x02in\x00")

	buf := make([]byte, 512)

	n, err := EncodeDomainName(buf, domainName)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	encoded := buf[:n]

	if len(expected) != len(encoded) {
		t.Errorf("len expected and gotten are not same")
		return
	}

	if string(encoded) != string(expected) {
		t.Errorf("gotten (%+q) not equal to expected (%+q)", encoded, expected)
		return
	}
}

func TestEncodeRR(t *testing.T) {
	rr := ResourceRecord{
		Name: "testing.kausm.in",
		Type: &TypeA,
		Class: &ClassIN,
		TTL: 4200,
		Value: []byte{42, 69, 255, 1},
	}

	expectedBuf := []byte("\x07testing\x05kausm\x02in\x00\x00\x01\x00\x01\x00\x00\x10\x68\x00\x04\x2a\x45\xff\x01")
	expectedLen := len(expectedBuf)

	buf := make([]byte, 512)
	rlen, err := rr.Encode(buf)
	if err != nil {
		t.Errorf("error while encoding RR: %v", err)
		return
	}

	if rlen != expectedLen {
		t.Errorf("lengths don't match up: gotten %d != %d expected", rlen, expectedLen)
	}

	if string(buf[:rlen]) != string(expectedBuf) {
		t.Errorf("gotten encoded RR (%q) not equal to expected encoded RR (%q)", buf[:rlen], expectedBuf)
		return
	}
}
