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
