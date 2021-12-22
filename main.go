package main

import (
	"fmt"

	"github.com/nikochiko/dns-server/server"
)

func main() {
	h := server.DNSHeader{
		ID:               42,
		Type:             server.QRQuery,
		OpCode:           server.QueryOp,
		RecursionDesired: true,
		QuestionsCount:   1,
	}

	// expectedEncoded := []byte{0x00, 0x2a, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	buf := make([]byte, 12)
	h.Encode(buf)

	fmt.Printf("Buf: %v\n", buf)

	// for i := 0; i < 12; i++ {
	// 	if buf[i] != expectedEncoded[i] {
	// 		t.Errorf("buf not equal to expected. %d != %d", buf[i], expectedEncoded[i])
	// 	}
	// }
}
