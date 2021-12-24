package main

import (
	"os"

	"github.com/nikochiko/dns-server/server"
)

func main() {
	// default listen address
	laddr := "127.0.0.1:1053"

	if len(os.Args) > 1 {
		laddr = os.Args[1]
	}

	srv, err := server.NewDNSServer(laddr, "")
	if err != nil {
		panic(err)
	}

	err = srv.Listen()
	if err != nil {
		panic(err)
	}

	// b := make([]byte, 8)
	// s := "kaustubh"
	// copy(b, s)
	// return
	// b := byte(0)
	// fmt.Println(b)

	//	h := server.DNSHeader{
	//		ID:               42,
	//		Type:             server.QRQuery,
	//		OpCode:           server.QueryOp,
	//		RecursionDesired: true,
	//		QuestionsCount:   1,
	//	}

	// expectedEncoded := []byte{0x00, 0x2a, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	//	buf := make([]byte, 12)
	//	h.Encode(buf)
	//
	//	fmt.Printf("Buf: %v\n", buf)

	// for i := 0; i < 12; i++ {
	// 	if buf[i] != expectedEncoded[i] {
	// 		t.Errorf("buf not equal to expected. %d != %d", buf[i], expectedEncoded[i])
	// 	}
	// }
}
