package server

import (
	"encoding/binary"
	"fmt"
	"net"
)

type (
	DNSMessageType bool
	OpCode         uint8
	ResponseCode   uint8
)

const (
	QRQuery    DNSMessageType = false
	QRResponse DNSMessageType = true
)

var messageTypeMap = map[int]DNSMessageType{
	0: QRQuery,
	1: QRResponse,
}

func GetMessageTypeFromInt(bit int) (DNSMessageType, error) {
	msgType, ok := messageTypeMap[bit]
	if !ok {
		return msgType, fmt.Errorf("invalid message type %d", bit)
	}

	return msgType, nil
}

const (
	QueryOp OpCode = iota
	IQueryOp
	StatusOp
)

var opCodeMap = map[uint8]OpCode{
	0: QueryOp,
	1: IQueryOp,
	2: StatusOp,
}

func GetOpCodeFromInt(n int) (OpCode, error) {
	opcode, ok := opCodeMap[uint8(n)]
	if !ok {
		return opcode, fmt.Errorf("invalid opcode %d", n)
	}

	return opcode, nil
}

const (
	NoError ResponseCode = iota
	FormatError
	ServerFailure
	NameError
	NotImplemented
	Refused
)

var responseCodeMap = map[uint8]ResponseCode{
	0: NoError,
	1: FormatError,
	2: ServerFailure,
	3: NameError,
	4: NotImplemented,
	5: Refused,
}

func GetResponseCodeFromInt(n int) (ResponseCode, error) {
	rcode, ok := responseCodeMap[uint8(n)]
	if !ok {
		return rcode, fmt.Errorf("invalid response code %d", n)
	}

	return rcode, nil
}

type ResourceRecord struct {
	Type  string
	Name  string
	Class string
	TTL   uint
	Value string
}

type DNSServer struct {
	laddr   string
	records []*ResourceRecord
}

type DNSHeader struct {
	ID                     uint16
	Type                   DNSMessageType
	OpCode                 OpCode // QUERY, IQUERY, STATUS, only defined when Type: "query"
	IsAuthoritative        bool   // Is responding name server an authority for the domain name in question section, only valid for responses
	IsTruncated            bool   // Was the message truncated?
	RecursionDesired       bool   // is recursion desired? set in query and may be copied into response
	RecursionAvailable     bool   // whether recursive query support is available in name server
	ResponseCode           ResponseCode
	QuestionsCount         uint16
	AnswersCount           uint16
	NameserversCount       uint16
	AdditionalRecordsCount uint16
}

func parseMsgType(headerBits uint16) DNSMessageType {
	return headerBits&(uint16(1)<<15) != 0
}

func parseOpCode(headerBits uint16) (OpCode, error) {
	// 4 bits leaving the 1st one from the left
	opcode := headerBits & ((uint16(1) << 14) | (uint16(1) << 13) | (uint16(1) << 12) | (uint16(1) << 11))
	opcode = opcode >> 11
	return GetOpCodeFromInt(int(opcode))
}

func parseAA(headerBits uint16) bool {
	return headerBits&(uint16(1)<<10) != 0
}

func parseTC(headerBits uint16) bool {
	return headerBits&(uint16(1)<<9) != 0
}

func parseRD(headerBits uint16) bool {
	return headerBits&(uint16(1)<<8) != 0
}

func parseRA(headerBits uint16) bool {
	return headerBits&(uint16(1)<<7) != 0
}

func parseRCode(headerBits uint16) (ResponseCode, error) {
	rcode := headerBits & ((uint16(1) << 3) | uint16(1)<<2 | uint16(1)<<1 | uint16(1))
	return GetResponseCodeFromInt(int(rcode))
}

func (h *DNSHeader) ReadFrom(buf []byte) (err error) {
	offset := 0
	h.ID = binary.BigEndian.Uint16(buf[offset/8:])
	offset += 16

	headerBits := binary.BigEndian.Uint16(buf[offset/8:])
	offset += 16

	h.Type = parseMsgType(headerBits)

	h.OpCode, err = parseOpCode(headerBits)
	if err != nil {
		return
	}

	h.IsAuthoritative = parseAA(headerBits)

	h.IsTruncated = parseTC(headerBits)

	h.RecursionDesired = parseRD(headerBits)

	h.RecursionAvailable = parseRA(headerBits)

	h.ResponseCode, err = parseRCode(headerBits)
	if err != nil {
		return
	}

	h.QuestionsCount = binary.BigEndian.Uint16(buf[offset/8:])
	offset += 16

	h.AnswersCount = binary.BigEndian.Uint16(buf[offset/8:])
	offset += 16

	h.NameserversCount = binary.BigEndian.Uint16(buf[offset/8:])
	offset += 16

	h.AdditionalRecordsCount = binary.BigEndian.Uint16(buf[offset/8:])
	offset += 16

	return
}

func (h DNSHeader) encodeHeaderBits(buf []byte) {
	headerBits := uint16(0)

	if h.Type == QRResponse {
		headerBits |= uint16(1) << 15
	}

	headerBits |= uint16(h.OpCode) << 11

	if h.IsAuthoritative {
		headerBits |= uint16(1) << 10
	}

	if h.IsTruncated {
		headerBits |= uint16(1) << 9
	}

	if h.RecursionDesired {
		headerBits |= uint16(1) << 8
	}

	if h.RecursionAvailable {
		headerBits |= uint16(1) << 7
	}

	headerBits |= uint16(h.ResponseCode)&(uint16(1)<<3|uint16(1)<<2|uint16(1)<<1|uint16(1))

	binary.BigEndian.PutUint16(buf, headerBits)
}

func (h DNSHeader) Encode(buf []byte) error {
	binary.BigEndian.PutUint16(buf[:2], h.ID)
	h.encodeHeaderBits(buf[2:4])
	binary.BigEndian.PutUint16(buf[4:6], h.QuestionsCount)
	binary.BigEndian.PutUint16(buf[6:8], h.AnswersCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NameserversCount)
	binary.BigEndian.PutUint16(buf[10:12], h.AdditionalRecordsCount)

	return nil
}

func NewDNSServer(laddr string, recordsFile string) (*DNSServer, error) {
	records := []*ResourceRecord{}

	// TODO: read recordsFile
	if recordsFile == "" {
		record1 := ResourceRecord{
			Type:  "A",
			Name:  "test.kausm.in",
			Class: "IN",
			TTL:   600,
			Value: "134.209.148.50",
		}
		records = append(records, &record1)
	}

	srv := DNSServer{
		laddr:   laddr,
		records: records,
	}

	return &srv, nil
}

func (srv *DNSServer) Listen() {
}

func (srv *DNSServer) LookupRecords(recordType string, recordClass string, name string) *ResourceRecord {
	for _, r := range srv.records {
		if r.Type == recordType && r.Class == recordClass && r.Name == name {
			return r
		}
	}

	return nil
}

func (srv *DNSServer) HandleConnection(conn net.UDPConn) {
}

func parseHeaders(headers []byte) (*DNSHeader, error) {
	return nil, nil
}
