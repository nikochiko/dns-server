package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
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
	NoError        ResponseCode = 0
	FormatError    ResponseCode = 1
	ServerFailure  ResponseCode = 2
	NameError      ResponseCode = 3
	NotImplemented ResponseCode = 4
	Refused        ResponseCode = 5
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

type Question struct {
	Name  string
	Type  *QTYPE
	Class *QCLASS
}

func (q *Question) Encode(buf []byte) (int, error) {
	wlen, err := EncodeDomainName(buf, q.Name)
	if err != nil {
		return wlen, fmt.Errorf("error while encoding domain name: %v", err)
	}

	wlen += copy(buf[wlen:], q.Type.Value)

	wlen += copy(buf[wlen:], q.Class.Value)

	return wlen, nil
}

func (q Question) String() string {
	return fmt.Sprintf(`<Question Name: "%s", Type: "%s", Class: "%s"`, q.Name, q.Type, q.Class)
}

func ReadQuestionFrom(buf []byte) (int, *Question, error) {
	bytesRead, name, err := DecodeDomainName(buf)
	if err != nil {
		return bytesRead, nil, err
	}

	qtype, err := bytesToQtype(buf[bytesRead : bytesRead+2])
	if err != nil {
		return bytesRead, nil, err
	}
	bytesRead += 2

	qclass, err := bytesToClass(buf[bytesRead : bytesRead+2])
	if err != nil {
		return bytesRead, nil, err
	}
	bytesRead += 2

	q := Question{
		Name:  name,
		Type:  qtype,
		Class: qclass,
	}

	return bytesRead, &q, nil
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

	headerBits |= uint16(h.ResponseCode) & (uint16(1)<<3 | uint16(1)<<2 | uint16(1)<<1 | uint16(1))

	binary.BigEndian.PutUint16(buf, headerBits)
}

func (h DNSHeader) Encode(buf []byte) (int, error) {
	// make the number of bytes return in output dynamic

	binary.BigEndian.PutUint16(buf[:2], h.ID)
	h.encodeHeaderBits(buf[2:4])
	binary.BigEndian.PutUint16(buf[4:6], h.QuestionsCount)
	binary.BigEndian.PutUint16(buf[6:8], h.AnswersCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NameserversCount)
	binary.BigEndian.PutUint16(buf[10:12], h.AdditionalRecordsCount)

	return 12, nil
}

func NewDNSServer(laddr string, recordsFile string) (*DNSServer, error) {
	records := []*ResourceRecord{}

	// TODO: read recordsFile
	if recordsFile == "" {
		soa, _ := EncodeSOA("kausm.in", "kaustubh.kausm.in", 1, 600, 600, 600, 600)
		soaRecord := ResourceRecord{
			Type:  &TypeSOA,
			Name:  "kausm.in",
			Class: &ClassIN,
			TTL:   600,
			Value: soa,
		}
		record1 := ResourceRecord{
			Type:  &TypeA,
			Name:  "test.kausm.in",
			Class: &ClassIN,
			TTL:   600,
			Value: []byte{134, 209, 148, 50},
		}
		records = append(records, &record1, &soaRecord)
	}

	srv := DNSServer{
		laddr:   laddr,
		records: records,
	}

	return &srv, nil
}

func (srv *DNSServer) Listen() error {
	laddr, err := net.ResolveUDPAddr("udp", srv.laddr)
	if err != nil {
		return fmt.Errorf("error while resolving given listen addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("error while listening for udp: %v", err)
	}

	for {
		input := make([]byte, 512)
		rlen, returnAddr, err := conn.ReadFromUDP(input)
		if err != nil {
			log.Printf("Error: %v\n", err)
		}

		go srv.handleUDPPacket(conn, input[:rlen], returnAddr)
	}
}

func (srv *DNSServer) LookupRecords(recordType *QTYPE, recordClass *QCLASS, name string) *ResourceRecord {
	for _, r := range srv.records {
		if r.Type == recordType && r.Class == recordClass && strings.ToLower(r.Name) == strings.ToLower(name) {
			return r
		}
	}

	return nil
}

func (srv DNSServer) setDefaultResponseHeaders(h *DNSHeader) {
	h.Type = QRResponse
	h.RecursionAvailable = false
	h.IsTruncated = false
	h.IsAuthoritative = false
}

func (srv *DNSServer) handleUDPPacket(conn *net.UDPConn, buf []byte, returnAddr *net.UDPAddr) {
	log.Printf("got packet from %s\n", returnAddr.String())

	rlen := 0

	headers := DNSHeader{}
	err := headers.ReadFrom(buf)
	if err != nil {
		log.Printf("error while reading header: %v", err)
		return
	}

	rlen += 12

	srv.setDefaultResponseHeaders(&headers)

	if headers.Type != QRQuery || headers.OpCode != QueryOp {
		log.Printf("not implemented")

		// only support standard query for now
		headers.ResponseCode = NotImplemented
		headers.AnswersCount = 0

		err := srv.RespondToUDP(conn, returnAddr, &headers, nil, nil, nil, nil)
		if err != nil {
			log.Printf("error while responding: %v", err)
			return
		}

		return
	}

	questions := []*Question{}
	answers := []*ResourceRecord{}
	nameservers := []*ResourceRecord{}
	additionals := []*ResourceRecord{}

	for qi := uint16(0); qi < headers.QuestionsCount; qi++ {
		bytesRead, q, err := ReadQuestionFrom(buf[rlen:])
		rlen += bytesRead
		if err != nil {
			log.Printf("error while reading question %d: %v", qi+1, err)
			return
		}

		questions = append(questions, q)

		answersi, nameserversi, additionalsi, isAuthoritative := srv.GetAnswers(q)
		headers.IsAuthoritative = isAuthoritative

		if isAuthoritative && len(answersi) == 0 {
			headers.ResponseCode = NameError
		}

		answers = append(answers, answersi...)
		nameservers = append(nameservers, nameserversi...)
		additionals = append(additionals, additionalsi...)
	}

	srv.RespondToUDP(conn, returnAddr, &headers, questions, answers, nameservers, additionals)

	return
}

func (srv *DNSServer) GetAnswers(q *Question) ([]*ResourceRecord, []*ResourceRecord, []*ResourceRecord, bool) {
	log.Printf("getting answer for question: %s", q.String())

	isAuthoritative := strings.HasSuffix(strings.ToLower(q.Name), "kausm.in")
	answer := srv.LookupRecords(q.Type, q.Class, q.Name)

	var answers []*ResourceRecord
	if answer != nil {
		answers = append(answers, answer)
	}

	return answers, nil, nil, isAuthoritative
}

func (srv *DNSServer) RespondToUDP(conn *net.UDPConn, returnAddr *net.UDPAddr, headers *DNSHeader, questions []*Question, answers []*ResourceRecord, nameservers []*ResourceRecord, additionalRecords []*ResourceRecord) error {
	headers.QuestionsCount = uint16(len(questions))
	headers.AnswersCount = uint16(len(answers))
	headers.NameserversCount = uint16(len(nameservers))
	headers.AdditionalRecordsCount = uint16(len(additionalRecords))

	buf := make([]byte, 512)

	bytesWritten, err := headers.Encode(buf)
	if err != nil {
		return err
	}

	for _, q := range questions {
		n, err := q.Encode(buf[bytesWritten:])
		if err != nil {
			return err
		}

		bytesWritten += n
	}

	for _, rr := range answers {
		n, err := rr.Encode(buf[bytesWritten:])
		if err != nil {
			return err
		}

		bytesWritten += n
	}

	for _, rr := range nameservers {
		n, err := rr.Encode(buf[bytesWritten:])
		if err != nil {
			return err
		}

		bytesWritten += n
	}

	for _, rr := range additionalRecords {
		n, err := rr.Encode(buf[bytesWritten:])
		if err != nil {
			return err
		}

		bytesWritten += n
	}

	log.Printf("writing to return addr: %s, bytes: %d", returnAddr.String(), bytesWritten)
	_, err = conn.WriteTo(buf[:bytesWritten], returnAddr)
	if err != nil {
		return fmt.Errorf("error while writing to conn: %v", err)
	}

	return nil
}
