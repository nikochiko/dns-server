package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type ResourceRecord struct {
	Name  string
	Type  *QTYPE
	Class *QCLASS
	TTL   uint32
	Value []byte
}

func (rr *ResourceRecord) Encode(buf []byte) (int, error) {
	nWritten, err := EncodeDomainName(buf, rr.Name)
	if err != nil {
		return nWritten, err
	}

	nWritten += copy(buf[nWritten:], rr.Type.Value)

	nWritten += copy(buf[nWritten:], rr.Class.Value)

	binary.BigEndian.PutUint32(buf[nWritten:], rr.TTL)
	nWritten += 4

	binary.BigEndian.PutUint16(buf[nWritten:], uint16(len(rr.Value)))
	nWritten += 2

	copy(buf[nWritten:], rr.Value)

	return nWritten, nil
}

// QTYPE stands for Question Type as per RFC 1035
type QTYPE struct {
	Type    string
	Value   []byte
	Meaning string
}

func (q QTYPE) String() string {
	return q.Type
}

// TypeA stands for RR type A - Host Address
var TypeA = QTYPE{
	Type:    "A",
	Value:   []byte("\x00\x01"),
	Meaning: "a host address",
}

// TypeNS stands for RR type NS - Name Server
var TypeNS = QTYPE{
	Type:    "NS",
	Value:   []byte("\x00\x02"),
	Meaning: "an authoritative name server",
}

// TypeMD stands for RR type MD - Mail Destination
var TypeMD = QTYPE{
	Type:    "MD",
	Value:   []byte("\x00\x03"),
	Meaning: "a mail destination (Obsolete - use MX)",
}

// TypeMF stands for RR type MF - Mail Forwarder
var TypeMF = QTYPE{
	Type:    "MF",
	Value:   []byte("\x00\x04"),
	Meaning: "a mail forwarder (Obsolete - use MX)",
}

// TypeCNAME stands for RR type CNAME - Canonical Name for alias
var TypeCNAME = QTYPE{
	Type:    "CNAME",
	Value:   []byte("\x00\x05"),
	Meaning: "a canonical name for an alias",
}

// TypeSOA stands for RR type SOA - Start of Authority
var TypeSOA = QTYPE{
	Type:    "SOA",
	Value:   []byte("\x00\x06"),
	Meaning: "marks the start of a zone of authority",
}

// TypeWKS stands for RR type Well Known Service
var TypeWKS = QTYPE{
	Type:    "WKS",
	Value:   []byte("\x00\x0b"),
	Meaning: "a well known service description",
}

// TypePTR stands for RR type Pointer
var TypePTR = QTYPE{
	Type:    "PTR",
	Value:   []byte("\x00\x0c"),
	Meaning: "a domain name pointer",
}

// TypeHINFO Host Info
var TypeHINFO = QTYPE{
	Type:    "HINFO",
	Value:   []byte("\x00\x0d"),
	Meaning: "host information",
}

// TypeMINFO Mail info
var TypeMINFO = QTYPE{
	Type:    "MINFO",
	Value:   []byte("\x00\x0e"),
	Meaning: "mailbox or mail list information",
}

// TypeMX = Mail Exchange Record
var TypeMX = QTYPE{
	Type:    "MX",
	Value:   []byte("\x00\x0f"),
	Meaning: "mail exchange",
}

// TypeTXT text strings
var TypeTXT = QTYPE{
	Type:    "TXT",
	Value:   []byte("\x00\x10"),
	Meaning: "text string",
}

// TypeAll = "*" type for all records
var TypeAll = QTYPE{
	Type:    "*",
	Value:   []byte("\x00\xff"),
	Meaning: "a request for all records",
}

var uintToQtypeMap = map[uint16]*QTYPE{
	1:   &TypeA,
	2:   &TypeNS,
	3:   &TypeMD,
	4:   &TypeMF,
	5:   &TypeCNAME,
	6:   &TypeSOA,
	11:  &TypeWKS,
	12:  &TypePTR,
	13:  &TypeHINFO,
	14:  &TypeMINFO,
	15:  &TypeMX,
	16:  &TypeTXT,
	255: &TypeAll,
}

func bytesToQtype(b []byte) (*QTYPE, error) {
	if len(b) != 2 {
		return nil, errors.New("argument must be 2 octet long")
	}

	code := binary.BigEndian.Uint16(b)
	qtype, ok := uintToQtypeMap[code]
	if !ok {
		return nil, fmt.Errorf("unrecognized code: %d", code)
	}

	return qtype, nil
}

type QCLASS struct {
	Class   string
	Value   []byte
	Meaning string
}

func (q QCLASS) String() string {
	return q.Class
}

var ClassIN = QCLASS{
	Class:   "IN",
	Value:   []byte("\x00\x01"),
	Meaning: "The Internet!",
}

func bytesToClass(b []byte) (*QCLASS, error) {
	if len(b) != 2 {
		return nil, errors.New("argument must be 2 octet long")
	}

	code := binary.BigEndian.Uint16(b)
	if code != 1 {
		return nil, fmt.Errorf("unsupported/unrecognized class code: %d", code)
	}

	// support only 1 class i.e. IN
	return &ClassIN, nil
}

func EncodeDomainName(buf []byte, name string) (int, error) {
	if len(name) > 255 {
		return 0, errors.New("domain name cannot be longer than 255 characters")
	}

	if len(buf) < (len(name) + 2) {
		// maybe later, write as many bytes as possible?
		return 0, errors.New("buffer too small")
	}

	labels := strings.Split(name, ".")

	written := 0
	for _, label := range labels {
		if len(label) > 63 {
			return written, errors.New("label cannot be longer than 63 characters")
		}
		buf[written] = byte(len(label))
		written++

		written += copy(buf[written:written+len(label)], label)
	}

	buf[written] = byte(0)
	written++

	return written, nil
}

func EncodeSOA(mname, rname string, serial, refresh, retry, expire, minimum uint32) ([]byte, error) {
	// number of octets in output = (len(mname) + 2) + (len(rname) + 2) + (32/8) * 5
	outputLength := len(mname) + len(rname) + 24

	buf := make([]byte, outputLength)

	// write mname
	written := 0
	moreWritten, err := EncodeDomainName(buf[written:], mname)
	if err != nil {
		return nil, err
	}
	written += moreWritten

	// write rname
	moreWritten, err = EncodeDomainName(buf[written:], rname)
	if err != nil {
		return nil, err
	}
	written += moreWritten

	// write serial
	binary.BigEndian.PutUint32(buf[written:], serial)
	written += 4

	// write refresh
	binary.BigEndian.PutUint32(buf[written:], refresh)
	written += 4

	// write retry
	binary.BigEndian.PutUint32(buf[written:], retry)
	written += 4

	// write expire
	binary.BigEndian.PutUint32(buf[written:], expire)
	written += 4

	// write minimum
	binary.BigEndian.PutUint32(buf[written:], minimum)
	written += 4

	return buf, nil
}
