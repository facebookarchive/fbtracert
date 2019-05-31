/**
 * Copyright (c) 2016-present, Facebook, Inc. and its affiliates.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

package main

import (
	"bytes"
	"encoding/binary"
	"net"
)

//
// TCP flags
//
const (
	FIN = 1 << 0
	SYN = 1 << 1
	RST = 1 << 2
	PSH = 1 << 3
	ACK = 1 << 4
	URG = 1 << 5
)

// TCPHeader defines the TCP header struct
type TCPHeader struct {
	Source      uint16
	Destination uint16
	SeqNum      uint32
	AckNum      uint32
	DataOffset  uint8 // 4 bits
	Reserved    uint8 // 6 bits
	Flags       uint8 // 6 bits
	Window      uint16
	Checksum    uint16
	Urgent      uint16
}

//
// create & serialize a TCP header, compute and fill in the checksum (v4/v6)
//
func makeTCPHeader(af string, srcAddr, dstAddr net.IP, srcPort, dstPort int, ts uint32) []byte {
	tcpHeader := TCPHeader{
		Source:      uint16(srcPort), // Random ephemeral port
		Destination: uint16(dstPort),
		SeqNum:      ts,
		AckNum:      0,
		DataOffset:  5,      // 4 bits
		Reserved:    0,      // 6 bits
		Flags:       SYN,    // 6 bits (000010, SYN bit set)
		Window:      0xffff, // max window
		Checksum:    0,
		Urgent:      0,
	}

	// temporary bytes for checksum
	bytes := tcpHeader.Serialize()
	tcpHeader.Checksum = tcpChecksum(af, bytes, srcAddr, dstAddr)

	return tcpHeader.Serialize()
}

// Parse packet into TCPHeader structure
func parseTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader

	r := bytes.NewReader(data)

	binary.Read(r, binary.BigEndian, &tcp.Source)
	binary.Read(r, binary.BigEndian, &tcp.Destination)
	binary.Read(r, binary.BigEndian, &tcp.SeqNum)
	binary.Read(r, binary.BigEndian, &tcp.AckNum)

	// read the flags from a 16-bit field
	var field uint16

	binary.Read(r, binary.BigEndian, &field)
	// most significant 4 bits
	tcp.DataOffset = byte(field >> 12)
	// reserved part - 6 bits
	tcp.Reserved = byte(field >> 6 & 0x3f)
	// flags - 6 bits
	tcp.Flags = byte(field & 0x3f)

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)

	return &tcp
}

// Serialize emits raw bytes for the header
func (tcp *TCPHeader) Serialize() []byte {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.Source)
	binary.Write(buf, binary.BigEndian, tcp.Destination)
	binary.Write(buf, binary.BigEndian, tcp.SeqNum)
	binary.Write(buf, binary.BigEndian, tcp.AckNum)

	var mix uint16
	mix = uint16(tcp.DataOffset)<<12 |
		uint16(tcp.Reserved&0x3f)<<9 |
		uint16(tcp.Flags&0x3f)
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	out := buf.Bytes()

	return out
}

//
// TCP Checksum, works for both v4 and v6 IP addresses
//
func tcpChecksum(af string, data []byte, srcip, dstip net.IP) uint16 {

	// the pseudo header used for TCP c-sum computation
	var pseudoHeader []byte

	pseudoHeader = append(pseudoHeader, srcip...)
	pseudoHeader = append(pseudoHeader, dstip...)
	switch {
	case af == "ip4":
		pseudoHeader = append(pseudoHeader, []byte{
			0,
			6,                  // protocol number for TCP
			0, byte(len(data)), // TCP length (16 bits), w/o pseudoheader
		}...)
	case af == "ip6":
		pseudoHeader = append(pseudoHeader, []byte{
			0, 0, 0, byte(len(data)), // TCP length (32 bits), w/0 pseudoheader
			0, 0, 0,
			6, // protocol number for TCP
		}...)
	}

	body := make([]byte, 0, len(pseudoHeader)+len(data))
	body = append(body, pseudoHeader...)
	body = append(body, data...)

	bodyLen := len(body)

	var word uint16
	var csum uint32

	for i := 0; i+1 < bodyLen; i += 2 {
		word = uint16(body[i])<<8 | uint16(body[i+1])
		csum += uint32(word)
	}

	if bodyLen%2 != 0 {
		csum += uint32(body[len(body)-1])
	}

	csum = (csum >> 16) + (csum & 0xffff)
	csum = csum + (csum >> 16)

	return uint16(^csum)
}
