// Copyright 2013 Julien Schmidt. All rights reserved.
// http://www.julienschmidt.com
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package sphinxql

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Packets documentation:
// http://dev.mysql.com/doc/internals/en/client-server-protocol.html

// Read packet to buffer 'data'
func (mc *sphinxqlConn) readPacket() (data []byte, err error) {
	// Read packet header
	data = make([]byte, 4)
	err = mc.buf.read(data)
	if err != nil {
		errLog.Print(err.Error())
		return nil, driver.ErrBadConn
	}

	// Packet Length [24 bit]
	pktLen := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16

	if pktLen < 1 {
		errLog.Print(errMalformPkt.Error())
		return nil, driver.ErrBadConn
	}

	// Check Packet Sync [8 bit]
	if data[3] != mc.sequence {
		if data[3] > mc.sequence {
			return nil, errPktSyncMul
		} else {
			return nil, errPktSync
		}
	}
	mc.sequence++

	// Read packet body [pktLen bytes]
	data = make([]byte, pktLen)
	err = mc.buf.read(data)
	if err == nil {
		return data, nil
	}
	errLog.Print(err.Error())
	return nil, driver.ErrBadConn
}

// Write packet buffer 'data'
// The packet header must be already included
func (mc *sphinxqlConn) writePacket(data []byte) error {
	// Write packet
	n, err := mc.netConn.Write(data)
	if err == nil && n == len(data) {
		mc.sequence++
		return nil
	}

	if err == nil { // n != len(data)
		errLog.Print(errMalformPkt.Error())
	} else {
		errLog.Print(err.Error())
	}
	return driver.ErrBadConn
}

/******************************************************************************
*                           Initialisation Process                            *
******************************************************************************/

// Handshake Initialization Packet
// http://dev.mysql.com/doc/internals/en/connection-phase.html#packet-Protocol::Handshake
func (mc *sphinxqlConn) readInitPacket() (err error) {
	data, err := mc.readPacket()
	if err != nil {
		return
	}

	// protocol version [1 byte]
	if data[0] < MIN_PROTOCOL_VERSION {
		err = fmt.Errorf(
			"Unsupported MySQL Protocol Version %d. Protocol Version %d or higher is required",
			data[0],
			MIN_PROTOCOL_VERSION)
	}

	// server version [null terminated string]
	// connection id [4 bytes]
	pos := 1 + bytes.IndexByte(data[1:], 0x00) + 1 + 4

	// first part of the password cipher [8 bytes]
	mc.cipher = append(mc.cipher, data[pos:pos+8]...)

	// (filler) always 0x00 [1 byte]
	pos += 8 + 1

	// capability flags (lower 2 bytes) [2 bytes]
	mc.flags = ClientFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
	if mc.flags&CLIENT_PROTOCOL_41 == 0 {
		err = errors.New("SphinxQL-Server does not support required Protocol 41+")
	}
	pos += 2

	if len(data) > pos {
		// character set [1 byte]
		mc.charset = data[pos]

		// status flags [2 bytes]
		// capability flags (upper 2 bytes) [2 bytes]
		// length of auth-plugin-data [1 byte]
		// reserved (all [00]) [10 byte]
		pos += 1 + 2 + 2 + 1 + 10

		// second part of the password cipher [12? bytes]
		// The documentation is ambiguous about the length.
		// The official Python library uses the fixed length 12
		// which is not documented but seems to work.
		mc.cipher = append(mc.cipher, data[pos:pos+12]...)

		if data[len(data)-1] == 0 {
			return
		}
		return errMalformPkt
	}

	return
}

// Client Authentication Packet
// http://dev.mysql.com/doc/internals/en/connection-phase.html#packet-Protocol::HandshakeResponse
func (mc *sphinxqlConn) writeAuthPacket() error {
	// Adjust client flags based on server support
	clientFlags := uint32(
		CLIENT_PROTOCOL_41 |
			CLIENT_SECURE_CONN |
			CLIENT_LONG_PASSWORD |
			CLIENT_TRANSACTIONS,
	)
	if mc.flags&CLIENT_LONG_FLAG > 0 {
		clientFlags |= uint32(CLIENT_LONG_FLAG)
	}

	// User Password
	scrambleBuff := scramblePassword(mc.cipher, []byte(mc.cfg.passwd))
	mc.cipher = nil

	pktLen := 4 + 4 + 1 + 23 + len(mc.cfg.user) + 1 + 1 + len(scrambleBuff)

	// To specify a db name
	if len(mc.cfg.dbname) > 0 {
		clientFlags |= uint32(CLIENT_CONNECT_WITH_DB)
		pktLen += len(mc.cfg.dbname) + 1
	}

	// Calculate packet length and make buffer with that size
	data := make([]byte, pktLen+4)

	// Add the packet header  [24bit length + 1 byte sequence]
	data[0] = byte(pktLen)
	data[1] = byte(pktLen >> 8)
	data[2] = byte(pktLen >> 16)
	data[3] = mc.sequence

	// ClientFlags [32 bit]
	data[4] = byte(clientFlags)
	data[5] = byte(clientFlags >> 8)
	data[6] = byte(clientFlags >> 16)
	data[7] = byte(clientFlags >> 24)

	// MaxPacketSize [32 bit] (1<<24 - 1)
	data[8] = 0xff
	data[9] = 0xff
	data[10] = 0xff
	//data[11] = 0x00

	// Charset [1 byte]
	data[12] = mc.charset

	// Filler [23 byte] (all 0x00)
	pos := 13 + 23

	// User [null terminated string]
	if len(mc.cfg.user) > 0 {
		pos += copy(data[pos:], mc.cfg.user)
	}
	//data[pos] = 0x00
	pos++

	// ScrambleBuffer [length encoded integer]
	data[pos] = byte(len(scrambleBuff))
	pos += 1 + copy(data[pos+1:], scrambleBuff)

	// Databasename [null terminated string]
	if len(mc.cfg.dbname) > 0 {
		pos += copy(data[pos:], mc.cfg.dbname)
		//data[pos] = 0x00
	}

	// Send Auth packet
	return mc.writePacket(data)
}

/******************************************************************************
*                             Command Packets                                 *
******************************************************************************/

func (mc *sphinxqlConn) writeCommandPacket(command commandType) error {
	// Reset Packet Sequence
	mc.sequence = 0

	// Send CMD packet
	return mc.writePacket([]byte{
		// Add the packet header [24bit length + 1 byte sequence]
		0x05, // 5 bytes long
		0x00,
		0x00,
		mc.sequence,

		// Add command byte
		byte(command),
	})
}

func (mc *sphinxqlConn) writeCommandPacketStr(command commandType, arg string) error {
	// Reset Packet Sequence
	mc.sequence = 0

	pktLen := 1 + len(arg)
	data := make([]byte, pktLen+4)

	// Add the packet header [24bit length + 1 byte sequence]
	data[0] = byte(pktLen)
	data[1] = byte(pktLen >> 8)
	data[2] = byte(pktLen >> 16)
	data[3] = mc.sequence

	// Add command byte
	data[4] = byte(command)

	// Add arg
	copy(data[5:], arg)

	// Send CMD packet
	return mc.writePacket(data)
}

func (mc *sphinxqlConn) writeCommandPacketUint32(command commandType, arg uint32) error {
	// Reset Packet Sequence
	mc.sequence = 0

	// Send CMD packet
	return mc.writePacket([]byte{
		// Add the packet header [24bit length + 1 byte sequence]
		0x05, // 5 bytes long
		0x00,
		0x00,
		mc.sequence,

		// Add command byte
		byte(command),

		// Add arg [32 bit]
		byte(arg),
		byte(arg >> 8),
		byte(arg >> 16),
		byte(arg >> 24),
	})
}

/******************************************************************************
*                              Result Packets                                 *
******************************************************************************/

// Returns error if Packet is not an 'Result OK'-Packet
func (mc *sphinxqlConn) readResultOK() error {
	data, err := mc.readPacket()
	if err == nil {
		switch data[0] {
		// OK
		case 0:
			mc.handleOkPacket(data)
			return nil
		// EOF, someone is using old_passwords
		case 254:
			return errOldPassword
		}
		// ERROR
		return mc.handleErrorPacket(data)
	}
	return err
}

// Result Set Header Packet
// http://dev.mysql.com/doc/internals/en/text-protocol.html#packet-ProtocolText::Resultset
func (mc *sphinxqlConn) readResultSetHeaderPacket() (int, error) {
	data, err := mc.readPacket()
	if err == nil {
		if data[0] == 0 {
			mc.handleOkPacket(data)
			return 0, nil
		} else if data[0] == 255 {
			return 0, mc.handleErrorPacket(data)
		}

		// column count
		num, _, n := readLengthEncodedInteger(data)
		if n-len(data) == 0 {
			return int(num), nil
		}

		return 0, errMalformPkt
	}
	return 0, err
}

// Error Packet
// http://dev.mysql.com/doc/internals/en/overview.html#packet-ERR_Packet
func (mc *sphinxqlConn) handleErrorPacket(data []byte) error {
	if data[0] != 255 {
		return errMalformPkt
	}

	// 0xff [1 byte]

	// Error Number [16 bit uint]
	errno := binary.LittleEndian.Uint16(data[1:3])

	// SQL State [# + 5bytes string]
	//sqlstate := string(data[pos : pos+6])

	// Error Message [string]
	return fmt.Errorf("Error %d: %s", errno, string(data[9:]))
}

// Ok Packet
// http://dev.mysql.com/doc/internals/en/overview.html#packet-OK_Packet
func (mc *sphinxqlConn) handleOkPacket(data []byte) {
	var n int

	// 0x00 [1 byte]

	// Affected rows [Length Coded Binary]
	mc.affectedRows, _, n = readLengthEncodedInteger(data[1:])

	// Insert id [Length Coded Binary]
	mc.insertId, _, _ = readLengthEncodedInteger(data[1+n:])

	// server_status [2 bytes]
	// warning count [2 bytes]
	// message [until end of packet]
}

// Read Packets as Field Packets until EOF-Packet or an Error appears
// http://dev.mysql.com/doc/internals/en/text-protocol.html#packet-Protocol::ColumnDefinition41
func (mc *sphinxqlConn) readColumns(count int) (columns []sphinxqlField, err error) {
	var data []byte
	var i, pos, n int
	var name []byte

	columns = make([]sphinxqlField, count)

	for {
		data, err = mc.readPacket()
		if err != nil {
			return
		}

		// EOF Packet
		if data[0] == 254 && len(data) == 5 {
			if i != count {
				err = fmt.Errorf("ColumnsCount mismatch n:%d len:%d", count, len(columns))
			}
			return
		}

		// Catalog
		pos, err = skipLengthEnodedString(data)
		if err != nil {
			return
		}

		// Database [len coded string]
		n, err = skipLengthEnodedString(data[pos:])
		if err != nil {
			return
		}
		pos += n

		// Table [len coded string]
		n, err = skipLengthEnodedString(data[pos:])
		if err != nil {
			return
		}
		pos += n

		// Original table [len coded string]
		n, err = skipLengthEnodedString(data[pos:])
		if err != nil {
			return
		}
		pos += n

		// Name [len coded string]
		name, _, n, err = readLengthEnodedString(data[pos:])
		if err != nil {
			return
		}
		columns[i].name = string(name)
		pos += n

		// Original name [len coded string]
		n, err = skipLengthEnodedString(data[pos:])
		if err != nil {
			return
		}

		// Filler [1 byte]
		// Charset [16 bit uint]
		// Length [32 bit uint]
		pos += n + 1 + 2 + 4

		// Field type [byte]
		columns[i].fieldType = data[pos]
		pos++

		// Flags [16 bit uint]
		columns[i].flags = FieldFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
		//pos += 2

		// Decimals [8 bit uint]
		//pos++

		// Default value [len coded binary]
		//if pos < len(data) {
		//	defaultVal, _, err = bytesToLengthCodedBinary(data[pos:])
		//}

		i++
	}

	return
}

// Read Packets as Field Packets until EOF-Packet or an Error appears
// http://dev.mysql.com/doc/internals/en/text-protocol.html#packet-ProtocolText::ResultsetRow
func (rows *sphinxqlRows) readRow(dest []driver.Value) (err error) {
	data, err := rows.mc.readPacket()
	if err != nil {
		return
	}

	// EOF Packet
	if data[0] == 254 && len(data) == 5 {
		return io.EOF
	}

	// RowSet Packet
	var n int
	var isNull bool
	pos := 0

	for i := range dest {
		// Read bytes and convert to string
		dest[i], isNull, n, err = readLengthEnodedString(data[pos:])
		pos += n
		if err == nil {
			if !isNull {
				continue
			} else {
				dest[i] = nil
			}
		}
		return // err
	}

	return
}

// Reads Packets until EOF-Packet or an Error appears. Returns count of Packets read
func (mc *sphinxqlConn) readUntilEOF() (err error) {
	var data []byte

	for {
		data, err = mc.readPacket()

		// No Err and no EOF Packet
		if err == nil && (data[0] != 254 || len(data) != 5) {
			continue
		}
		return
	}
	return
}
