// Copyright 2013 Julien Schmidt. All rights reserved.
// http://www.julienschmidt.com
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package sphinxql

import (
	"database/sql/driver"
	"errors"
	"net"
	"strings"
)

type sphinxqlConn struct {
	cfg          *config
	flags        ClientFlag
	charset      byte
	cipher       []byte
	netConn      net.Conn
	buf          *buffer
	protocol     uint8
	sequence     uint8
	affectedRows uint64
	insertId     uint64
}

type config struct {
	user   string
	passwd string
	net    string
	addr   string
	dbname string
	params map[string]string
}

// Handles parameters set in DSN
func (mc *sphinxqlConn) handleParams() (err error) {
	for param, val := range mc.cfg.params {
		switch param {
		// Charset
		case "charset":
			charsets := strings.Split(val, ",")
			for _, charset := range charsets {
				err = mc.exec("SET NAMES " + charset)
				if err != nil {
					return
				}
			}

		// Timeout - already handled on connecting
		case "timeout":
			continue

		// System Vars
		default:
			err = mc.exec("SET " + param + "=" + val + "")
			if err != nil {
				return
			}
		}
	}

	return
}

func (mc *sphinxqlConn) Begin() (driver.Tx, error) {
	err := mc.exec("START TRANSACTION")
	if err == nil {
		return &sphinxqlTx{mc}, err
	}

	return nil, err
}

func (mc *sphinxqlConn) Close() (err error) {
	mc.writeCommandPacket(COM_QUIT)
	mc.cfg = nil
	mc.buf = nil
	mc.netConn.Close()
	mc.netConn = nil
	return
}

func (mc *sphinxqlConn) Prepare(query string) (driver.Stmt, error) {
	return &sphinxqlStmt{
		mc:    mc,
		query: query,
	}, nil
}

func (mc *sphinxqlConn) Exec(query string, args []driver.Value) (_ driver.Result, err error) {
	if len(args) == 0 {
		mc.affectedRows = 0
		mc.insertId = 0

		err = mc.exec(query)
		if err == nil {
			return &sphinxqlResult{
				affectedRows: int64(mc.affectedRows),
				insertId:     int64(mc.insertId),
			}, err
		} else {
			return nil, err
		}

	}
	return nil, errors.New("args not supported")

}

// Internal function to execute commands
func (mc *sphinxqlConn) exec(query string) (err error) {
	// Send command
	err = mc.writeCommandPacketStr(COM_QUERY, query)
	if err != nil {
		return
	}

	// Read Result
	var resLen int
	resLen, err = mc.readResultSetHeaderPacket()
	if err == nil && resLen > 0 {
		err = mc.readUntilEOF()
		if err != nil {
			return
		}

		err = mc.readUntilEOF()
	}

	return
}

func (mc *sphinxqlConn) Query(query string, args []driver.Value) (_ driver.Rows, err error) {
	if len(args) == 0 {
		var rows *sphinxqlRows
		// Send command
		err = mc.writeCommandPacketStr(COM_QUERY, query)
		if err == nil {
			// Read Result
			var resLen int
			resLen, err = mc.readResultSetHeaderPacket()
			if err == nil {
				rows = &sphinxqlRows{mc, nil, false}

				if resLen > 0 {
					// Columns
					rows.columns, err = mc.readColumns(resLen)
				}
				return rows, err
			}
		}
		return nil, err
	}

	return nil, errors.New("args not supported")
}
