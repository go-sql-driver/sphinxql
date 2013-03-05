// Copyright 2013 Julien Schmidt. All rights reserved.
// http://www.julienschmidt.com
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

// Go SphinxQL Driver - A SphinxQL-Driver for Go's database/sql package
package sphinxql

import (
	"database/sql"
	"database/sql/driver"
	"net"
	"time"
)

type sphinxqlDriver struct{}

// Open new Connection.
// See https://github.com/Go-SQL-Driver/SphinxQL#dsn-data-source-name for how
// the DSN string is formated
func (d *sphinxqlDriver) Open(dsn string) (driver.Conn, error) {
	var err error

	// New sphinxqlConn
	mc := new(sphinxqlConn)
	mc.cfg = parseDSN(dsn)

	// Connect to Server
	if _, ok := mc.cfg.params["timeout"]; ok { // with timeout
		var timeout time.Duration
		timeout, err = time.ParseDuration(mc.cfg.params["timeout"])
		if err == nil {
			mc.netConn, err = net.DialTimeout(mc.cfg.net, mc.cfg.addr, timeout)
		}
	} else { // no timeout
		mc.netConn, err = net.Dial(mc.cfg.net, mc.cfg.addr)
	}
	if err != nil {
		return nil, err
	}
	mc.buf = newBuffer(mc.netConn)

	// Reading Handshake Initialization Packet
	err = mc.readInitPacket()
	if err != nil {
		return nil, err
	}

	// Send Client Authentication Packet
	err = mc.writeAuthPacket()
	if err != nil {
		return nil, err
	}

	// Read Result Packet
	err = mc.readResultOK()
	if err != nil {
		return nil, err
	}

	// Handle DSN Params
	err = mc.handleParams()
	if err != nil {
		return nil, err
	}

	return mc, err
}

func init() {
	sql.Register("sphinxql", &sphinxqlDriver{})
}
