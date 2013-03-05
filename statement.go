// Copyright 2013 Julien Schmidt. All rights reserved.
// http://www.julienschmidt.com
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package sphinxql

import (
	"database/sql/driver"
)

type sphinxqlStmt struct {
	mc    *sphinxqlConn
	query string
}

func (stmt *sphinxqlStmt) Close() (err error) {
	stmt.mc = nil
	return
}

func (stmt *sphinxqlStmt) NumInput() int {
	return 0
}

func (stmt *sphinxqlStmt) Exec(args []driver.Value) (driver.Result, error) {
	return stmt.mc.Exec(stmt.query, args)
}

func (stmt *sphinxqlStmt) Query(args []driver.Value) (driver.Rows, error) {
	return stmt.mc.Query(stmt.query, args)
}
