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
	"io"
)

type sphinxqlField struct {
	name      string
	fieldType byte
	flags     FieldFlag
}

type sphinxqlRows struct {
	mc      *sphinxqlConn
	columns []sphinxqlField
	eof     bool
}

func (rows *sphinxqlRows) Columns() (columns []string) {
	columns = make([]string, len(rows.columns))
	for i := range columns {
		columns[i] = rows.columns[i].name
	}
	return
}

func (rows *sphinxqlRows) Close() (err error) {
	defer func() {
		rows.mc = nil
	}()

	// Remove unread packets from stream
	if !rows.eof {
		if rows.mc == nil {
			return errors.New("Invalid Connection")
		}

		err = rows.mc.readUntilEOF()
	}

	return
}

func (rows *sphinxqlRows) Next(dest []driver.Value) error {
	if rows.eof {
		return io.EOF
	}

	if rows.mc == nil {
		return errors.New("Invalid Connection")
	}

	// Fetch next row from stream
	err := rows.readRow(dest)

	if err == io.EOF {
		rows.eof = true
	}
	return err
}
