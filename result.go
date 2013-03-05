// Copyright 2013 Julien Schmidt. All rights reserved.
// http://www.julienschmidt.com
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package sphinxql

type sphinxqlResult struct {
	affectedRows int64
	insertId     int64
}

func (res *sphinxqlResult) LastInsertId() (int64, error) {
	return res.insertId, nil
}

func (res *sphinxqlResult) RowsAffected() (int64, error) {
	return res.affectedRows, nil
}
