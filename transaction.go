// Copyright 2013 Julien Schmidt. All rights reserved.
// http://www.julienschmidt.com
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package sphinxql

type sphinxqlTx struct {
	mc *sphinxqlConn
}

func (tx *sphinxqlTx) Commit() (err error) {
	err = tx.mc.exec("COMMIT")
	tx.mc = nil
	return
}

func (tx *sphinxqlTx) Rollback() (err error) {
	err = tx.mc.exec("ROLLBACK")
	tx.mc = nil
	return
}
