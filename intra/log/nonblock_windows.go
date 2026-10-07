// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package log

import "os"

// setNonblock is a no-op on Windows: files and pipes have no O_NONBLOCK.
func setNonblock(*os.File) error {
	return nil
}
