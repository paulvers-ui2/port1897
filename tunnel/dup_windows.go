// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package tunnel

// maybeDup returns fd as is: on Windows it is a netstack.RegisterTun id,
// which netstack takes ownership of, not an OS handle to duplicate.
func maybeDup(fd int) (int, error) {
	if fd < 0 {
		return 0, errInvalidTunFd
	}
	return fd, nil
}
