// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import "io"

// SetOutput sends the default logger's output to w. The logger holds the
// os.Stdout and os.Stderr of when this package initialized, so a program
// that redirects them later (fswin -logfile) must also call this.
func SetOutput(w io.Writer) {
	if l, ok := Glogger.(*simpleLogger); ok {
		l.o.SetOutput(w)
		l.e.SetOutput(w)
	}
}
