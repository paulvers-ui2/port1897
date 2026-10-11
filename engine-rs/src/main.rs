// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! fswin-rs: the Rust engine, in progress (see PLAN.md). It reads fswin's
//! command line, and for now refuses to start the tunnel: the parts that
//! change the system are not done, and a half engine must not run in place
//! of the Go one.

use std::process::ExitCode;

use fswin_rs::flags::{self, FlagError};

/// The build, set at compile time: FSWIN_VERSION=<commit> cargo build.
const VERSION: &str = match option_env!("FSWIN_VERSION") {
    Some(v) => v,
    None => "dev",
};

fn main() -> ExitCode {
    let mut argv = std::env::args_os().map(|a| a.to_string_lossy().into_owned());
    let program = argv.next().unwrap_or_else(|| "fswin-rs".to_string());
    let args: Vec<String> = argv.collect();

    let parsed = match flags::parse(&args) {
        Ok(p) => p,
        Err(FlagError::Help) => {
            eprint!("{}", flags::usage(&program));
            return ExitCode::SUCCESS;
        }
        Err(FlagError::Invalid(msg)) => {
            // as Go's flag.ExitOnError: the reason, the usage, exit code 2
            eprintln!("{msg}");
            eprint!("{}", flags::usage(&program));
            return ExitCode::from(2);
        }
    };
    let o = parsed.opts;
    if o.show_version {
        println!("fswin-rs {VERSION}");
        return ExitCode::SUCCESS;
    }
    eprintln!("fswin-rs: not ready to run yet: the tunnel, DNS, kill switch, NRPT and service are still being written (engine-rs/PLAN.md); use fswin.exe");
    ExitCode::FAILURE
}
