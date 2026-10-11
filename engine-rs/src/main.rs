// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! fswin-rs: the Rust engine, run with fswin.exe's command line (see
//! PLAN.md for what it does so far). Flags it cannot serve yet are refused
//! before it changes anything (run::check_supported), so the app shows why.

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
        println!("fswin {VERSION}");
        return ExitCode::SUCCESS;
    }
    engine(o)
}

#[cfg(not(windows))]
fn engine(_o: flags::Options) -> ExitCode {
    eprintln!("fswin: Windows only");
    ExitCode::FAILURE
}

#[cfg(windows)]
fn engine(o: flags::Options) -> ExitCode {
    use std::sync::Arc;

    use fswin_rs::run::{self, StopReason};
    use fswin_rs::win;
    use tokio::sync::watch;

    if !o.service.is_empty() {
        eprintln!("fswin: -service: AuroraVPN Service is not part of this engine yet (fswin-rs); use fswin.exe");
        return ExitCode::FAILURE;
    }
    if o.user_token != 0 {
        eprintln!("fswin: -user-token is not supported by this engine yet (fswin-rs); use fswin.exe");
        return ExitCode::FAILURE;
    }
    if !o.log_file.is_empty()
        && let Err(e) = win::stdio::redirect_output(&o.log_file)
    {
        eprintln!("fswin: -logfile: {e}");
        return ExitCode::FAILURE;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fswin: {e}");
            return ExitCode::FAILURE;
        }
    };
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_string_lossy().into_owned())).unwrap_or_default();
    let sys: Arc<dyn run::Sys> = Arc::new(win::sys::WinSys::new(&dir, Box::new(|p| std::fs::read(p).map_err(|e| format!("open {p}: {e}")))));
    let stop_tx = Arc::new(watch::channel(None).0);
    // AuroraVPN Service asks the engine it started to stop with an event
    if o.stop_handle != 0 {
        let tx = stop_tx.clone();
        let h = o.stop_handle;
        std::thread::spawn(move || {
            if win::stdio::wait_event(h) {
                run::request_stop(&tx, StopReason::Service);
            }
        });
    }
    let r = rt.block_on(async {
        let tx = stop_tx.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                run::request_stop(&tx, StopReason::CtrlC);
            }
        });
        run::run(o, sys, VERSION, stop_tx).await
    });
    // connections still copying must not hold the exit up
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fswin: {e}");
            ExitCode::FAILURE
        }
    }
}
