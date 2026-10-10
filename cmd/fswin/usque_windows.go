// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// usque (github.com/paulvers-ui/usque, MIT) carries WARP over MASQUE. fswin
// runs it as a child process serving SOCKS5 on loopback with a random port,
// user and password per run, so other programs cannot use it to get around
// the firewall, and sends the exit traffic into it. usque's own connections
// to Cloudflare are let straight out (see bridge.bypass) so they do not loop.
//
//	masque: apps -> usque socks -> WARP (MASQUE) -> internet
//	chain:  apps -> usque chain -> WARP2 -> wg0 -> WARP1 -> internet

type usque struct {
	cmd        *exec.Cmd
	job        windows.Handle
	url        string // socks5://user:pass@127.0.0.1:port
	port       int
	user, pass string
	done       chan struct{}    // closed once the process has exited
	state      *os.ProcessState // how it exited, once done is closed
}

// usqueSetup holds what startUsque needs.
type usqueSetup struct {
	exe     string   // usque.exe
	dir     string   // where warp1.json / warp2.json live
	chainWG string   // wg-quick file for the chain's middle hop; "" for plain MASQUE
	extra   []string // more usque flags (SNI, MTU...), checked by usqueFlags
	link    int      // the network's MTU (mtu_windows.go), for -i; 0 if unknown
	logf    func(string, ...any)
}

// prepareUsque checks usque.exe and registers the WARP identities it needs,
// over the normal network, before fswin changes anything on the PC.
func prepareUsque(s usqueSetup) error {
	if _, err := os.Stat(s.exe); err != nil {
		return fmt.Errorf("usque: %w (usque.exe should sit next to fswin.exe)", err)
	}
	if err := asUser.do(func() error { return os.MkdirAll(s.dir, 0o700) }); err != nil {
		return err
	}
	if err := usqueRegister(s, filepath.Join(s.dir, "warp1.json")); err != nil {
		return err
	}
	if s.chainWG != "" {
		return usqueRegister(s, filepath.Join(s.dir, "warp2.json"))
	}
	return nil
}

// startUsque runs usque once prepareUsque has registered it, and only after
// all traffic goes to the tunnel: usque's connection to Cloudflare has to
// begin on the path it keeps, into the tunnel and out direct (see
// bridge.bypass). Begun before the routes, it went straight out, moved into
// the tunnel when they came, and went silent: no DNS and no traffic for 30 s,
// until usque gave up on it and reconnected.
func startUsque(s usqueSetup) (*usque, error) {
	return startUsqueOn(s, 0, "", "")
}

// startUsqueOn starts usque with its SOCKS proxy on port, user and pass, or
// on a free port with new credentials when port is 0. The supervisor
// (supervise_windows.go) restarts usque on the same ones, so the exit that
// points at them keeps working.
func startUsqueOn(s usqueSetup, port int, user, pass string) (*usque, error) {
	if port == 0 {
		p, err := freePort()
		if err != nil {
			return nil, err
		}
		port, user, pass = p, randHex(8), randHex(16)
	}
	args := []string{"-c", filepath.Join(s.dir, "warp1.json")}
	if s.chainWG != "" {
		args = append(args, "chain", "--wg", s.chainWG, "--exit-config", filepath.Join(s.dir, "warp2.json"))
	} else {
		args = append(args, "socks")
	}
	args = append(args, "-b", "127.0.0.1", "-p", fmt.Sprint(port), "-u", user, "-w", pass)
	args = append(args, usqueDefaults(s.chainWG != "", s.link)...)
	args = append(args, s.extra...) // after the defaults: the last of a flag wins

	// usque.exe beside fswin.exe; argv only, no shell; flags checked by usqueFlags
	cmd := exec.Command(s.exe, args...) //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Dir = s.dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	asUser.unelevated(cmd) // a SOCKS proxy and a QUIC client: no admin rights
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("usque: start: %w", err)
	}
	u := &usque{cmd: cmd, port: port, user: user, pass: pass, done: make(chan struct{})}
	// the one wait for this process: waitListening, stop and the supervisor
	// all watch done
	go func() {
		u.state, _ = cmd.Process.Wait()
		close(u.done)
	}()
	go func() {
		pipeLog(out, "usque", s.logf)
		_ = out.Close() // no cmd.Wait to close it
	}()

	// usque dies with us, even if fswin crashes
	if job, err := killOnCloseJob(cmd.Process.Pid); err == nil {
		u.job = job
	} else {
		s.logf("usque: no job object (%v); stop it by hand if fswin crashes", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitListening(addr, 30*time.Second, u); err != nil {
		u.stop()
		return nil, err
	}
	u.url = (&url.URL{Scheme: "socks5", User: url.UserPassword(user, pass), Host: addr}).String()
	return u, nil
}

func (u *usque) stop() {
	if u == nil || u.cmd == nil || u.cmd.Process == nil {
		return
	}
	_ = u.cmd.Process.Kill()
	select {
	case <-u.done:
	case <-time.After(5 * time.Second):
	}
	if u.job != 0 {
		_ = windows.CloseHandle(u.job)
		u.job = 0
	}
}

// exited tells whether the process has ended.
func (u *usque) exited() bool {
	select {
	case <-u.done:
		return true
	default:
		return false
	}
}

// usqueRegister creates a free WARP MASQUE identity in cfg unless it exists.
func usqueRegister(s usqueSetup, cfg string) error {
	if statUserFile(cfg) == nil {
		return nil
	}
	s.logf("usque: registering a free WARP identity in %s", cfg)
	// usque.exe beside fswin.exe; argv only, no shell
	cmd := exec.Command(s.exe, "-c", cfg, "register", "--accept-tos") //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Dir = s.dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	asUser.unelevated(cmd)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("usque register: %w: %s", err, b)
	}
	if err := statUserFile(cfg); err != nil {
		return fmt.Errorf("usque register wrote no config: %s", b)
	}
	return nil
}

func pipeLog(r io.Reader, tag string, logf func(string, ...any)) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		logf("%s: %s", tag, sc.Text())
	}
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// usqueDefaults are the Android app's usque flags (rethink-app-masque
// ChainArgs.DEFAULT_WARP1_ARGS and UsqueManager's resilience flags), for
// usque v0.0.4: how fast a dead tunnel is noticed and rebuilt. The user's
// flags come after them and win.
//
//	-i 1350              QUIC packets of 1350 bytes, as Cloudflare's own
//	                     client sends: usque's default starts at 1280 and
//	                     grows by path MTU discovery, and until then a full
//	                     1280-byte tunnel packet does not fit and is dropped
//	                     (TLS handshakes stalled a second after each connect).
//	                     Less on a network that cannot carry 1350 + 28.
//	-k 10s               keepalive: keeps NAT bindings open
//	-r 1s                a second between reconnect attempts
//	--idle-timeout 25s   QUIC drops a connection that hears nothing for 25 s
//	--stall-timeout 2s   packets go out, nothing comes back for 2 s, and a
//	                     probe through the tunnel gets no answer: rebuild now
//
// WARP over MASQUE also gets --always-reconnect (rebuild at once, not on the
// next packet); the chain reconnects always (usque sets it), and its WARP2
// keeps usque's own --exit-stall-timeout 8s.
func usqueDefaults(chain bool, link int) []string {
	ips := 1350
	if link > 0 {
		ips = max(min(ips, link-28), 1200) // 28: IPv4 and UDP headers; QUIC needs 1200
	}
	f := []string{"-i", fmt.Sprint(ips), "-k", "10s", "-r", "1s", "--idle-timeout", "25s", "--stall-timeout", "2s"}
	if !chain {
		f = append(f, "--always-reconnect")
	}
	return f
}

// waitListening waits until addr accepts connections or u exits.
func waitListening(addr string, d time.Duration, u *usque) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if u.exited() {
			return fmt.Errorf("usque exited (exit code %s) before its proxy came up; see the log", exitCode(u.state))
		}
		if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("usque: no proxy on %s after %s", addr, d)
}

// exitCode is written as Windows writes it: 1, or 0xC0000142 for a program
// Windows could not start; a dead start leaves no output to go by.
func exitCode(st *os.ProcessState) string {
	if st == nil {
		return "?"
	}
	c := uint32(st.ExitCode()) //nolint:gosec // G115: Windows exit codes are uint32
	if c >= 0x80000000 {
		return fmt.Sprintf("0x%08X", c)
	}
	return fmt.Sprint(c)
}

// killOnCloseJob puts pid in a job object that kills it when the last handle
// to the job closes, which happens when fswin exits for any reason.
func killOnCloseJob(pid int) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	defer windows.CloseHandle(p)
	if err := windows.AssignProcessToJobObject(job, p); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// coreFlags belong to fswin: the proxy address and password, and the
// identity and config files. Users may add any other usque flag.
var coreFlags = map[string]bool{
	"-b": true, "--bind": true, "-p": true, "--port": true,
	"-u": true, "--username": true, "-w": true, "--password": true,
	"-c": true, "--config": true, "--wg": true, "--exit-config": true,
	// usque runs these paths as programs, as admin under fswin
	"--on-connect": true, "--on-disconnect": true,
}

// usqueFlags splits extra, space-separated usque flags and refuses the
// core ones and subcommands, as the Android chain screen does.
func usqueFlags(s string) ([]string, error) {
	f := strings.Fields(s)
	for _, a := range f {
		name, _, _ := strings.Cut(a, "=")
		if len(name) > 2 && name[0] == '-' && name[1] != '-' {
			// pflag reads -b0.0.0.0, and -6b 0.0.0.0 after bool shorthands, as -b
			if i := strings.IndexAny(name[1:], "bpuwc"); i >= 0 {
				name = "-" + name[1+i:2+i]
			}
		}
		if coreFlags[name] || strings.HasSuffix(name, "-on-connect") || strings.HasSuffix(name, "-on-disconnect") {
			return nil, fmt.Errorf("usque flag %s belongs to the fixed core", name)
		}
		switch a {
		case "socks", "chain", "register", "nativetun", "http-proxy", "portfw":
			return nil, fmt.Errorf("usque flags: leave out the %s subcommand", a)
		}
	}
	return f, nil
}
