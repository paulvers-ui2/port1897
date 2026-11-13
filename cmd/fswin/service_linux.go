// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// AuroraVPN Service on Linux: what service_windows.go is on Windows, run by
// systemd (auroravpn.service, installed by the .deb) as root:
//
//	fswin -service run -app /opt/AuroraVPN/auroravpn
//
// It listens on the unix socket /run/auroravpn/auroravpn.sock and speaks the
// same protocol as the Windows pipe (service_proto.go). It answers
//   - any local user, as on Windows: the socket is open to all, and the peer
//     is known from the kernel (SO_PEERCRED), not from what it says;
//   - only the installed app: the peer process must be the -app program.
// The engine runs as root, which a VPN needs, with -user-token <uid> of the
// user who asked: that user's files are opened, and usque runs, as them.

const (
	socketDir  = "/run/auroravpn"
	socketPath = socketDir + "/auroravpn.sock"
	// the time a client has to send its request
	sockReadTimeout = 10 * time.Second
)

type sockServer struct {
	app    string // the only program that may ask
	engine string // this fswin
	logf   func(string, ...any)

	mu  sync.Mutex
	eng *exec.Cmd     // the engine, nil when none
	end chan struct{} // closed when eng has ended
}

// serviceMain runs the service until systemd stops it.
func serviceMain(cmd, app string) error {
	if cmd != "run" {
		return fmt.Errorf("-service %s: on Linux the .deb installs auroravpn.service; only -service run is for systemd", cmd)
	}
	if app == "" {
		return errors.New("-service run needs -app, the path of the installed app")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if a, err := filepath.EvalSymlinks(app); err == nil {
		app = a
	}
	ss := &sockServer{app: app, engine: exe, logf: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}
	// a killed service left an engine: it is no one's now
	ss.cleanupStale()

	if err := os.MkdirAll(socketDir, 0o755); err != nil { //nolint:gosec // G301: users reach the socket in it
		return err
	}
	_ = os.Remove(socketPath)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	l.SetUnlinkOnClose(true)
	// any local user may connect; who it is comes from SO_PEERCRED
	if err := os.Chmod(socketPath, 0o666); err != nil { //nolint:gosec // G302: see above
		_ = l.Close()
		return err
	}
	ss.logf("AuroraVPN Service %s: listening on %s for %s", version, socketPath, app)

	stop := make(chan os.Signal, 2)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-stop
		ss.logf("stopping")
		_ = l.Close()
	}()
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			ss.logf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go ss.answer(c)
	}
	ss.stopEngine(15 * time.Second)
	return nil
}

// peer is who is on the other end of a connection.
type peer struct {
	pid, uid int
}

func (ss *sockServer) identify(c *net.UnixConn) (peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return peer{}, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peer{}, err
	}
	if cerr != nil {
		return peer{}, cerr
	}
	if cred == nil {
		return peer{}, errors.New("who is asking: no peer credentials")
	}
	p := peer{pid: int(cred.Pid), uid: int(cred.Uid)}
	exe, err := os.Readlink("/proc/" + strconv.Itoa(p.pid) + "/exe")
	if err != nil {
		return p, fmt.Errorf("who is asking: %w", err)
	}
	if !samePathLinux(exe, ss.app) {
		return p, fmt.Errorf("only %s may use AuroraVPN Service, not %s", ss.app, exe)
	}
	return p, nil
}

func samePathLinux(a, b string) bool {
	if x, err := filepath.EvalSymlinks(a); err == nil {
		a = x
	}
	if x, err := filepath.EvalSymlinks(b); err == nil {
		b = x
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func (ss *sockServer) answer(c *net.UnixConn) {
	defer c.Close()
	p, err := ss.identify(c)
	if err != nil {
		ss.logf("refused: %v", err)
		// read what it sent first (and ignore it): a unix socket closed with
		// unread data resets the connection, and the caller would lose the
		// reason
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = io.Copy(io.Discard, io.LimitReader(c, 64<<10))
		_ = json.NewEncoder(c).Encode(pipeReply{Error: err.Error()})
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(sockReadTimeout))
	var req pipeRequest
	if err := json.NewDecoder(io.LimitReader(c, 64<<10)).Decode(&req); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	reply := ss.handle(p, req)
	if !reply.OK {
		ss.logf("%s: %s", req.Cmd, reply.Error)
	}
	_ = json.NewEncoder(c).Encode(reply)
}

func (ss *sockServer) handle(p peer, req pipeRequest) pipeReply {
	switch req.Cmd {
	case "ping":
		return pipeReply{OK: true, Version: version}
	case "start":
		// keep and watch are for the Windows keeper; systemd keeps the
		// service up, and the app restarts the engine
		pid, err := ss.startEngine(p, req.Args)
		if err != nil {
			return pipeReply{Error: err.Error()}
		}
		return pipeReply{OK: true, PID: uint32(pid)} //nolint:gosec // G115: a pid
	case "stop":
		ss.stopEngine(15 * time.Second)
		return pipeReply{OK: true}
	case "unkeep":
		return pipeReply{OK: true}
	case "cleanup":
		if err := ss.cleanup(); err != nil {
			return pipeReply{Error: err.Error()}
		}
		return pipeReply{OK: true}
	}
	return pipeReply{Error: fmt.Sprintf("unknown request %q", req.Cmd)}
}

func (ss *sockServer) startEngine(p peer, args []string) (int, error) {
	if err := checkEngineArgs(args); err != nil {
		return 0, err
	}
	ss.stopEngine(15 * time.Second)
	full := append([]string{}, args...)
	if p.uid != 0 {
		full = append(full, "-user-token", strconv.Itoa(p.uid))
	}
	// nosemgrep
	cmd := exec.Command(ss.engine, full...) //nolint:gosec // G204: this fswin, flags checked above
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stderr // the journal; -logfile is the app's copy
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start the engine: %w", err)
	}
	end := make(chan struct{})
	ss.mu.Lock()
	ss.eng, ss.end = cmd, end
	ss.mu.Unlock()
	go func() {
		err := cmd.Wait()
		ss.logf("engine %d ended: %v", cmd.Process.Pid, err)
		ss.mu.Lock()
		if ss.eng == cmd {
			ss.eng, ss.end = nil, nil
		}
		ss.mu.Unlock()
		close(end)
	}()
	ss.logf("engine %d started for uid %d", cmd.Process.Pid, p.uid)
	return cmd.Process.Pid, nil
}

// stopEngine asks the engine to stop (SIGTERM: it undoes its routes, DNS and
// kill switch), and kills it after d.
func (ss *sockServer) stopEngine(d time.Duration) {
	ss.mu.Lock()
	cmd, end := ss.eng, ss.end
	ss.mu.Unlock()
	if cmd == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-end:
	case <-time.After(d):
		ss.logf("engine %d still ending after %s: killed", cmd.Process.Pid, d)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-end
		_ = ss.cleanup()
	}
}

// cleanup undoes what an engine that was killed left: its DNS, routing
// rules and kill switch.
func (ss *sockServer) cleanup() error {
	ss.mu.Lock()
	running := ss.eng != nil
	ss.mu.Unlock()
	if running {
		return errors.New("the engine is running: stop it first")
	}
	// nosemgrep
	out, err := exec.Command(ss.engine, "-cleanup").CombinedOutput() //nolint:gosec // G204: this fswin
	if err != nil {
		return fmt.Errorf("cleanup: %w: %s", err, out)
	}
	return nil
}

// cleanupStale ends engines a killed service left and undoes their changes.
func (ss *sockServer) cleanupStale() {
	ents, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil || !samePathLinux(exe, ss.engine) {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGTERM)
		n++
	}
	if n > 0 {
		ss.logf("ended %d engine(s) left by a stopped service", n)
		time.Sleep(3 * time.Second)
	}
	_ = ss.cleanup()
}
