// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// AuroraVPN Service starts the engine when the app turns protection on, so
// the app no longer asks for admin rights through a UAC prompt each time.
//
// It runs as LocalSystem from the per-machine install, which only
// administrators can change, and listens on the named pipe
// \\.\pipe\AuroraVPN: one request per connection, each answered on its own
// thread. It answers only
//   - local clients: the pipe refuses remote ones;
//   - the installed app: the client process must be the AuroraVPN.exe the
//     service was installed for;
//   - administrators: the engine runs with the user's own elevated token,
//     the one a UAC prompt hands out, in the user's session, so it is the
//     engine of a UAC prompt, minus the prompt. Standard users are refused.
// The engine is fswin.exe from the service's own folder. The app picks its
// flags, but the engine opens every file of the app with the user's rights
// and runs usque unelevated (asuser_windows.go), and the flags that pick a
// program to run are refused, so a request reaches nothing the user could
// not reach alone, besides the network settings protection is about.

const (
	serviceName = "AuroraVPN"
	pipePath    = `\\.\pipe\AuroraVPN`
	// CreateNamedPipe: refuse clients on other computers.
	pipeRejectRemoteClients = 0x8
	// the pipe: SYSTEM and administrators fully, interactive users (the app
	// runs unelevated) may connect; nobody else
	pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
	// a folder SYSTEM and administrators change, users read and run
	lockedSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

// serviceMain handles -service install, uninstall and run.
func serviceMain(cmd, app string) error {
	switch cmd {
	case "install":
		return installService(app)
	case "uninstall":
		return uninstallService()
	case "run":
		return svc.Run(serviceName, &service{app: app})
	}
	return fmt.Errorf("-service must be install, uninstall or run, not %q", cmd)
}

// installService installs (or updates) the service for the app at app and
// starts it.
func installService(app string) error {
	if app == "" {
		return errors.New("-service install needs -app, the path of AuroraVPN.exe")
	}
	app, err := filepath.Abs(app)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(app); err != nil || fi.IsDir() {
		return fmt.Errorf("-app %s: not a program", app)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// a LocalSystem service runs code only from where administrators write
	if err := lockDown(installRoot(exe)); err != nil {
		return fmt.Errorf("protect %s: %w", installRoot(exe), err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	cfg := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "AuroraVPN Service",
		Description:  "Starts AuroraVPN's engine when you turn protection on, without asking for admin rights each time.",
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	s, err := m.OpenService(serviceName)
	if err == nil {
		// an update: the same service, maybe from a new folder
		stopService(s)
		cfg.BinaryPathName = windows.ComposeCommandLine([]string{exe, "-service", "run", "-app", app})
		err = s.UpdateConfig(cfg)
	} else {
		s, err = m.CreateService(serviceName, exe, cfg, "-service", "run", "-app", app)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	// a crash restarts it; an engine it started keeps running meanwhile
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*3600)
	return s.Start()
}

// uninstallService stops the service, which stops its engine, and removes it.
func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	stopService(s)
	return s.Delete()
}

// stopService asks s to stop and waits for it, at most 30 s.
func stopService(s *mgr.Service) {
	if st, err := s.Query(); err != nil || st.State == svc.Stopped {
		return
	}
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 60; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// installRoot is the folder the service runs code from: the app's install
// folder when the engine sits in it (<install>\resources\engine), else the
// engine's own.
func installRoot(exe string) string {
	dir := filepath.Dir(exe)
	if strings.EqualFold(filepath.Base(dir), "engine") && strings.EqualFold(filepath.Base(filepath.Dir(dir)), "resources") {
		return filepath.Dir(filepath.Dir(dir))
	}
	return dir
}

// lockDown lets only SYSTEM and administrators change dir and everything in
// it; users read and run. Program Files is like that already; a folder
// picked elsewhere, such as C:\AuroraVPN, may let users write.
func lockDown(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(lockedSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// service is the Windows service: a pipe server while it runs.
type service struct {
	app string
}

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	exe, _ := os.Executable()
	logf := serviceLog(filepath.Join(installRoot(exe), "service.log"))
	ps, err := newPipeServer(s.app, exe, logf)
	if err != nil {
		logf("start: %v", err)
		return true, 1
	}
	go ps.serve()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	logf("running %s for %s", version, s.app)
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			ps.close()
			logf("stopped")
			return false, 0
		}
	}
	return false, 0
}

// serviceLog appends to path (in the locked-down install folder: only SYSTEM
// and administrators write there) and starts over past 1 MB.
func serviceLog(path string) func(string, ...any) {
	var mu sync.Mutex
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
			_ = os.Rename(path, path+".old")
		}
		f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
}

// pipeRequest is one request to the service.
type pipeRequest struct {
	Cmd  string   `json:"cmd"`            // ping, start, stop or cleanup
	Args []string `json:"args,omitempty"` // start: the engine's flags
}

// pipeReply is the service's answer.
type pipeReply struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	PID     uint32 `json:"pid,omitempty"`     // start: the engine's process
	Version string `json:"version,omitempty"` // ping
}

type pipeServer struct {
	app    string // the only program that may ask
	engine string // fswin.exe
	logf   func(string, ...any)
	sa     *windows.SecurityAttributes
	first  windows.Handle

	mu      sync.Mutex
	closed  bool
	running *engineProc
}

func newPipeServer(app, engine string, logf func(string, ...any)) (*pipeServer, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return nil, err
	}
	ps := &pipeServer{app: app, engine: engine, logf: logf, sa: &windows.SecurityAttributes{SecurityDescriptor: sd}}
	ps.sa.Length = uint32(unsafe.Sizeof(*ps.sa)) //nolint:gosec // G103: the struct's size, for Windows
	// the first instance fails if another program already holds the name
	if ps.first, err = ps.instance(true); err != nil {
		return nil, fmt.Errorf("pipe %s: %w", pipePath, err)
	}
	return ps, nil
}

func (ps *pipeServer) instance(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | pipeRejectRemoteClients)
	return windows.CreateNamedPipe(name, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, ps.sa)
}

func (ps *pipeServer) isClosed() bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.closed
}

// serve takes clients until close, each answered on its own goroutine.
func (ps *pipeServer) serve() {
	h := ps.first
	for {
		err := windows.ConnectNamedPipe(h, nil)
		if ps.isClosed() {
			_ = windows.CloseHandle(h)
			return
		}
		if err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			go ps.answer(h)
		} else {
			ps.logf("connect: %v", err)
			_ = windows.CloseHandle(h)
		}
		// the next client gets a new instance of the pipe
		for {
			if h, err = ps.instance(false); err == nil {
				break
			}
			ps.logf("pipe: %v", err)
			if ps.isClosed() {
				return
			}
			time.Sleep(time.Second)
		}
	}
}

// close stops taking clients, and stops the engine.
func (ps *pipeServer) close() {
	ps.mu.Lock()
	ps.closed = true
	ps.mu.Unlock()
	// a connection of our own wakes serve, waiting for the next client
	if name, err := windows.UTF16PtrFromString(pipePath); err == nil {
		if h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
			_ = windows.CloseHandle(h)
		}
	}
	ps.stopEngine(15 * time.Second)
}

// answer serves one connection: who asks, what for, and the reply.
func (ps *pipeServer) answer(h windows.Handle) {
	f := os.NewFile(uintptr(h), pipePath)
	defer f.Close()
	var req pipeRequest
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&req); err != nil {
		return
	}
	reply := ps.handle(h, req)
	if !reply.OK {
		ps.logf("%s: %s", req.Cmd, reply.Error)
	}
	_ = json.NewEncoder(f).Encode(reply)
}

func (ps *pipeServer) handle(h windows.Handle, req pipeRequest) pipeReply {
	c, err := ps.identify(h)
	if err != nil {
		return pipeReply{Error: err.Error()}
	}
	defer c.token.Close()
	switch req.Cmd {
	case "ping":
		return pipeReply{OK: true, Version: version}
	case "start":
		pid, err := ps.startEngine(c, req.Args)
		if err != nil {
			return pipeReply{Error: err.Error()}
		}
		return pipeReply{OK: true, PID: pid}
	case "stop":
		ps.stopEngine(15 * time.Second)
		return pipeReply{OK: true}
	case "cleanup":
		if err := ps.cleanup(c); err != nil {
			return pipeReply{Error: err.Error()}
		}
		return pipeReply{OK: true}
	}
	return pipeReply{Error: fmt.Sprintf("unknown request %q", req.Cmd)}
}

// pipeClient is who asks: an administrator in the installed app.
type pipeClient struct {
	pid   uint32
	user  string
	token windows.Token // the user's elevated token, primary
}

var errNotAdmin = errors.New("only an administrator can turn on AuroraVPN (Windows needs admin rights for a VPN)")

func (ps *pipeServer) identify(h windows.Handle) (*pipeClient, error) {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return nil, err
	}
	// a handle on the process keeps its id from going to another meanwhile
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return nil, fmt.Errorf("client %d: %w", pid, err)
	}
	defer windows.CloseHandle(p)
	exe, err := processPath(p)
	if err != nil {
		return nil, fmt.Errorf("client %d: %w", pid, err)
	}
	if !samePath(exe, ps.app) {
		return nil, fmt.Errorf("%s is not the AuroraVPN app", exe)
	}
	tok, err := pipeClientToken(h)
	if err != nil {
		return nil, fmt.Errorf("client %d: %w", pid, err)
	}
	defer tok.Close()
	user := "?"
	if u, err := tok.GetTokenUser(); err == nil {
		if a, d, _, err := u.User.Sid.LookupAccount(""); err == nil {
			user = d + `\` + a
		}
	}
	et, err := elevatedToken(tok)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", user, err)
	}
	return &pipeClient{pid: pid, user: user, token: et}, nil
}

func processPath(p windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(p, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func samePath(a, b string) bool {
	return a != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// pipeClientToken is the token of the program at the other end of h.
func pipeClientToken(h windows.Handle) (windows.Token, error) {
	type result struct {
		t   windows.Token
		err error
	}
	done := make(chan result, 1)
	go func() {
		// impersonation belongs to this thread; one that cannot go back to
		// the service's own token stays locked, and Go ends it with the goroutine
		runtime.LockOSThread()
		if r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("impersonate: %w", e)}
			return
		}
		var t windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, true, &t)
		if windows.RevertToSelf() == nil {
			runtime.UnlockOSThread()
		}
		done <- result{t, err}
	}()
	r := <-done
	return r.t, r.err
}

// tokenSession is the Windows session (log-on) a token belongs to.
func tokenSession(t windows.Token) uint32 {
	var session, n uint32
	_ = windows.GetTokenInformation(t, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &n) //nolint:gosec // G103: the call fills a uint32
	return session
}

// tokenLinked is TOKEN_LINKED_TOKEN.
type tokenLinked struct{ token windows.Token }

// elevatedToken is the token to run the engine with: the user's own elevated
// one. An elevated client (UAC off, or the app run as administrator) has it
// already; an administrator's ordinary token links to it, the token a UAC
// prompt would hand out. A standard user has none.
//
//nolint:gosec // G103: GetTokenInformation fills a struct
func elevatedToken(t windows.Token) (windows.Token, error) {
	src := t
	if !t.IsElevated() {
		var linked tokenLinked
		var n uint32
		if err := windows.GetTokenInformation(t, windows.TokenLinkedToken, (*byte)(unsafe.Pointer(&linked)), uint32(unsafe.Sizeof(linked)), &n); err != nil {
			return 0, errNotAdmin
		}
		defer linked.token.Close()
		if !linked.token.IsElevated() {
			return 0, errNotAdmin
		}
		src = linked.token
	}
	var dup windows.Token
	if err := windows.DuplicateTokenEx(src, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return 0, err
	}
	return dup, nil
}

// refusedFlags pick a program for the engine to run, or one of fswin's own
// modes, not a setting.
var refusedFlags = map[string]bool{"service": true, "app": true, "stop-handle": true, "usque": true}

// checkEngineArgs refuses the flags a client may not pass.
func checkEngineArgs(args []string) error {
	if len(args) > 256 {
		return errors.New("too many flags")
	}
	for _, a := range args {
		if len(a) > 8192 || strings.ContainsRune(a, 0) {
			return errors.New("a flag is too long")
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if refusedFlags[strings.ToLower(name)] {
			return fmt.Errorf("the flag -%s is not allowed through the service", name)
		}
	}
	return nil
}

// engineProc is an engine the service started.
type engineProc struct {
	pid     uint32
	process windows.Handle
	stop    windows.Handle // an event: set, the engine stops as for the app
}

func (e *engineProc) exited(d time.Duration) bool {
	ev, err := windows.WaitForSingleObject(e.process, uint32(d.Milliseconds()))
	return err == nil && ev == windows.WAIT_OBJECT_0
}

func (e *engineProc) close() {
	_ = windows.CloseHandle(e.process)
	_ = windows.CloseHandle(e.stop)
}

func (ps *pipeServer) startEngine(c *pipeClient, args []string) (uint32, error) {
	if err := checkEngineArgs(args); err != nil {
		return 0, err
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if e := ps.running; e != nil {
		if !e.exited(0) {
			return e.pid, nil // the app checks the engine's API anyway
		}
		e.close()
		ps.running = nil
	}
	e, err := launch(c.token, ps.engine, args)
	if err != nil {
		return 0, err
	}
	ps.running = e
	ps.logf("engine %d started for %s in session %d", e.pid, c.user, tokenSession(c.token))
	return e.pid, nil
}

// stopEngine asks the running engine to stop, as the app's stop button does,
// and ends it if it has not after d.
func (ps *pipeServer) stopEngine(d time.Duration) {
	ps.mu.Lock()
	e := ps.running
	ps.running = nil
	ps.mu.Unlock()
	if e == nil {
		return
	}
	defer e.close()
	if e.exited(0) {
		return
	}
	_ = windows.SetEvent(e.stop)
	if !e.exited(d) {
		ps.logf("engine %d did not stop in %s; ending it", e.pid, d)
		_ = windows.TerminateProcess(e.process, 1)
	}
}

// cleanup runs fswin -cleanup for c: it removes a kill switch and DNS rule
// that a crashed engine left behind.
func (ps *pipeServer) cleanup(c *pipeClient) error {
	ps.mu.Lock()
	running := ps.running != nil && !ps.running.exited(0)
	ps.mu.Unlock()
	if running {
		return errors.New("stop protection first")
	}
	e, err := launch(c.token, ps.engine, []string{"-cleanup"})
	if err != nil {
		return err
	}
	defer e.close()
	if !e.exited(30 * time.Second) {
		_ = windows.TerminateProcess(e.process, 1)
		return errors.New("cleanup did not finish in 30 s")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(e.process, &code); err != nil || code != 0 {
		return fmt.Errorf("cleanup failed (exit code %d)", code)
	}
	return nil
}

// launch starts exe with args as the user of token (elevated), on the user's
// desktop, hidden, with the user's own environment. The engine inherits only
// the stop event, and learns it from -stop-handle.
func launch(token windows.Token, exe string, args []string) (*engineProc, error) {
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(sa)) //nolint:gosec // G103: the struct's size, for Windows
	stop, err := windows.CreateEvent(&sa, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = windows.CloseHandle(stop)
		}
	}()

	argv := append(append([]string{exe}, args...), "-stop-handle", strconv.FormatUint(uint64(stop), 10))
	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(argv))
	if err != nil {
		return nil, err
	}
	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	dir16, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return nil, err
	}
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return nil, err
	}
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return nil, fmt.Errorf("the user's environment: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&stop), unsafe.Sizeof(stop)); err != nil { //nolint:gosec // G103: the attribute takes a pointer
		return nil, err
	}
	si := windows.StartupInfoEx{
		StartupInfo:             windows.StartupInfo{Desktop: desktop, Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE},
		ProcThreadAttributeList: attrs.List(),
	}
	si.Cb = uint32(unsafe.Sizeof(si)) //nolint:gosec // G103: the struct's size, for Windows
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcessAsUser(token, exe16, cmdline, nil, nil, true, flags, env, dir16, &si.StartupInfo, &pi); err != nil {
		return nil, fmt.Errorf("start the engine: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)
	ok = true
	return &engineProc{pid: pi.ProcessId, process: pi.Process, stop: stop}, nil
}

// validAdapterName keeps -name to what netsh takes as a plain name.
var validAdapterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`).MatchString
