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
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	cmd  *exec.Cmd
	job  windows.Handle
	path string // usque.exe, for the bypass rule
	url  string // socks5://user:pass@127.0.0.1:port
}

// usqueSetup holds what startUsque needs.
type usqueSetup struct {
	exe     string // usque.exe
	dir     string // where warp1.json / warp2.json live
	chainWG string // wg-quick file for the chain's middle hop; "" for plain MASQUE
	logf    func(string, ...any)
}

func startUsque(s usqueSetup) (*usque, error) {
	if _, err := os.Stat(s.exe); err != nil {
		return nil, fmt.Errorf("usque: %w (usque.exe should sit next to fswin.exe)", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	warp1 := filepath.Join(s.dir, "warp1.json")
	if err := usqueRegister(s, warp1); err != nil {
		return nil, err
	}

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	user, pass := randHex(8), randHex(16)
	args := []string{"-c", warp1}
	if s.chainWG != "" {
		warp2 := filepath.Join(s.dir, "warp2.json")
		if err := usqueRegister(s, warp2); err != nil {
			return nil, err
		}
		args = append(args, "chain", "--wg", s.chainWG, "--exit-config", warp2)
	} else {
		args = append(args, "socks")
	}
	args = append(args, "-b", "127.0.0.1", "-p", fmt.Sprint(port), "-u", user, "-w", pass)

	cmd := exec.Command(s.exe, args...)
	cmd.Dir = s.dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("usque: start: %w", err)
	}
	u := &usque{cmd: cmd, path: s.exe}
	go pipeLog(out, "usque", s.logf)

	// usque dies with us, even if fswin crashes
	if job, err := killOnCloseJob(cmd.Process.Pid); err == nil {
		u.job = job
	} else {
		s.logf("usque: no job object (%v); stop it by hand if fswin crashes", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitListening(addr, 30*time.Second, cmd); err != nil {
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
	_ = u.cmd.Wait()
	if u.job != 0 {
		_ = windows.CloseHandle(u.job)
	}
}

// usqueRegister creates a free WARP MASQUE identity in cfg unless it exists.
func usqueRegister(s usqueSetup, cfg string) error {
	if _, err := os.Stat(cfg); err == nil {
		return nil
	}
	s.logf("usque: registering a free WARP identity in %s", cfg)
	cmd := exec.Command(s.exe, "-c", cfg, "register", "--accept-tos")
	cmd.Dir = s.dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("usque register: %w: %s", err, b)
	}
	if _, err := os.Stat(cfg); err != nil {
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

// waitListening waits until addr accepts connections or cmd exits.
func waitListening(addr string, d time.Duration, cmd *exec.Cmd) error {
	exited := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(exited)
	}()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return errors.New("usque exited before its proxy came up; see the log")
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("usque: no proxy on %s after %s", addr, d)
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
