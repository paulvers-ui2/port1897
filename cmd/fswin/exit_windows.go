// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Exits: where -full traffic leaves. firestack calls them proxies; WireGuard
// ones need an id starting with "wg".
const (
	exitWG     = "wgconf"
	exitWarp   = "wgwarp"
	exitProxy  = "socks"
	exitMasque = "masque" // usque socks
	exitChain  = "chain"  // usque chain
)

// wgQuickToUAPI converts a wg-quick .conf file to the key=value config
// firestack's WireGuard proxy reads (WireGuard's UAPI keys plus address,
// dns and mtu). Keys go from base64 to hex.
func wgQuickToUAPI(conf string) (string, error) {
	var iface, peers strings.Builder
	section := ""
	sawKey, sawPeer, sawDNS := false, false, false
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return "", fmt.Errorf("wg: bad line %q", line)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				h, err := b64hex(v)
				if err != nil {
					return "", fmt.Errorf("wg: PrivateKey: %w", err)
				}
				fmt.Fprintf(&iface, "private_key=%s\n", h)
				sawKey = true
			case "address":
				fmt.Fprintf(&iface, "address=%s\n", v)
			case "dns":
				fmt.Fprintf(&iface, "dns=%s\n", v)
				sawDNS = true
			case "mtu":
				// wg-quick's MTU is the size of a packet inside the tunnel;
				// firestack's is the size on the link, and it keeps
				// wgOverhead of that for WireGuard (mtu_windows.go)
				if m, err := strconv.Atoi(v); err == nil && m > 0 {
					fmt.Fprintf(&iface, "mtu=%d\n", m+wgOverhead)
				} else {
					fmt.Fprintf(&iface, "mtu=%s\n", v)
				}
			case "listenport":
				fmt.Fprintf(&iface, "listen_port=%s\n", v)
			}
		case "peer":
			switch k {
			case "publickey":
				h, err := b64hex(v)
				if err != nil {
					return "", fmt.Errorf("wg: PublicKey: %w", err)
				}
				fmt.Fprintf(&peers, "public_key=%s\n", h)
				sawPeer = true
			case "presharedkey":
				h, err := b64hex(v)
				if err != nil {
					return "", fmt.Errorf("wg: PresharedKey: %w", err)
				}
				fmt.Fprintf(&peers, "preshared_key=%s\n", h)
			case "endpoint":
				fmt.Fprintf(&peers, "endpoint=%s\n", v)
			case "allowedips":
				for _, ip := range strings.Split(v, ",") {
					if ip = strings.TrimSpace(ip); ip != "" {
						fmt.Fprintf(&peers, "allowed_ip=%s\n", ip)
					}
				}
			case "persistentkeepalive":
				fmt.Fprintf(&peers, "persistent_keepalive_interval=%s\n", v)
			}
		}
	}
	if !sawKey || !sawPeer {
		return "", errors.New("wg: config needs [Interface] PrivateKey and a [Peer] PublicKey")
	}
	if !sawDNS {
		iface.WriteString("dns=1.1.1.1\n") // firestack requires one
	}
	return iface.String() + peers.String(), nil
}

func b64hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("key is %d bytes, want 32", len(b))
	}
	return hex.EncodeToString(b), nil
}

// warpAccount is what fswin keeps of a free WARP registration.
type warpAccount struct {
	PrivateKey string `json:"private_key"` // base64
	PeerKey    string `json:"peer_public_key"`
	ClientID   string `json:"client_id"` // base64, 3 bytes
	Address4   string `json:"address_v4"`
	Endpoint4  string `json:"endpoint_v4"` // ip:port
	ID         string `json:"id"`
	Token      string `json:"token"`
}

// warp API, as used by Cloudflare's own Android client.
const (
	warpRegURL       = "https://api.cloudflareclient.com/v0a2158/reg"
	warpClientVer    = "a-6.10-2158"
	warpDefaultPeer  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpDefaultEp4   = "162.159.192.1:2408"
	warpDefaultAddr4 = "172.16.0.2"
)

// loadOrRegisterWarp reads the WARP account in path, or registers a new free
// one and saves it there. The file holds the WireGuard private key.
func loadOrRegisterWarp(path string) (*warpAccount, error) {
	if b, err := readUserFile(path); err == nil {
		var a warpAccount
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("warp: read %s: %w", path, err)
		}
		return &a, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	a, err := registerWarp()
	if err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(a, "", "  ")
	if err := asUser.do(func() error { return os.WriteFile(filepath.Clean(path), b, 0o600) }); err != nil {
		return nil, fmt.Errorf("warp: save %s: %w", path, err)
	}
	return a, nil
}

func registerWarp() (*warpAccount, error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, err
	}
	// WireGuard clamps private keys; do it up front so the key round-trips.
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	priv, err := ecdh.X25519().NewPrivateKey(sk[:])
	if err != nil {
		return nil, err
	}
	pub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	body, _ := json.Marshal(map[string]any{
		"key":        pub,
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":      "PC",
		"type":       "Android",
		"locale":     "en_US",
	})
	req, err := http.NewRequest(http.MethodPost, warpRegURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", warpClientVer)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	c := &http.Client{Timeout: 20 * time.Second}
	res, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warp: register: %w", err)
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("warp: register: %s: %s", res.Status, bytes.TrimSpace(rb))
	}

	var r struct {
		ID     string `json:"id"`
		Token  string `json:"token"`
		Config struct {
			ClientID string `json:"client_id"`
			Peers    []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4 string `json:"v4"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rb, &r); err != nil {
		return nil, fmt.Errorf("warp: register: bad reply: %w", err)
	}

	a := &warpAccount{
		PrivateKey: base64.StdEncoding.EncodeToString(sk[:]),
		PeerKey:    warpDefaultPeer,
		ClientID:   r.Config.ClientID,
		Address4:   r.Config.Interface.Addresses.V4,
		Endpoint4:  warpDefaultEp4,
		ID:         r.ID,
		Token:      r.Token,
	}
	if len(r.Config.Peers) > 0 {
		p := r.Config.Peers[0]
		if p.PublicKey != "" {
			a.PeerKey = p.PublicKey
		}
		// the API reports port 0; WARP listens on 2408 (also 500, 1701, 4500)
		if ap, err := netip.ParseAddrPort(p.Endpoint.V4); err == nil {
			a.Endpoint4 = netip.AddrPortFrom(ap.Addr(), 2408).String()
		}
	}
	if a.Address4 == "" {
		a.Address4 = warpDefaultAddr4
	}
	return a, nil
}

// uapi builds firestack's WireGuard config for this WARP account, IPv4 only.
func (a *warpAccount) uapi() (string, error) {
	sk, err := b64hex(a.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("warp: private key: %w", err)
	}
	pk, err := b64hex(a.PeerKey)
	if err != nil {
		return "", fmt.Errorf("warp: peer key: %w", err)
	}
	var cfg strings.Builder
	fmt.Fprintf(&cfg, "private_key=%s\n", sk)
	fmt.Fprintf(&cfg, "address=%s/32\n", a.Address4)
	cfg.WriteString("dns=1.1.1.1\n")
	fmt.Fprintf(&cfg, "mtu=%d\n", warpMTU+wgOverhead) // 1280 inside the tunnel, as in Cloudflare's client
	// WARP wants its 3-byte client id in the reserved header bytes. firestack
	// lowercases values, which breaks a base64 client_id line, so pass the
	// header words it would derive (h1..h4) as plain numbers instead.
	if id, err := base64.StdEncoding.DecodeString(a.ClientID); err == nil && len(id) == 3 {
		for i, typ := range []byte{1, 2, 3, 4} { // initiation, response, cookie reply, transport
			h := binary.LittleEndian.Uint32([]byte{typ, id[0], id[1], id[2]})
			fmt.Fprintf(&cfg, "h%d=%d\n", i+1, h)
		}
	}
	fmt.Fprintf(&cfg, "public_key=%s\n", pk)
	fmt.Fprintf(&cfg, "endpoint=%s\n", a.Endpoint4)
	cfg.WriteString("allowed_ip=0.0.0.0/0\n")
	cfg.WriteString("persistent_keepalive_interval=25\n")
	return cfg.String(), nil
}
