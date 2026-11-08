package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func keypair(t *testing.T) (priv, pub []byte) {
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// TestEndToEnd runs a second WireGuard peer in process, playing the VPN
// server, and checks that both CONNECT and plain HTTP go through the tunnel.
func TestEndToEnd(t *testing.T) {
	sPriv, sPub := keypair(t)
	cPriv, cPub := keypair(t)

	// Server peer.
	sTun, sNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	sDev := device.NewDevice(sTun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "server: "))
	defer sDev.Close()
	uc, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := fmt.Sprint(uc.LocalAddr().(*net.UDPAddr).Port)
	uc.Close()
	err = sDev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%s\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(sPriv), port, hex.EncodeToString(cPub)))
	if err != nil {
		t.Fatal(err)
	}
	if err := sDev.Up(); err != nil {
		t.Fatal(err)
	}

	ln, err := sNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.9.0.1"), Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from tunnel %s", r.URL.Path)
	}))

	// Client: our engine, configured the way a user would paste it.
	cfg := fmt.Sprintf(`
[Interface]
# Key for test
PrivateKey = %s
Address = 10.9.0.2/32
DNS = 10.9.0.1

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:%s
`, base64.StdEncoding.EncodeToString(cPriv), base64.StdEncoding.EncodeToString(sPub), port)

	p, err := start(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p))

	// Plain HTTP through the proxy.
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 15 * time.Second}
	resp, err := client.Get("http://10.9.0.1/plain")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from tunnel /plain" {
		t.Fatalf("plain: %q", body)
	}

	// CONNECT, as Cronet does for HTTPS.
	c, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT 10.9.0.1:80 HTTP/1.1\r\nHost: 10.9.0.1:80\r\n\r\nGET /tunnel HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	br := bufio.NewReader(c)
	r1, err := http.ReadResponse(br, nil)
	if err != nil || r1.StatusCode != 200 {
		t.Fatalf("connect: %v %v", r1, err)
	}
	r2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(r2.Body)
	if string(body) != "hello from tunnel /tunnel" {
		t.Fatalf("connect body: %q", body)
	}

	// Restart works (settings change without app restart).
	if _, err := start(cfg, p); err != nil {
		t.Fatal(err)
	}

	// Bad config is reported, not crashed on.
	if _, err := start("[Interface]\nPrivateKey = nope\n", 0); err == nil {
		t.Fatal("expected error")
	}
}
