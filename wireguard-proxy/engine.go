package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// engine is a userspace WireGuard tunnel plus a local HTTP proxy whose
// outgoing connections go through the tunnel. Nothing here touches the
// system network configuration, so no VpnService is needed.
type engine struct {
	dev      *device.Device
	tnet     *netstack.Net
	listener net.Listener
	network  string // tcp, tcp4 or tcp6, from the tunnel addresses
	client   *http.Client
	wg       sync.WaitGroup
}

var (
	mu        sync.Mutex
	current   *engine
	lastError string
)

func setLastError(err error) {
	if err == nil {
		lastError = ""
	} else {
		lastError = err.Error()
	}
}

// start brings the tunnel up and listens on 127.0.0.1:port (0 picks any free
// port). It returns the port actually used.
func start(configText string, port int) (int, error) {
	mu.Lock()
	defer mu.Unlock()

	if current != nil {
		current.close()
		current = nil
	}

	cfg, err := parseConfig(configText)
	if err != nil {
		return 0, err
	}
	uapi, err := cfg.uapi()
	if err != nil {
		return 0, err
	}

	tunDev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return 0, fmt.Errorf("netstack: %w", err)
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log.Printf("wireguard: "+f, a...) },
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return 0, fmt.Errorf("wireguard config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return 0, fmt.Errorf("wireguard up: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil && port != 0 {
		// Fixed port taken, for example by a previous process. Use any port.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		dev.Close()
		return 0, fmt.Errorf("listen: %w", err)
	}

	has4, has6 := false, false
	for _, a := range cfg.Addresses {
		if a.Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	network := "tcp"
	if has4 && !has6 {
		network = "tcp4"
	} else if has6 && !has4 {
		network = "tcp6"
	}

	e := &engine{dev: dev, tnet: tnet, listener: ln, network: network}
	e.client = &http.Client{
		Transport: &http.Transport{
			DialContext:           e.dial,
			Proxy:                 nil,
			MaxIdleConns:          32,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	e.wg.Add(1)
	go e.serve()
	current = e
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func stop() {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		current.close()
		current = nil
	}
}

func (e *engine) close() {
	_ = e.listener.Close()
	e.dev.Close()
	e.wg.Wait()
}

func (e *engine) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	return e.tnet.DialContext(ctx, e.network, addr)
}

func (e *engine) serve() {
	defer e.wg.Done()
	for {
		c, err := e.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go e.handle(c)
	}
}

func (e *engine) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(120 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})

		if req.Method == http.MethodConnect {
			e.tunnel(c, br, req)
			return
		}
		if !e.forward(c, req) {
			return
		}
	}
}

// tunnel handles CONNECT, which Cronet uses for every HTTPS request.
func (e *engine) tunnel(c net.Conn, br *bufio.Reader, req *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	upstream, err := e.dial(ctx, "tcp", req.Host)
	cancel()
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		// Bytes the client sent right after the CONNECT may already be buffered.
		if n := br.Buffered(); n > 0 {
			buf, _ := br.Peek(n)
			if _, err := upstream.Write(buf); err != nil {
				done <- struct{}{}
				return
			}
		}
		_, _ = io.Copy(upstream, c)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, upstream)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	// Give the other direction a moment to drain, then tear down.
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// forward handles plain HTTP proxy requests. Returns whether the client
// connection can be reused.
func (e *engine) forward(c net.Conn, req *http.Request) bool {
	if req.URL == nil || req.URL.Host == "" {
		fmt.Fprintf(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return false
	}
	keepAlive := !req.Close
	req.RequestURI = ""
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return false
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		if !strings.EqualFold(h, "Transfer-Encoding") {
			resp.Header.Del(h)
		}
	}
	if !keepAlive {
		resp.Close = true
	}
	if err := resp.Write(c); err != nil {
		return false
	}
	return keepAlive && !resp.Close
}
