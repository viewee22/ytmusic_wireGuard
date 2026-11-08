package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// wgConfig is the subset of a wg-quick style configuration file that is needed
// to bring up a userspace WireGuard tunnel.
type wgConfig struct {
	PrivateKey string // hex
	Addresses  []netip.Addr
	DNS        []netip.Addr
	MTU        int
	Peers      []wgPeer
}

type wgPeer struct {
	PublicKey    string // hex
	PresharedKey string // hex, optional
	Endpoint     string // host:port as written in the config
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("invalid key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("invalid key length %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseConfig parses a wg-quick configuration, such as the files Proton VPN
// and other providers let you download.
func parseConfig(text string) (*wgConfig, error) {
	cfg := &wgConfig{MTU: 1280}
	var peer *wgPeer
	section := ""

	sc := bufio.NewScanner(strings.NewReader(text))
	line := 0
	for sc.Scan() {
		line++
		l := sc.Text()
		if i := strings.IndexAny(l, "#;"); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.ToLower(strings.TrimSpace(l[1 : len(l)-1]))
			if section == "peer" {
				cfg.Peers = append(cfg.Peers, wgPeer{})
				peer = &cfg.Peers[len(cfg.Peers)-1]
			}
			continue
		}
		eq := strings.IndexByte(l, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		key := strings.ToLower(strings.TrimSpace(l[:eq]))
		val := strings.TrimSpace(l[eq+1:])

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				h, err := keyToHex(val)
				if err != nil {
					return nil, fmt.Errorf("PrivateKey: %w", err)
				}
				cfg.PrivateKey = h
			case "address":
				for _, a := range splitList(val) {
					if p, err := netip.ParsePrefix(a); err == nil {
						cfg.Addresses = append(cfg.Addresses, p.Addr())
					} else if ad, err := netip.ParseAddr(a); err == nil {
						cfg.Addresses = append(cfg.Addresses, ad)
					} else {
						return nil, fmt.Errorf("Address: invalid %q", a)
					}
				}
			case "dns":
				for _, a := range splitList(val) {
					if ad, err := netip.ParseAddr(a); err == nil {
						cfg.DNS = append(cfg.DNS, ad)
					}
					// Search domains are ignored.
				}
			case "mtu":
				m, err := strconv.Atoi(val)
				if err != nil || m < 576 || m > 9000 {
					return nil, fmt.Errorf("MTU: invalid %q", val)
				}
				cfg.MTU = m
			}
		case "peer":
			switch key {
			case "publickey":
				h, err := keyToHex(val)
				if err != nil {
					return nil, fmt.Errorf("PublicKey: %w", err)
				}
				peer.PublicKey = h
			case "presharedkey":
				h, err := keyToHex(val)
				if err != nil {
					return nil, fmt.Errorf("PresharedKey: %w", err)
				}
				peer.PresharedKey = h
			case "endpoint":
				peer.Endpoint = val
			case "allowedips":
				for _, a := range splitList(val) {
					p, err := netip.ParsePrefix(a)
					if err != nil {
						return nil, fmt.Errorf("AllowedIPs: invalid %q", a)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, p)
				}
			case "persistentkeepalive":
				k, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("PersistentKeepalive: invalid %q", val)
				}
				peer.Keepalive = k
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("[Interface] PrivateKey is missing")
	}
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("[Interface] Address is missing")
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("[Peer] section is missing")
	}
	for i, p := range cfg.Peers {
		if p.PublicKey == "" {
			return nil, fmt.Errorf("peer %d: PublicKey is missing", i+1)
		}
		if p.Endpoint == "" {
			return nil, fmt.Errorf("peer %d: Endpoint is missing", i+1)
		}
		if len(p.AllowedIPs) == 0 {
			cfg.Peers[i].AllowedIPs = []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			}
		}
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	return cfg, nil
}

// resolveEndpoint turns host:port into ip:port using the device's normal network.
func resolveEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("Endpoint %q: %w", ep, err)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(host, port), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("Endpoint %q: cannot resolve: %v", ep, err)
	}
	// Prefer IPv4, which every mobile network supports.
	for _, ip := range ips {
		if ip.To4() != nil {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// uapi renders the configuration in the WireGuard userspace API format.
func (c *wgConfig) uapi() (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.PrivateKey)
	b.WriteString("replace_peers=true\n")
	for _, p := range c.Peers {
		ep, err := resolveEndpoint(p.Endpoint)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "public_key=%s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
		keepalive := p.Keepalive
		if keepalive == 0 {
			// Keeps NAT mappings on mobile networks alive.
			keepalive = 25
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
		}
	}
	return b.String(), nil
}
