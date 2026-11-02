// Package scope decides which scan targets are allowed.
//
// A model chooses scan targets, and text it reads (a web page, an issue, a
// document) can steer that choice. By default the checker therefore refuses
// loopback, private, link-local and cloud metadata addresses, so a steered
// model cannot point a vulnerability scanner at the internal network.
package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ErrOutOfScope is wrapped by every refusal.
var ErrOutOfScope = errors.New("target out of scope")

// Cloud metadata endpoints are refused even when private targets are
// allowed, unless listed explicitly in the allow list.
var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // AWS, GCP, Azure, OpenStack
	netip.MustParsePrefix("169.254.170.2/32"),   // AWS ECS task metadata
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure WireServer
}

// Non-public ranges beyond what netip.Addr's predicates cover.
var extraPrivate = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved
}

// Resolver looks up a host's addresses.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Checker applies the scope rules.
type Checker struct {
	allowPrivate bool
	allow        []rule
	deny         []rule
	resolve      Resolver
}

type rule struct {
	raw    string
	prefix netip.Prefix // valid for IP and CIDR rules
	host   string       // exact host name
	suffix string       // "*.example.com" -> ".example.com"
}

// New builds a checker. allow and deny take host names, "*.domain"
// wildcards, IP addresses and CIDR ranges.
func New(allowPrivate bool, allow, deny []string) (*Checker, error) {
	c := &Checker{allowPrivate: allowPrivate, resolve: defaultResolver}
	var err error
	if c.allow, err = parseRules(allow); err != nil {
		return nil, fmt.Errorf("security.allowed_targets: %w", err)
	}
	if c.deny, err = parseRules(deny); err != nil {
		return nil, fmt.Errorf("security.denied_targets: %w", err)
	}
	return c, nil
}

// WithResolver replaces DNS resolution; used by tests.
func (c *Checker) WithResolver(r Resolver) *Checker {
	c.resolve = r
	return c
}

func parseRules(entries []string) ([]rule, error) {
	var out []rule
	for _, raw := range entries {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		r := rule{raw: e}
		switch {
		case strings.Contains(e, "/"):
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", raw)
			}
			r.prefix = p.Masked()
		case strings.HasPrefix(e, "*."):
			r.suffix = e[1:]
		default:
			if a, err := netip.ParseAddr(e); err == nil {
				r.prefix = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			} else {
				r.host = strings.TrimSuffix(e, ".")
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func (r rule) matchesHost(host string) bool {
	return (r.host != "" && host == r.host) || (r.suffix != "" && strings.HasSuffix(host, r.suffix))
}

func (r rule) matchesAddr(a netip.Addr) bool {
	return r.prefix.IsValid() && r.prefix.Contains(a)
}

// AllowsLocalNetwork reports whether any scan may reach a non-public
// address. When false, the scanner also enables Nuclei's own local network
// restriction as a second line of defence (redirects, DNS rebinding).
func (c *Checker) AllowsLocalNetwork() bool {
	if c.allowPrivate {
		return true
	}
	for _, r := range c.allow {
		if r.prefix.IsValid() && isNonPublic(r.prefix.Addr()) {
			return true
		}
	}
	return false
}

// Check returns nil if target may be scanned, or an error wrapping
// ErrOutOfScope that explains which setting would allow it.
func (c *Checker) Check(ctx context.Context, target string) error {
	host, err := Host(target)
	if err != nil {
		return err
	}

	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, _ = c.resolve(rctx, host)
		cancel()
		// A name that does not resolve reaches nothing private; DNS
		// templates (e.g. subdomain takeover checks) need to scan it.
	}

	for _, r := range c.deny {
		if r.matchesHost(host) {
			return fmt.Errorf("%w: %s matches denied_targets entry %q", ErrOutOfScope, host, r.raw)
		}
		for _, a := range addrs {
			if r.matchesAddr(a) {
				return fmt.Errorf("%w: %s (%s) matches denied_targets entry %q", ErrOutOfScope, host, a, r.raw)
			}
		}
	}

	if len(c.allow) > 0 {
		if c.allowedByName(host) {
			return nil
		}
		if len(addrs) == 0 {
			return fmt.Errorf("%w: %s is not in allowed_targets", ErrOutOfScope, host)
		}
		for _, a := range addrs {
			if !c.allowedAddr(a) {
				return fmt.Errorf("%w: %s (%s) is not in allowed_targets", ErrOutOfScope, host, a)
			}
		}
		return nil
	}

	if !c.allowPrivate && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return fmt.Errorf("%w: %s is a loopback name; set security.allow_private_targets: true (or NUCLEI_MCP_SECURITY_ALLOW_PRIVATE_TARGETS=true) to scan your own machine", ErrOutOfScope, host)
	}
	for _, a := range addrs {
		if isMetadata(a) {
			return fmt.Errorf("%w: %s (%s) is a cloud metadata endpoint; list it in security.allowed_targets to scan it", ErrOutOfScope, host, a)
		}
		if !c.allowPrivate && isNonPublic(a) {
			return fmt.Errorf("%w: %s (%s) is a loopback, private or link-local address; set security.allow_private_targets: true (or NUCLEI_MCP_SECURITY_ALLOW_PRIVATE_TARGETS=true) to scan your own network", ErrOutOfScope, host, a)
		}
	}
	return nil
}

func (c *Checker) allowedByName(host string) bool {
	for _, r := range c.allow {
		if r.matchesHost(host) {
			return true
		}
	}
	return false
}

func (c *Checker) allowedAddr(a netip.Addr) bool {
	for _, r := range c.allow {
		if r.matchesAddr(a) {
			return true
		}
	}
	return false
}

func isMetadata(a netip.Addr) bool {
	for _, p := range metadataPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isNonPublic(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range extraPrivate {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Host extracts the host name or IP from a scan target: a URL, host:port,
// [ipv6]:port, a bare host or a bare IP.
func Host(target string) (string, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", fmt.Errorf("target is empty")
	}
	if strings.ContainsAny(t, " \t\r\n\"'<>`") {
		return "", fmt.Errorf("target %q contains invalid characters", target)
	}
	var host string
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return "", fmt.Errorf("target %q is not a valid URL: %v", target, err)
		}
		host = u.Hostname()
	} else {
		hp := t
		if i := strings.IndexAny(hp, "/?#"); i >= 0 {
			hp = hp[:i]
		}
		if h, _, err := net.SplitHostPort(hp); err == nil {
			host = h
		} else {
			host = strings.Trim(hp, "[]")
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("target %q has no host", target)
	}
	return host, nil
}

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out, nil
}
