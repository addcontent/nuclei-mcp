package scope

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// fakeDNS resolves a fixed table; unknown names do not resolve.
func fakeDNS(table map[string]string) Resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		if ip, ok := table[host]; ok {
			return []netip.Addr{netip.MustParseAddr(ip)}, nil
		}
		return nil, errors.New("no such host")
	}
}

var dns = fakeDNS(map[string]string{
	"example.com":       "93.184.215.14",
	"intranet.corp":     "10.1.2.3",
	"rebind.attacker":   "127.0.0.1",
	"metadata.internal": "169.254.169.254",
	"app.example.com":   "93.184.215.15",
})

func mustNew(t *testing.T, allowPrivate bool, allow, deny []string) *Checker {
	t.Helper()
	c, err := New(allowPrivate, allow, deny)
	if err != nil {
		t.Fatal(err)
	}
	return c.WithResolver(dns)
}

func TestDefaultPolicy(t *testing.T) {
	c := mustNew(t, false, nil, nil)
	ok := []string{"https://example.com", "example.com", "93.184.215.14:8443", "does-not-resolve.example"}
	bad := []string{
		"http://127.0.0.1:8080", "localhost.:80", "10.0.0.5", "192.168.1.1", "172.16.0.1",
		"http://169.254.169.254/latest/meta-data/", "[::1]:80", "http://[fd00:ec2::254]/",
		"100.64.1.1", "0.0.0.0", "intranet.corp", "rebind.attacker", "metadata.internal",
		"http://[::ffff:127.0.0.1]/", "http://localhost:3000", "api.localhost",
	}
	for _, target := range ok {
		if err := c.Check(context.Background(), target); err != nil {
			t.Errorf("Check(%q) = %v, want allowed", target, err)
		}
	}
	for _, target := range bad {
		err := c.Check(context.Background(), target)
		if !errors.Is(err, ErrOutOfScope) {
			t.Errorf("Check(%q) = %v, want ErrOutOfScope", target, err)
		}
	}
	if c.AllowsLocalNetwork() {
		t.Error("default policy must not allow the local network")
	}
}

func TestAllowPrivateStillBlocksMetadata(t *testing.T) {
	c := mustNew(t, true, nil, nil)
	if err := c.Check(context.Background(), "10.0.0.5"); err != nil {
		t.Errorf("private target refused with allow_private_targets: %v", err)
	}
	for _, target := range []string{"169.254.169.254", "metadata.internal", "100.100.100.200"} {
		if err := c.Check(context.Background(), target); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("metadata %q allowed: %v", target, err)
		}
	}
	if !c.AllowsLocalNetwork() {
		t.Error("AllowsLocalNetwork must be true")
	}
}

func TestAllowList(t *testing.T) {
	c := mustNew(t, false, []string{"*.example.com", "10.1.0.0/16", "169.254.169.254"}, nil)
	ok := []string{"app.example.com", "https://deep.app.example.com/x", "intranet.corp", "10.1.200.1", "169.254.169.254"}
	bad := []string{"example.com", "93.184.215.14", "10.2.0.1", "unknown.host"}
	for _, target := range ok {
		if err := c.Check(context.Background(), target); err != nil {
			t.Errorf("Check(%q) = %v, want allowed", target, err)
		}
	}
	for _, target := range bad {
		if err := c.Check(context.Background(), target); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("Check(%q) = %v, want ErrOutOfScope", target, err)
		}
	}
	if !c.AllowsLocalNetwork() {
		t.Error("an allow list with a private CIDR must allow the local network")
	}
}

func TestDenyList(t *testing.T) {
	c := mustNew(t, true, nil, []string{"example.com", "10.9.0.0/16"})
	for _, target := range []string{"https://example.com/", "10.9.1.1"} {
		if err := c.Check(context.Background(), target); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("denied %q allowed: %v", target, err)
		}
	}
	if err := c.Check(context.Background(), "app.example.com"); err != nil {
		t.Errorf("exact deny must not cover subdomains: %v", err)
	}
}

func TestHost(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM:8443/path?q=1": "example.com",
		"example.com":                       "example.com",
		"example.com.":                      "example.com",
		"example.com:8080":                  "example.com",
		"example.com/path":                  "example.com",
		"10.0.0.1":                          "10.0.0.1",
		"[::1]:443":                         "::1",
		"::1":                               "::1",
	}
	for in, want := range cases {
		got, err := Host(in)
		if err != nil || got != want {
			t.Errorf("Host(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "  ", "http://", "a b.com", "x.com\n-t evil"} {
		if _, err := Host(in); err == nil {
			t.Errorf("Host(%q) should fail", in)
		}
	}
}

func TestInvalidRules(t *testing.T) {
	if _, err := New(false, []string{"10.0.0.0/99"}, nil); err == nil || !strings.Contains(err.Error(), "allowed_targets") {
		t.Errorf("expected CIDR error, got %v", err)
	}
}
