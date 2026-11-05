package ctf

import (
	"testing"
	"time"
)

func TestParseConnect(t *testing.T) {
	cases := []struct {
		in        string
		host, url string
		port      int
		tls       bool
		cmd       string
		wantNil   bool
	}{
		{in: "nc chall.example.com 1337", host: "chall.example.com:1337", port: 1337, cmd: "nc chall.example.com 1337"},
		{in: "Connect with `ncat -v 10.0.0.2 9001` now", host: "10.0.0.2:9001", port: 9001, cmd: "nc 10.0.0.2 9001"},
		{in: "openssl s_client -quiet -connect pwn.example.com:443", host: "pwn.example.com:443", port: 443, tls: true,
			cmd: "openssl s_client -quiet -connect pwn.example.com:443"},
		{in: "see https://web.example.com/login.", host: "web.example.com", url: "https://web.example.com/login", port: 443, tls: true},
		{in: "http://1.2.3.4:8080/", host: "1.2.3.4:8080", url: "http://1.2.3.4:8080/", port: 8080},
		{in: "host: misc.example.org:31337", host: "misc.example.org:31337", port: 31337, cmd: "nc misc.example.org 31337"},
		{in: "no target here", wantNil: true},
		{in: "", wantNil: true},
	}
	for _, c := range cases {
		got := ParseConnect(c.in)
		if c.wantNil {
			if got != nil {
				t.Errorf("%q: want nil, got %+v", c.in, got)
			}
			continue
		}
		if got == nil || got.Host != c.host || got.URL != c.url || got.Port != c.port || got.TLS != c.tls || got.Command != c.cmd {
			t.Errorf("%q: got %+v", c.in, got)
		}
	}
}

func TestTimestamp(t *testing.T) {
	want := "2026-10-23T14:31:40Z"
	for _, in := range []any{"2026-10-23T14:31:40Z", "2026-10-23T22:31:40+08:00", "2026-10-23 14:31:40",
		float64(1792765900), "1792765900", int64(1792765900000)} {
		if got := Timestamp(in); got != want {
			t.Errorf("Timestamp(%v) = %q, want %q", in, got, want)
		}
	}
	if Timestamp("soon") != "" || Timestamp(nil) != "" || Timestamp(0.0) != "" {
		t.Error("unparseable input must give empty")
	}
}

func TestValidateInstance(t *testing.T) {
	ok := &Instance{Action: InstanceStart, State: InstanceRunning, Connect: &Connect{Host: "h:1"}, Expires: time.Now().UTC().Format(time.RFC3339)}
	if err := ValidateInstance(ok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]*Instance{
		"state":   {Action: InstanceStart, State: "started"},
		"action":  {Action: "restart", State: InstanceStopped},
		"connect": {Action: InstanceStatus, State: InstanceRunning},
		"expires": {Action: InstanceStatus, State: InstanceStopped, Expires: "in 10 min"},
	} {
		if ValidateInstance(bad) == nil {
			t.Errorf("%s: invalid instance accepted", name)
		}
	}
}

func TestCapabilitiesSupports(t *testing.T) {
	c := Capabilities{Instances: true, InstanceActions: []string{InstanceStart}}
	if !c.Supports(InstanceStatus) || !c.Supports(InstanceStart) || c.Supports(InstanceStop) {
		t.Fatalf("supports: %+v", c)
	}
	if (Capabilities{}).Supports(InstanceStatus) {
		t.Fatal("no instances must support nothing")
	}
}
