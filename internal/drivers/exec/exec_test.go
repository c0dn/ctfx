package exec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// plugin writes a shell driver that answers each op from a case statement.
func plugin(t *testing.T, cases string) ctf.Driver {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "ctfx-driver-t")
	script := "#!/bin/sh\ncat >/dev/null\ncase \"$1\" in\n" + cases + "\n*) echo '{\"error\":{\"kind\":\"unsupported\",\"message\":\"no\"}}';;\nesac\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := Spec("t", p).New(&driver.Env{Config: &config.Config{Platform: "t", Root: dir, Values: map[string]string{}}})
	if err != nil {
		t.Fatal(err)
	}
	return ctf.Checked("t", d)
}

const caps = `capabilities) echo '{"result":{"protocol":2,"challenges":true,"submit":true,"instances":true,"instance_actions":["start","stop"]}}';;`

func TestProtocolMismatchRefused(t *testing.T) {
	d := plugin(t, `capabilities) echo '{"result":{"challenges":true}}';;`)
	_, err := d.ListChallenges(context.Background())
	if ctf.KindOf(err) != ctf.KindConfig || !strings.Contains(err.Error(), "protocol 0") {
		t.Fatalf("want a protocol refusal, got %v", err)
	}
}

func TestTimeoutKillsDriver(t *testing.T) {
	d := plugin(t, caps+"\nlist_challenges) sleep 5;;")
	d.(interface{ Unwrap() ctf.Driver }).Unwrap().(*Driver).timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := d.ListChallenges(context.Background())
	if ctf.KindOf(err) != ctf.KindTimeout {
		t.Fatalf("want timeout, got %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("timeout did not kill the driver (%s)", time.Since(start))
	}
}

func TestContractViolations(t *testing.T) {
	d := plugin(t, caps+`
submit) echo '{"result":{"status":"wrong"}}';;
instance) echo '{"result":{"state":"started","action":"start"}}';;
get_challenge) echo '{"result":{"id":"1","name":"a","connection":{"command":"nc"}}}';;`)
	ctx := context.Background()
	if _, err := d.Submit(ctx, "1", "f"); err == nil || !strings.Contains(err.Error(), "status \"wrong\"") {
		t.Fatalf("bad submit status accepted: %v", err)
	}
	if _, err := d.Instance(ctx, ctf.InstanceStart, "1"); err == nil || !strings.Contains(err.Error(), "state \"started\"") {
		t.Fatalf("bad instance state accepted: %v", err)
	}
	if _, err := d.GetChallenge(ctx, "1"); err == nil || !strings.Contains(err.Error(), "host or url") {
		t.Fatalf("connection without host accepted: %v", err)
	}
}

func TestResetFallsBackToStopStart(t *testing.T) {
	d := plugin(t, caps+`
instance) echo '{"result":{"state":"running","action":"start","connect":{"host":"h:1","port":1}}}';;`)
	inst, err := d.Instance(context.Background(), ctf.InstanceReset, "1")
	if err != nil || inst.State != ctf.InstanceRunning || inst.Action != ctf.InstanceReset {
		t.Fatalf("reset = %+v %v", inst, err)
	}
	if _, err := d.Instance(context.Background(), ctf.InstanceExtend, "1"); ctf.KindOf(err) != ctf.KindUnsupported {
		t.Fatalf("unadvertised extend: %v", err)
	}
}

func TestExpiredKindPassesThrough(t *testing.T) {
	d := plugin(t, caps+`
list_challenges) echo '{"error":{"kind":"expired","message":"session expired"}}';;`)
	if _, err := d.ListChallenges(context.Background()); ctf.KindOf(err) != ctf.KindExpired {
		t.Fatalf("want expired, got %v", err)
	}
}
