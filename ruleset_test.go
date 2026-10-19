package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

func TestRulesetChanged(t *testing.T) {
	appliedPath := filepath.Join(t.TempDir(), "ips-v4")
	content := []byte("173.245.48.0/20 all 443 # Cloudflare IPs\n103.21.244.0/22 all 443 # Cloudflare IPs")

	changed, err := rulesetChanged(appliedPath, content)
	if err != nil || !changed {
		t.Fatalf("no applied copy: got changed=%v err=%v, want changed=true", changed, err)
	}

	err = os.WriteFile(appliedPath, content, 0644)
	if err != nil {
		t.Fatal(err)
	}

	changed, err = rulesetChanged(appliedPath, content)
	if err != nil || changed {
		t.Fatalf("same content: got changed=%v err=%v, want changed=false", changed, err)
	}

	changed, err = rulesetChanged(appliedPath, []byte("173.245.48.0/20 tcp 443 # Cloudflare IPs\n103.21.244.0/22 tcp 443 # Cloudflare IPs"))
	if err != nil || !changed {
		t.Fatalf("protocol changed: got changed=%v err=%v, want changed=true", changed, err)
	}

	changed, err = rulesetChanged(appliedPath, []byte("173.245.48.0/20 all 443 # Cloudflare IPs"))
	if err != nil || !changed {
		t.Fatalf("ip removed: got changed=%v err=%v, want changed=true", changed, err)
	}

	changed, err = rulesetChanged(t.TempDir(), content)
	if err == nil || !changed {
		t.Fatalf("unreadable applied copy: got changed=%v err=%v, want changed=true with error", changed, err)
	}
}

// Runs the fetch, dry run and apply steps against a local list server several
// times and checks that only runs with a changed list reach ufw.
func TestFetchRulesetsSkipsUnchangedLists(t *testing.T) {
	if !lib.IsTestMode() {
		t.Skip("adds real ufw rules, run it inside the test container with `just test`")
	}

	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	serveDir := t.TempDir()
	server := httptest.NewServer(http.FileServer(http.Dir(serveDir)))
	defer server.Close()

	rulesetDir := t.TempDir()
	for _, dir := range []string{"tmp", "rules"} {
		err := os.MkdirAll(filepath.Join(rulesetDir, dir), os.ModePerm)
		if err != nil {
			t.Fatal(err)
		}
	}

	steps := []struct {
		name        string
		list        string
		port        string
		wantChanged int
		wantRules   []string
	}{
		{
			name:        "new list is applied",
			list:        "192.0.2.0/24 # TEST-NET-1\n198.51.100.7\n",
			port:        "443",
			wantChanged: 1,
			wantRules: []string{
				"ufw allow from 192.0.2.0/24 to any port 443 proto tcp comment 'Test list'",
				"ufw allow from 198.51.100.7 to any port 443 proto tcp comment 'Test list'",
			},
		},
		{
			name:        "unchanged list is skipped",
			list:        "192.0.2.0/24 # TEST-NET-1\n198.51.100.7\n",
			port:        "443",
			wantChanged: 0,
		},
		{
			name:        "comment only change in list is skipped",
			list:        "# updated daily\n192.0.2.0/24 # TEST-NET-1\n198.51.100.7 # single host\n",
			port:        "443",
			wantChanged: 0,
		},
		{
			name:        "added ip is applied",
			list:        "192.0.2.0/24 # TEST-NET-1\n198.51.100.7\n203.0.113.0/24\n",
			port:        "443",
			wantChanged: 1,
			wantRules: []string{
				"ufw allow from 203.0.113.0/24 to any port 443 proto tcp comment 'Test list'",
			},
		},
		{
			name:        "port change in config is applied",
			list:        "192.0.2.0/24 # TEST-NET-1\n198.51.100.7\n203.0.113.0/24\n",
			port:        "8443",
			wantChanged: 1,
			wantRules: []string{
				"ufw allow from 192.0.2.0/24 to any port 8443 proto tcp comment 'Test list'",
				"ufw allow from 198.51.100.7 to any port 8443 proto tcp comment 'Test list'",
				"ufw allow from 203.0.113.0/24 to any port 8443 proto tcp comment 'Test list'",
			},
		},
	}

	for _, step := range steps {
		ok := t.Run(step.name, func(t *testing.T) {
			logger := zerolog.New(zerolog.ConsoleWriter{
				Out:          zerolog.NewTestWriter(t),
				NoColor:      true,
				PartsExclude: []string{zerolog.TimestampFieldName},
			})

			err := os.WriteFile(filepath.Join(serveDir, "test-list"), []byte(step.list), 0644)
			if err != nil {
				t.Fatal(err)
			}

			lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesetDir: rulesetDir}
			lib.UfwApplyConfig.RuleSources = []struct {
				Url      string `yaml:"url"`
				Protocol string `yaml:"protocol"`
				Port     string `yaml:"port"`
				Comment  string `yaml:"comment"`
			}{
				{Url: server.URL + "/test-list", Protocol: "tcp", Port: step.port, Comment: "Test list"},
			}

			changedRulesets := FetchRulesets(logger)
			if len(changedRulesets) != step.wantChanged {
				t.Fatalf("got %d changed rulesets %v, want %d", len(changedRulesets), changedRulesets, step.wantChanged)
			}

			err = UfwApplyDryRun(logger, changedRulesets)
			if err != nil {
				t.Fatalf("dry run failed: %v", err)
			}

			err = UfwApply(logger, changedRulesets)
			if err != nil {
				t.Fatalf("apply failed: %v", err)
			}

			tmpFiles, err := os.ReadDir(filepath.Join(rulesetDir, "tmp"))
			if err != nil {
				t.Fatal(err)
			}
			if len(tmpFiles) != 0 {
				t.Errorf("tmp dir still has %d file(s) after apply, want 0", len(tmpFiles))
			}

			_, err = os.Stat(filepath.Join(rulesetDir, "rules", "test-list"))
			if err != nil {
				t.Errorf("applied copy of the list is missing: %v", err)
			}

			output, err := exec.Command("ufw", "show", "added").CombinedOutput()
			if err != nil {
				t.Fatalf("ufw show added failed: %v\n%s", err, output)
			}

			for _, rule := range step.wantRules {
				if !strings.Contains(string(output), rule) {
					t.Errorf("ufw is missing rule %q, got:\n%s", rule, output)
				}
			}
		})

		if !ok {
			t.FailNow()
		}
	}
}
