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

// /dev/shm is its own mount, so the applied copy can't be renamed into t.TempDir() and has to be written
func TestSaveAppliedRulesetAcrossFilesystems(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/dev/shm", "ufwApply-")
	if err != nil {
		t.Skipf("no /dev/shm to put the tmp dir on another filesystem: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	content := []byte("192.0.2.0/24 tcp 443 # Test list\n198.51.100.7 tcp 443 # Test list")
	tmpPath := filepath.Join(tmpDir, "test-list")
	appliedPath := filepath.Join(t.TempDir(), "test-list")

	err = os.WriteFile(tmpPath, content, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = saveAppliedRuleset(tmpPath, appliedPath, content)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}

	applied, err := os.ReadFile(appliedPath)
	if err != nil {
		t.Fatalf("applied copy is missing: %v", err)
	}
	if string(applied) != string(content) {
		t.Errorf("applied copy is %q, want %q", applied, content)
	}
}

func TestSetDefaultDirs(t *testing.T) {
	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	tests := []struct {
		name   string
		config lib.UfwApplyConfigType
		want   [3]string // ruleset-dir, rules-dir, tmp-dir-base
	}{
		{
			name:   "nothing set",
			config: lib.UfwApplyConfigType{},
			want:   [3]string{"/etc/mono/ufw-rulesets", "/etc/mono/ufw-rulesets/rules", "/etc/mono/ufw-rulesets/tmp"},
		},
		{
			name:   "only ruleset-dir set",
			config: lib.UfwApplyConfigType{RulesetDir: "/var/lib/ufw-rulesets"},
			want:   [3]string{"/var/lib/ufw-rulesets", "/var/lib/ufw-rulesets/rules", "/var/lib/ufw-rulesets/tmp"},
		},
		{
			name:   "everything set",
			config: lib.UfwApplyConfigType{RulesetDir: "/var/lib/ufw-rulesets", RulesDir: "/var/lib/ufw-rules", TmpDirBase: "/tmp/ufw-applier"},
			want:   [3]string{"/var/lib/ufw-rulesets", "/var/lib/ufw-rules", "/tmp/ufw-applier"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lib.UfwApplyConfig = test.config

			setDefaultDirs()

			got := [3]string{lib.UfwApplyConfig.RulesetDir, lib.UfwApplyConfig.RulesDir, lib.UfwApplyConfig.TmpDirBase}
			if got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
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

	rulesDir := t.TempDir()

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

			// every run gets its own tmp directory, like main does
			tmpDir := t.TempDir()

			lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesDir: rulesDir}
			lib.UfwApplyConfig.RuleSources = []struct {
				Url      string `yaml:"url"`
				Protocol string `yaml:"protocol"`
				Port     string `yaml:"port"`
				Comment  string `yaml:"comment"`
			}{
				{Url: server.URL + "/test-list", Protocol: "tcp", Port: step.port, Comment: "Test list"},
			}

			changedRulesets := FetchRulesets(logger, tmpDir)
			if len(changedRulesets) != step.wantChanged {
				t.Fatalf("got %d changed rulesets %v, want %d", len(changedRulesets), changedRulesets, step.wantChanged)
			}

			err = UfwApplyDryRun(logger, tmpDir, changedRulesets)
			if err != nil {
				t.Fatalf("dry run failed: %v", err)
			}

			err = UfwApply(logger, tmpDir, changedRulesets)
			if err != nil {
				t.Fatalf("apply failed: %v", err)
			}

			tmpFiles, err := os.ReadDir(tmpDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(tmpFiles) != 0 {
				t.Errorf("tmp dir still has %d file(s) after apply, want 0", len(tmpFiles))
			}

			_, err = os.Stat(filepath.Join(rulesDir, "test-list"))
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
