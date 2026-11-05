package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

	err = saveAppliedRuleset(tmpPath, appliedPath)
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

func TestRemovedRulesets(t *testing.T) {
	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	rulesDir := t.TempDir()

	for _, fileName := range []string{"ips-v4", "rules2.txt", "old-list"} {
		err := os.WriteFile(filepath.Join(rulesDir, fileName), nil, 0644)
		if err != nil {
			t.Fatal(err)
		}
	}

	err := os.Mkdir(filepath.Join(rulesDir, "subdir"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesDir: rulesDir}
	lib.UfwApplyConfig.RuleSources = []struct {
		Url      string `yaml:"url"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}{
		{Url: "https://www.cloudflare.com/ips-v4/", Protocol: "all", Port: "443"},
		// FetchRulesets skips it for the typo in protocol, but it is still in config
		{Url: "https://example.com/rules2.txt", Protocol: "tpc", Port: "443"},
		{Url: ""},
	}

	got := RemovedRulesets(zerolog.Nop())
	want := []string{"old-list"}

	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Applies two lists that share rules with each other and with a static rule, then drops
// them from config one by one and checks that only rules nothing else needs are deleted.
func TestRemovedRulesetsAreCleanedUp(t *testing.T) {
	if !lib.IsTestMode() {
		t.Skip("adds and deletes real ufw rules, run it inside the test container with `just test`")
	}

	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	serveDir := t.TempDir()
	server := httptest.NewServer(http.FileServer(http.Dir(serveDir)))
	defer server.Close()

	// 198.51.100.21 is in both lists and 198.51.100.22 is also a static rule,
	// list-b is applied last so ufw keeps its comment on both
	lists := map[string]string{
		"list-a": "198.51.100.20\n198.51.100.21\n",
		"list-b": "198.51.100.21/32\n198.51.100.22\n198.51.100.23\n",
	}

	for fileName, list := range lists {
		err := os.WriteFile(filepath.Join(serveDir, fileName), []byte(list), 0644)
		if err != nil {
			t.Fatal(err)
		}
	}

	rulesDir := t.TempDir()

	lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesetDir: t.TempDir(), RulesDir: rulesDir}
	lib.UfwApplyConfig.RuleSources = []struct {
		Url      string `yaml:"url"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}{
		{Url: server.URL + "/list-a", Protocol: "tcp", Port: "2222", Comment: "List A"},
		{Url: server.URL + "/list-b", Protocol: "tcp", Port: "2222", Comment: "List B"},
	}
	lib.UfwApplyConfig.StaticRules = []struct {
		IP       string `yaml:"ip"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}{
		{IP: "198.51.100.22", Protocol: "tcp", Port: "2222", Comment: "Static rule"},
	}
	ruleSources := lib.UfwApplyConfig.RuleSources

	steps := []struct {
		name         string
		lists        int // how many of the rule sources stay in config
		wantRules    []string
		wantNoRules  []string
		wantFileList []string
	}{
		{
			name:         "both lists are applied",
			lists:        2,
			wantRules:    []string{"198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23"},
			wantFileList: []string{"list-a", "list-b"},
		},
		{
			name:         "list-b removed from config",
			lists:        1,
			wantRules:    []string{"198.51.100.20", "198.51.100.21", "198.51.100.22"},
			wantNoRules:  []string{"198.51.100.23"},
			wantFileList: []string{"list-a"},
		},
		{
			// 198.51.100.21 still carries list-b's comment
			name:        "list-a removed from config",
			lists:       0,
			wantRules:   []string{"198.51.100.22"},
			wantNoRules: []string{"198.51.100.20", "198.51.100.21"},
		},
	}

	for _, step := range steps {
		ok := t.Run(step.name, func(t *testing.T) {
			logger := testLogger(t)

			lib.UfwApplyConfig.RuleSources = ruleSources[:step.lists]

			tmpDir := t.TempDir()

			changedRulesets := FetchRulesets(logger, tmpDir)
			removedRulesets := RemovedRulesets(logger)

			err := UfwApplyDryRun(logger, tmpDir, changedRulesets, removedRulesets)
			if err != nil {
				t.Fatalf("dry run failed: %v", err)
			}

			err = UfwApply(logger, tmpDir, changedRulesets, removedRulesets)
			if err != nil {
				t.Fatalf("apply failed: %v", err)
			}

			var wantRules, wantNoRules []string
			for _, ip := range step.wantRules {
				wantRules = append(wantRules, "ufw allow from "+ip+" to any port 2222 proto tcp")
			}
			for _, ip := range step.wantNoRules {
				wantNoRules = append(wantNoRules, "ufw allow from "+ip+" to any port 2222 proto tcp")
			}

			checkUfwRules(t, wantRules, wantNoRules)

			entries, err := os.ReadDir(rulesDir)
			if err != nil {
				t.Fatal(err)
			}

			var fileList []string
			for _, entry := range entries {
				fileList = append(fileList, entry.Name())
			}

			if !slices.Equal(fileList, step.wantFileList) {
				t.Errorf("rules dir has %v, want %v", fileList, step.wantFileList)
			}
		})

		if !ok {
			t.FailNow()
		}
	}
}

// Runs the fetch, dry run and apply steps against a local list server several times and checks
// that only runs with a changed list reach ufw, and that rules the list no longer has are deleted.
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
	rulesDir := t.TempDir()

	steps := []struct {
		name        string
		list        string
		port        string
		wantChanged int
		wantRules   []string
		wantNoRules []string
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
			name:        "removed ip is deleted",
			list:        "192.0.2.0/24 # TEST-NET-1\n203.0.113.0/24\n",
			port:        "443",
			wantChanged: 1,
			wantRules: []string{
				"ufw allow from 192.0.2.0/24 to any port 443 proto tcp comment 'Test list'",
				"ufw allow from 203.0.113.0/24 to any port 443 proto tcp comment 'Test list'",
			},
			wantNoRules: []string{
				"ufw allow from 198.51.100.7 to any port 443 proto tcp",
			},
		},
		{
			name:        "port change in config replaces the old rules",
			list:        "192.0.2.0/24 # TEST-NET-1\n203.0.113.0/24\n",
			port:        "8443",
			wantChanged: 1,
			wantRules: []string{
				"ufw allow from 192.0.2.0/24 to any port 8443 proto tcp comment 'Test list'",
				"ufw allow from 203.0.113.0/24 to any port 8443 proto tcp comment 'Test list'",
			},
			wantNoRules: []string{
				"ufw allow from 192.0.2.0/24 to any port 443 proto tcp",
				"ufw allow from 203.0.113.0/24 to any port 443 proto tcp",
			},
		},
	}

	for _, step := range steps {
		ok := t.Run(step.name, func(t *testing.T) {
			logger := testLogger(t)

			err := os.WriteFile(filepath.Join(serveDir, "test-list"), []byte(step.list), 0644)
			if err != nil {
				t.Fatal(err)
			}

			// every run gets its own tmp directory, like main does
			tmpDir := t.TempDir()

			lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesetDir: rulesetDir, RulesDir: rulesDir}
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

			err = UfwApplyDryRun(logger, tmpDir, changedRulesets, nil)
			if err != nil {
				t.Fatalf("dry run failed: %v", err)
			}

			err = UfwApply(logger, tmpDir, changedRulesets, nil)
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

			checkUfwRules(t, step.wantRules, step.wantNoRules)
		})

		if !ok {
			t.FailNow()
		}
	}
}

// Applies static rules next to a list that shares one of them, then drops and changes them in
// config and checks that only rules nothing else needs are deleted.
func TestRemovedStaticRulesAreDeleted(t *testing.T) {
	if !lib.IsTestMode() {
		t.Skip("adds and deletes real ufw rules, run it inside the test container with `just test`")
	}

	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	serveDir := t.TempDir()
	server := httptest.NewServer(http.FileServer(http.Dir(serveDir)))
	defer server.Close()

	err := os.WriteFile(filepath.Join(serveDir, "list-c"), []byte("198.51.100.32\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesetDir: t.TempDir(), RulesDir: t.TempDir()}
	listC := []struct {
		Url      string `yaml:"url"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}{
		{Url: server.URL + "/list-c", Protocol: "tcp", Port: "2223", Comment: "List C"},
	}

	type staticRule = struct {
		IP       string `yaml:"ip"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}

	steps := []struct {
		name        string
		staticRules []staticRule
		withListC   bool
		wantRules   []string
		wantNoRules []string
	}{
		{
			name: "static rules are applied",
			staticRules: []staticRule{
				{IP: "198.51.100.30", Protocol: "tcp", Port: "2223", Comment: "Static A"},
				{IP: "198.51.100.31", Protocol: "tcp", Port: "2223", Comment: "Static B"},
				{IP: "198.51.100.32", Protocol: "tcp", Port: "2223", Comment: "Static C"},
			},
			withListC: true,
			wantRules: []string{
				"ufw allow from 198.51.100.30 to any port 2223 proto tcp",
				"ufw allow from 198.51.100.31 to any port 2223 proto tcp",
				"ufw allow from 198.51.100.32 to any port 2223 proto tcp",
			},
		},
		{
			// list-c still has 198.51.100.32
			name: "static rules dropped and changed in config",
			staticRules: []staticRule{
				{IP: "198.51.100.31", Protocol: "tcp", Port: "2224", Comment: "Static B"},
			},
			withListC: true,
			wantRules: []string{
				"ufw allow from 198.51.100.31 to any port 2224 proto tcp",
				"ufw allow from 198.51.100.32 to any port 2223 proto tcp",
			},
			wantNoRules: []string{
				"ufw allow from 198.51.100.30 to any port 2223 proto tcp",
				"ufw allow from 198.51.100.31 to any port 2223 proto tcp",
			},
		},
		{
			name: "list-c removed from config",
			staticRules: []staticRule{
				{IP: "198.51.100.31", Protocol: "tcp", Port: "2224", Comment: "Static B"},
			},
			wantRules: []string{
				"ufw allow from 198.51.100.31 to any port 2224 proto tcp",
			},
			wantNoRules: []string{
				"ufw allow from 198.51.100.32 to any port 2223 proto tcp",
			},
		},
		{
			name: "every static rule removed from config",
			wantNoRules: []string{
				"ufw allow from 198.51.100.31 to any port 2224 proto tcp",
			},
		},
	}

	for _, step := range steps {
		ok := t.Run(step.name, func(t *testing.T) {
			logger := testLogger(t)

			lib.UfwApplyConfig.StaticRules = step.staticRules
			lib.UfwApplyConfig.RuleSources = nil
			if step.withListC {
				lib.UfwApplyConfig.RuleSources = listC
			}

			tmpDir := t.TempDir()

			changedRulesets := FetchRulesets(logger, tmpDir)
			removedRulesets := RemovedRulesets(logger)

			err := UfwApplyDryRun(logger, tmpDir, changedRulesets, removedRulesets)
			if err != nil {
				t.Fatalf("dry run failed: %v", err)
			}

			err = UfwApply(logger, tmpDir, changedRulesets, removedRulesets)
			if err != nil {
				t.Fatalf("apply failed: %v", err)
			}

			checkUfwRules(t, step.wantRules, step.wantNoRules)
		})

		if !ok {
			t.FailNow()
		}
	}

	_, err = os.Stat(staticRulesPath())
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("applied static rules are still saved with no static rule in config: %v", err)
	}
}

func TestStaleRules(t *testing.T) {
	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	type staticRule = struct {
		IP       string `yaml:"ip"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}

	rulesDir := t.TempDir()
	tmpDir := t.TempDir()

	lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesetDir: t.TempDir(), RulesDir: rulesDir}

	// nothing has been applied yet
	staleRules, err := StaleRules(zerolog.Nop(), tmpDir, nil, nil)
	if err != nil || len(staleRules) != 0 {
		t.Fatalf("first run: got %v err=%v, want no stale rules", staleRules, err)
	}

	lib.UfwApplyConfig.StaticRules = []staticRule{
		{IP: "198.51.100.40", Protocol: "tcp", Port: "22", Comment: "dropped"},
		{IP: "198.51.100.41", Protocol: "tcp", Port: "22", Comment: "port changed"},
		{IP: "198.51.100.42", Protocol: "tcp", Port: "22", Comment: "dropped, new-list has it"},
		{IP: "198.51.100.43/32", Protocol: "tcp", Port: "22"},
	}

	err = saveStaticRules()
	if err != nil {
		t.Fatal(err)
	}

	lib.UfwApplyConfig.StaticRules = []staticRule{
		{IP: "198.51.100.41", Protocol: "tcp", Port: "2222"},
		{IP: "198.51.100.43", Protocol: "tcp", Port: "22"},
	}

	files := map[string]string{
		// changed drops 192.0.2.2 and 192.0.2.3, unchanged still has 192.0.2.3
		filepath.Join(rulesDir, "changed"):   "192.0.2.1 tcp 443 # Changed\n192.0.2.2 tcp 443 # Changed\n192.0.2.3 tcp 443 # Changed",
		filepath.Join(tmpDir, "changed"):     "192.0.2.1 tcp 443 # Changed",
		filepath.Join(rulesDir, "unchanged"): "192.0.2.3 tcp 443\n192.0.2.10 tcp 443",
		filepath.Join(tmpDir, "new-list"):    "198.51.100.42 tcp 22",
		// 192.0.2.2 is also stale in changed, 198.51.100.41 tcp 2222 is a static rule
		filepath.Join(rulesDir, "removed"): "192.0.2.2 tcp 443\n192.0.2.20 tcp 443\n198.51.100.41 tcp 2222\n192.0.2.21 tcp 443",
	}

	for path, content := range files {
		err := os.WriteFile(path, []byte(content), 0644)
		if err != nil {
			t.Fatal(err)
		}
	}

	staleRules, err = StaleRules(zerolog.Nop(), tmpDir, []string{"changed", "new-list"}, []string{"removed"})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, rule := range staleRules {
		got = append(got, rule.key())
	}

	want := []string{
		"198.51.100.40 tcp 22",
		"198.51.100.41 tcp 22",
		"192.0.2.2 tcp 443",
		"192.0.2.20 tcp 443",
		"192.0.2.21 tcp 443",
	}

	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSaveStaticRules(t *testing.T) {
	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesetDir: t.TempDir()}
	lib.UfwApplyConfig.StaticRules = []struct {
		IP       string `yaml:"ip"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}{
		{IP: "100.110.70.80", Protocol: "tcp", Port: "22", Comment: "SSH Access"},
		{IP: "100.110.70.0/24", Protocol: "all", Port: "80"},
	}

	err := saveStaticRules()
	if err != nil {
		t.Fatal(err)
	}

	saved, err := os.ReadFile(staticRulesPath())
	if err != nil {
		t.Fatal(err)
	}

	want := "100.110.70.80 tcp 22 # SSH Access\n100.110.70.0/24 all 80"
	if string(saved) != want {
		t.Errorf("saved %q, want %q", saved, want)
	}

	rules := parseRuleset(zerolog.Nop(), staticRulesFileName, saved)
	if !slices.Equal(rules, staticRules()) {
		t.Errorf("read back %v, want %v", rules, staticRules())
	}

	lib.UfwApplyConfig.StaticRules = nil

	// once to remove the saved copy and once more when there is nothing left to remove
	for range 2 {
		err = saveStaticRules()
		if err != nil {
			t.Fatalf("no static rules: %v", err)
		}
	}

	_, err = os.Stat(staticRulesPath())
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("saved copy is still there with no static rules: %v", err)
	}
}

func TestRunCommand(t *testing.T) {
	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	off := false

	tests := []struct {
		name          string
		commandOutput *bool
		command       []string
		wantErr       string // empty when the command has to succeed
		wantLog       []string
		wantNoLog     []string
	}{
		{
			name:    "output is logged when command-output is not set",
			command: []string{"sh", "-c", "echo Rule added"},
			wantLog: []string{"sh -c", "Rule added"},
		},
		{
			name:          "nothing is logged with command-output off",
			commandOutput: &off,
			command:       []string{"sh", "-c", "echo Rule added"},
			wantNoLog:     []string{"sh -c", "Rule added"},
		},
		{
			// sh takes the argument after the script as $0, it is only there to look like a dry run,
			// and the output is upper case so it can't be confused with the logged command
			name:      "dry run output is not logged",
			command:   []string{"sh", "-c", "echo generated ruleset | tr a-z A-Z", "--dry-run"},
			wantLog:   []string{"--dry-run"},
			wantNoLog: []string{"GENERATED RULESET"},
		},
		{
			name:          "failed command has its output in the error with command-output off",
			commandOutput: &off,
			command:       []string{"sh", "-c", "echo ERROR: Bad port; exit 1"},
			wantErr:       "exit status 1: ERROR: Bad port",
			wantLog:       []string{"ERROR: Bad port"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lib.UfwApplyConfig = lib.UfwApplyConfigType{CommandOutput: test.commandOutput}

			var logs bytes.Buffer
			err := runCommand(zerolog.New(&logs), exec.Command(test.command[0], test.command[1:]...))

			if test.wantErr == "" && err != nil {
				t.Fatalf("got error %v, want none", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("got error %v, want one with %q", err, test.wantErr)
			}

			for _, want := range test.wantLog {
				if !strings.Contains(logs.String(), want) {
					t.Errorf("log is missing %q, got:\n%s", want, logs.String())
				}
			}

			for _, want := range test.wantNoLog {
				if strings.Contains(logs.String(), want) {
					t.Errorf("log has %q, got:\n%s", want, logs.String())
				}
			}
		})
	}
}

// The alarm shows the error the run fails with, so it has to carry ufw's own message.
func TestUfwErrorIsReturned(t *testing.T) {
	if !lib.IsTestMode() {
		t.Skip("runs ufw, run it inside the test container with `just test`")
	}

	savedConfig := lib.UfwApplyConfig
	t.Cleanup(func() { lib.UfwApplyConfig = savedConfig })

	lib.UfwApplyConfig = lib.UfwApplyConfigType{RulesetDir: t.TempDir(), RulesDir: t.TempDir()}
	lib.UfwApplyConfig.StaticRules = []struct {
		IP       string `yaml:"ip"`
		Protocol string `yaml:"protocol"`
		Port     string `yaml:"port"`
		Comment  string `yaml:"comment"`
	}{
		{IP: "198.51.100.50", Protocol: "tcp", Port: "99999"},
	}

	err := UfwApplyDryRun(testLogger(t), t.TempDir(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "ERROR:") {
		t.Fatalf("got error %v, want one with ufw's message", err)
	}

	t.Logf("dry run failed with: %v", err)
}

func testLogger(t *testing.T) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{
		Out:          zerolog.NewTestWriter(t),
		NoColor:      true,
		PartsExclude: []string{zerolog.TimestampFieldName},
	})
}

// checkUfwRules looks for each rule as a substring of `ufw show added`, so the comment can be left out
func checkUfwRules(t *testing.T, wantRules []string, wantNoRules []string) {
	t.Helper()

	output, err := exec.Command("ufw", "show", "added").CombinedOutput()
	if err != nil {
		t.Fatalf("ufw show added failed: %v\n%s", err, output)
	}

	for _, rule := range wantRules {
		if !strings.Contains(string(output), rule) {
			t.Errorf("ufw is missing rule %q, got:\n%s", rule, output)
		}
	}

	for _, rule := range wantNoRules {
		if strings.Contains(string(output), rule) {
			t.Errorf("ufw still has rule %q, got:\n%s", rule, output)
		}
	}
}
