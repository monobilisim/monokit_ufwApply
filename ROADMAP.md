# ufwApply Roadmap

UFW firewall rule manager plugin. Feature parity with monokit1 `ufwApply/`.

## Features

- [X] Rule sources: download IP lists from URLs and apply rules (protocol/port/comment per source)
- [X] Static rules applied idempotently
- [X] Dry-run pass before apply
- [X] SHA256 change detection to skip unchanged lists
- [X] Cleanup of rules for lists removed from config
- [X] Static rule removal when dropped from config (last applied copy kept in `<ruleset-dir>/static-rules`)
- [X] Deleting rules a changed list no longer has (dropped IPs, old port/protocol), except rules something else still needs
- [X] `--no-cmdout` style output control (`command-output` in ufw.yml, ufw output always in errors and alarms)
- [X] Configurable `ruleset_dir`, `rules_dir` and `tmp_dir_base` (timestamped temp dir per run)
- [ ] Per-rule comments so rules stay attributable to their source list

