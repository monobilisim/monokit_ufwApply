# ufwApply Roadmap

UFW firewall rule manager plugin. Feature parity with monokit1 `ufwApply/`.

## Features

- [X] Rule sources: download IP lists from URLs and apply rules (protocol/port/comment per source)
- [X] Static rules applied idempotently
- [X] Dry-run pass before apply
- [ ] SHA256 change detection to skip unchanged lists
- [ ] Cleanup of rules for lists removed from config
- [ ] Static rule removal when dropped from config
- [ ] `--no-cmdout` style output control
