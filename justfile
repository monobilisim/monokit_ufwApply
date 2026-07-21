# justfile for a monokit2 plugin — compile & test recipes.
# Run `just` or `just --list` to see the available recipes.
#
# This file is plugin-agnostic: the plugin name (used for the output binary name)
# is derived from the directory name, so the same justfile can be copied verbatim
# into any plugin directory.

# Plugin name == directory name == output binary name.
plugin  := file_name(justfile_directory())
# Podman/OCI image + volume names must be lowercase.
image   := lowercase(plugin) + "-tests"
# Version stamped into the binary via -ldflags. Override with `VERSION=1.0.0 just ...`.
version := env("VERSION", "devel")
# Output directory: this plugin's own ./bin (kept self-contained per plugin/repo).
bindir  := justfile_directory() / "bin"

# Show the available recipes.
default:
    @just --list

# Build the plugin for the host platform into ./bin/<plugin>.
build:
    @echo "Building {{plugin}} {{version}} for the host platform"
    mkdir -p "{{bindir}}"
    rm -f "{{bindir}}/{{plugin}}"
    go build -ldflags "-X main.version={{version}}" -o "{{bindir}}/{{plugin}}"

# Clean, then cross-compile the plugin for every release target.
build-all: clean (build-target "linux" "amd64") (build-target "linux" "arm64")

# Cross-compile the plugin for a single GOOS/GOARCH target.
build-target goos goarch:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{bindir}}"
    ext=""
    [ "{{goos}}" = "windows" ] && ext=".exe"
    out="{{bindir}}/{{plugin}}_{{version}}_{{goos}}_{{goarch}}${ext}"
    echo "Building {{plugin}} {{version}} for {{goos}} {{goarch}}"
    GOOS={{goos}} GOARCH={{goarch}} go build -ldflags "-X 'main.version={{version}}'" -o "$out"

# Run this plugin's tests inside a Podman container (boots systemd as PID 1).
# `just test` runs every test; `just test TestFoo` runs only matching tests.
# Tests ALWAYS run inside Podman — never directly on the host.
test filter="":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{justfile_directory()}}/logs"
    podman build -t {{image}} -f Containerfile .
    podman run --rm -t \
        --systemd=always \
        --tmpfs /run \
        --tmpfs /run/lock \
        -v {{image}}-go-mod-cache:/go/pkg/mod \
        -v {{image}}-go-build-cache:/root/.cache/go-build \
        -v "{{justfile_directory()}}/logs":/artifacts \
        -e TEST_RUN="{{filter}}" \
        -e HOST_UID="$(id -u)" \
        -e HOST_GID="$(id -g)" \
        {{image}}

# Build then run the plugin, forwarding any extra ARGS (e.g. `just run -v`).
run *args: build
    "{{bindir}}/{{plugin}}" {{args}}

# Remove this plugin's build artifacts from ./bin.
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Removing {{plugin}} artifacts from {{bindir}}"
    rm -rf "{{bindir}}"
