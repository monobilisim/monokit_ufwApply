# Containerfile for running this plugin's tests under Podman.
#
# ufwApply is Linux-only (it drives `ufw`). The container boots systemd as PID 1
# and MUST be run with `--systemd=always` — that is why we use Podman, not Docker
# (systemd-as-PID1 doesn't work on Docker). Invoke it via `just test`, never by hand.
#
# Note: ufwApply currently ships no tests, so `just test` only verifies that the
# package compiles (go test reports "no test files").
FROM golang:1.25-trixie

ENV container=podman
ENV DEBIAN_FRONTEND=noninteractive
ENV CGO_ENABLED=1

WORKDIR /app

# build-essential + CGO_ENABLED: monokit_lib uses the sqlite (cgo) driver.
# systemd / systemd-sysv / dbus: PID 1 runs systemd for the test harness.
# ufw: the plugin's runtime dependency.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        systemd \
        systemd-sysv \
        dbus \
        ufw && \
    rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3

# Copy the whole plugin and warm the module cache (monokit_lib is a normal module).
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# lib.InitConfig reads config from /etc/mono.
RUN mkdir -p /etc/mono && \
    cp config/* /etc/mono/ && \
    chmod +x scripts/collect-test-artifacts.sh

# Test harness: tests.service runs `go test`, records the exit code, collects
# artifacts and powers off; exit-code.service propagates the code as the
# container's exit status.
RUN cp scripts/tests.service scripts/exit-code.service /etc/systemd/system/ && \
    cp scripts/exit.target /etc/systemd/system/ && \
    systemctl enable tests.service exit-code.service

ENTRYPOINT ["/sbin/init"]
