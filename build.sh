#!/usr/bin/env bash

set -euo pipefail

PROG_NAME="build.sh"
. "tui.sh"

NIX_LDFLAGS="-rpath ./outputs/out/lib";
export NIX_LDFLAGS

if [[ ! -e ./build ]]; then
    mkdir build
elif [[ ! -d ./build ]]; then
    errorf '"build" exists and it''s not a directory'
fi

go mod tidy
go build -o ./build -ldflags="-s -w" -trimpath ./cmd/...
