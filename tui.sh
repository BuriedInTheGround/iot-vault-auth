#!/usr/bin/env bash

set -euo pipefail

warningf() {
    fmt="$1"
    shift
    # shellcheck disable=SC2059
    printf "$PROG_NAME: warning: $fmt\n" "$@"
}

errorf() {
    fmt="$1"
    shift
    # shellcheck disable=SC2059
    printf "$PROG_NAME: error: $fmt\n" "$@"
    exit 1
}
