#!/usr/bin/env bash

set -euo pipefail

PROG_NAME="build.sh"
. "tui.sh"

DEVICE_COUNT=1
if [[ "$#" -gt 0 && "$1" =~ ^[0-9]+$ && "$1" -lt 1000 ]]; then
    DEVICE_COUNT="$1"
fi

VAULTS=""
for ((i = 1; i <= "$DEVICE_COUNT"; i++)); do
    DEVICE_ID=$(printf '%03d' "$i")
    VAULT_FILE="./build/${DEVICE_ID}.vault"
    ./build/vaultgen "$VAULT_FILE"

    # Used for starting the server.
    VAULTS="$VAULTS $VAULT_FILE"
done
echo "Initial secure vaults generated."
echo "----------------------------------------"

# shellcheck disable=SC2064
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

# shellcheck disable=SC2086
./build/server > ./build/server.log $VAULTS 2>&1 &
sleep 1
echo "Server started. See its logs at: ./build/server.log"
echo "----------------------------------------"

for ((i = 1; i <= "$DEVICE_COUNT"; i++)); do
    DEVICE_ID=$(printf '%03d' "$i")
    VAULT_FILE="./build/${DEVICE_ID}.vault"
    LOG_FILE="./build/device${DEVICE_ID}.log"
    ./build/device > "$LOG_FILE" "$VAULT_FILE" 2>&1 &
    echo "Device $DEVICE_ID started. See its logs at: $LOG_FILE"
done

echo "----------------------------------------"
echo -n "Press Ctrl+C to stop."

# shellcheck disable=SC2046
wait $(jobs -p)
