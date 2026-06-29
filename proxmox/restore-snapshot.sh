#!/bin/bash
# restore-snapshot.sh — Restores VM 162 (Windows) to its clean snapshot
# Run this after each malware analysis to ensure the next run starts fresh.
#
# Usage: ./restore-snapshot.sh [snapshot_name]
#   Default snapshot_name: win10-base

set -e

VM162_ID=162
SNAPSHOT_NAME="${1:-win10-base}"

echo "================================================"
echo " Restoring VM ${VM162_ID} to snapshot: ${SNAPSHOT_NAME}"
echo "================================================"

# Check VM exists
if ! qm status "$VM162_ID" &>/dev/null; then
    echo "[ERROR] VM ${VM162_ID} does not exist."
    exit 1
fi

# Check snapshot exists
if ! qm listsnapshot "$VM162_ID" | grep -q "$SNAPSHOT_NAME"; then
    echo "[ERROR] Snapshot '${SNAPSHOT_NAME}' not found on VM ${VM162_ID}."
    echo "Available snapshots:"
    qm listsnapshot "$VM162_ID"
    exit 1
fi

# Stop VM if running
STATUS=$(qm status "$VM162_ID" | awk '{print $2}')
if [ "$STATUS" == "running" ]; then
    echo "[1/3] VM is running. Stopping..."
    qm stop "$VM162_ID"
    sleep 3
else
    echo "[1/3] VM already stopped."
fi

# Rollback to snapshot
echo "[2/3] Rolling back to snapshot '${SNAPSHOT_NAME}'..."
qm rollback "$VM162_ID" "$SNAPSHOT_NAME"

echo "[3/3] Restore complete. VM ${VM162_ID} is ready for the next analysis."
echo "================================================"
