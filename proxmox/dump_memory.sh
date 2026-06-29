#!/bin/bash
# dump_memory.sh — IMPROVED version
# Original at: /var/lib/vz/snippets/dump_memory.sh
#
# FIX: the original script deletes the dump with `rm -f` regardless of
#      whether curl succeeded, causing permanent data loss if VM 161
#      (CAPE) is unreachable. This version:
#        1. Checks curl's exit code explicitly
#        2. Retries up to MAX_RETRIES times with a delay between attempts
#        3. Only deletes the dump if it was confirmed sent
#        4. If all retries fail, KEEPS the file and logs how to resend it
#
# Core dump-capture logic (QMP dump-guest-memory, compression) is UNCHANGED.

VM_ID=$1
DUMP_DIR="/extra/cape/memdumps"
LOG="${DUMP_DIR}/dump_memory.log"
HOST_IP=10.10.10.161
PORT=8888
MAX_RETRIES=3
RETRY_DELAY=10

function start_dump_memory {
    echo "Waiting for 30 seconds..." >> "$LOG"
    sleep 30
    date >> "$LOG"
    echo "Starting memory dump..." >> "$LOG"
    dump_memory &
}

function dump_memory {
    DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    DUMP_FILE="memdump_$DATE.raw"

    echo '{ "execute": "qmp_capabilities" } {"execute": "dump-guest-memory","arguments": { "paging": false, "protocol": "file:'"${DUMP_DIR}/${DUMP_FILE}"'", "detach": true}}' | socat - UNIX-CONNECT:/var/run/qemu-server/$VM_ID.qmp >> "$LOG"

    while true; do
        status=$(echo '{ "execute": "qmp_capabilities" } { "execute": "query-dump" }' | socat - UNIX-CONNECT:/var/run/qemu-server/$VM_ID.qmp | tail -n +3 | jq .return.status | sed 's/"//g')
        echo "$status" >> "$LOG"
        if [[ "$status" == "completed" ]]; then
            echo "Process completed!" >> "$LOG"
            break
        fi
        sleep 2
    done

    echo "Starting compression" >> "$LOG"
    zstd -8 -T4 "${DUMP_DIR}/${DUMP_FILE}" -o "${DUMP_DIR}/${DUMP_FILE}.zst" >> "$LOG"

    # ── FIX: retry loop with explicit success check ──
    SENT=false
    attempt=1
    while [ $attempt -le $MAX_RETRIES ]; do
        echo "Sending dump to CAPE VM (attempt ${attempt}/${MAX_RETRIES})..." >> "$LOG"
	curl -sf -X POST -H "Content-Type: application/octet-stream" \
            --data-binary "@${DUMP_DIR}/${DUMP_FILE}.zst" \
            -m 30 \
            "http://${HOST_IP}:${PORT}/" >> "$LOG" 2>&1
        
        CURL_EXIT=$?

        if [ $CURL_EXIT -eq 0 ]; then
            echo "Dump sent successfully on attempt ${attempt}." >> "$LOG"
            SENT=true
            break
        fi
        
        echo "Attempt ${attempt} failed (curl exit code ${CURL_EXIT}). Retrying in ${RETRY_DELAY}s..." >> "$LOG"
        sleep "$RETRY_DELAY"
        attempt=$((attempt + 1))
    done

    # ── FIX: only delete if confirmed sent ──
    if [ "$SENT" = true ]; then
        echo "Deleting local files (confirmed delivered)" >> "$LOG"
        rm -f "${DUMP_DIR}/${DUMP_FILE}"
        rm -f "${DUMP_DIR}/${DUMP_FILE}.zst"
    else
        echo "ERROR: All ${MAX_RETRIES} attempts failed. Dump KEPT at ${DUMP_DIR}/${DUMP_FILE}.zst" >> "$LOG"
        echo "ERROR: To resend manually later, run:" >> "$LOG"
        echo "  curl -X POST -H 'Content-Type: application/octet-stream' --data-binary @${DUMP_DIR}/${DUMP_FILE}.zst http://${HOST_IP}:${PORT}/" >> "$LOG"
        # Raw .raw file still removed to save disk space; .zst is the one kept
        rm -f "${DUMP_DIR}/${DUMP_FILE}"
    fi
}

start_dump_memory
