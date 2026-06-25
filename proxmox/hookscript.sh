#!/bin/bash
# hookscript.sh — IMPROVED version of the existing production hookscript
# Original at: /var/lib/vz/snippets/hookscript.sh
# Change vs original: adds post-stop phase logging (informational only).
# Core logic (delegating to dump_memory.sh) is UNCHANGED.

VM_ID="$1"
EXECUTION_PHASE="$2"
HOOK_LOG=/extra/cape/memdump-hook.log
DUMP_SCRIPT="/var/lib/vz/snippets/dump_memory.sh"

echo "---- $(date) HOOKSCRIPT vmid=$VM_ID phase=$EXECUTION_PHASE ----" >> "$HOOK_LOG"
logger "HOOKSCRIPT: vmid=$VM_ID phase=$EXECUTION_PHASE"

if [ "$EXECUTION_PHASE" = "post-start" ]; then
    echo "Starting memory dump process..." >> "$HOOK_LOG"
    nohup /bin/bash "$DUMP_SCRIPT" "$VM_ID" >> "$HOOK_LOG" 2>&1 &
    echo "Memory dump process started for VM $VM_ID" >> "$HOOK_LOG"

elif [ "$EXECUTION_PHASE" = "pre-stop" ]; then
    echo "Stopping memory dump process for VM $VM_ID..." >> "$HOOK_LOG"
    pkill -f "bash $DUMP_SCRIPT $VM_ID"
    echo "Memory dump process stopped for VM $VM_ID." >> "$HOOK_LOG"

# NEW: informational only, does not change behavior
elif [ "$EXECUTION_PHASE" = "post-stop" ]; then
    PENDING=$(find /extra/cape/memdumps -name "*.zst" -newer /extra/cape/memdump-hook.log 2>/dev/null | wc -l)
    echo "VM $VM_ID stopped. Pending undelivered dumps in directory: $PENDING" >> "$HOOK_LOG"
fi
