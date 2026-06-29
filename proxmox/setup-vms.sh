#!/bin/bash
# setup-vms.sh — Idempotent VM provisioning for IOC Extractor environment
# Runs on Proxmox host (Valhalla)
# Creates VM 161 (CAPE/Ubuntu) and VM 162 (cuckoo1/Windows) if they don't exist,
# or verifies their configuration if they already exist.
#
# Usage: sudo ./setup-vms.sh

set -e

# ─────────────────────────────────────────────
# Configuration — matches verified real values
# ─────────────────────────────────────────────
VM161_ID=161
VM161_NAME="CAPE"
VM161_CORES=4
VM161_MEMORY=12288
VM161_DISK_SIZE="80G"
VM161_STORAGE="extra2"
VM161_NET0_BRIDGE="vmbr1"
VM161_NET1_BRIDGE="vmbr2"

VM162_ID=162
VM162_NAME="cuckoo1"
VM162_CORES=2
VM162_MEMORY=4096
VM162_DISK_SIZE="60G"
VM162_STORAGE="local2-lvm"
VM162_NET_BRIDGE="vmbr2"
VM162_HOOKSCRIPT="local:snippets/hookscript.sh"

# ─────────────────────────────────────────────
# Helper: check if a VM ID already exists
# ─────────────────────────────────────────────
vm_exists() {
    qm status "$1" &>/dev/null
}

# ─────────────────────────────────────────────
# Helper: verify an existing VM's config matches expectations
# ─────────────────────────────────────────────
verify_vm161() {
    echo "[VM 161] Already exists. Verifying configuration..."
    local conf
    conf=$(qm config "$VM161_ID")

    echo "$conf" | grep -q "cores: $VM161_CORES" && \
        echo "  cores: $VM161_CORES" || \
        echo "  cores mismatch (expected $VM161_CORES)"

    echo "$conf" | grep -q "memory: $VM161_MEMORY" && \
        echo "  memory: $VM161_MEMORY MB" || \
        echo "  memory mismatch (expected $VM161_MEMORY MB)"

    echo "$conf" | grep -q "bridge=$VM161_NET0_BRIDGE" && \
        echo "  net0 bridge: $VM161_NET0_BRIDGE" || \
        echo "  net0 bridge mismatch"

    local status
    status=$(qm status "$VM161_ID" | awk '{print $2}')
    echo "  → Current status: $status"
    if [ "$status" != "running" ]; then
        echo "  → Starting VM 161..."
        qm start "$VM161_ID"
        sleep 5
    fi
}

verify_vm162() {
    echo "[VM 162] Already exists. Verifying configuration..."
    local conf
    conf=$(qm config "$VM162_ID")

    echo "$conf" | grep -q "cores: $VM162_CORES" && \
        echo "  cores: $VM162_CORES" || \
        echo "  cores mismatch (expected $VM162_CORES)"

    echo "$conf" | grep -q "memory: $VM162_MEMORY" && \
        echo "  memory: $VM162_MEMORY MB" || \
        echo "  memory mismatch (expected $VM162_MEMORY MB)"

    echo "$conf" | grep -q "hookscript: $VM162_HOOKSCRIPT" && \
        echo "  hookscript configured" || \
        echo "  hookscript NOT configured — memory capture will not work"

    local status
    status=$(qm status "$VM162_ID" | awk '{print $2}')
    echo "  → Current status: $status (expected: stopped between analyses)"
}

# ─────────────────────────────────────────────
# Create VM 161 from scratch (CAPE / Ubuntu 24.04)
# ─────────────────────────────────────────────
create_vm161() {
    echo "[VM 161] Does not exist. Creating from scratch..."
    echo "  NOTE: this creates an empty VM. You must still install Ubuntu 24.04"
    echo "        manually or via cloud-init, then run the Ansible playbook."

    qm create "$VM161_ID" \
        --name "$VM161_NAME" \
        --cores "$VM161_CORES" \
        --cpu kvm64 \
        --memory "$VM161_MEMORY" \
        --net0 "virtio,bridge=$VM161_NET0_BRIDGE" \
        --net1 "virtio,bridge=$VM161_NET1_BRIDGE" \
        --scsihw virtio-scsi-single \
        --ostype l26 \
        --agent 1 \
        --serial0 socket \
        --boot "order=virtio0;ide2;net0"

    qm set "$VM161_ID" \
        --virtio0 "${VM161_STORAGE}:0,import-from=/dev/null,size=${VM161_DISK_SIZE}" \
        2>/dev/null || \
    qm importdisk "$VM161_ID" /dev/null "$VM161_STORAGE" 2>/dev/null || \
    echo "  → Disk not auto-created. Attach manually: qm set $VM161_ID --virtio0 ${VM161_STORAGE}:${VM161_DISK_SIZE}"

    echo "  VM 161 created (empty). Next steps:"
    echo "    1. Attach Ubuntu 24.04 ISO and install OS"
    echo "    2. Configure network: ens18=10.10.10.161/24, ens19=10.0.100.161/24"
    echo "    3. Run: ./deploy.sh (Ansible playbook will configure the rest)"
}

# ─────────────────────────────────────────────
# Create VM 162 from scratch (cuckoo1 / Windows 10)
# ─────────────────────────────────────────────
create_vm162() {
    echo "[VM 162] Does not exist. Creating from scratch..."
    echo "  NOTE: this creates an empty VM. You must still install Windows 10"
    echo "        manually, then configure it per win10-base snapshot specs."

    qm create "$VM162_ID" \
        --name "$VM162_NAME" \
        --cores "$VM162_CORES" \
        --cpu kvm64 \
        --memory "$VM162_MEMORY" \
        --balloon 0 \
        --net0 "virtio,bridge=$VM162_NET_BRIDGE" \
        --scsihw virtio-scsi-single \
        --ostype win10 \
        --machine pc-i440fx-8.1 \
        --agent 1 \
        --tablet 1 \
        --boot "order=virtio0;net0" \
        --hookscript "$VM162_HOOKSCRIPT"

    echo "  VM 162 created (empty). Next steps:"
    echo "    1. Attach Windows 10 ISO + VirtIO drivers ISO"
    echo "    2. Install Windows, configure per win10-base specs:"
    echo "       - Disable Defender, UAC, Firewall"
    echo "       - Configure autologon"
    echo "       - Install Python agent listening on :8000"
    echo "       - Static IP 10.0.100.162/24 gw 10.0.100.161"
    echo "    3. Shut down and snapshot as 'win10-base'"
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
echo "================================================"
echo " IOC Extractor — VM Provisioning (idempotent)"
echo "================================================"
echo ""

if vm_exists "$VM161_ID"; then
    verify_vm161
else
    create_vm161
fi

echo ""

if vm_exists "$VM162_ID"; then
    verify_vm162
else
    create_vm162
fi

echo ""
echo "================================================"
echo " Provisioning check complete."
echo "================================================"
