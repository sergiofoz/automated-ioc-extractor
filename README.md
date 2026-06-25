# Instructions

This repository contains the code to run an automated malware analysis pipeline
using VMs running on a Proxmox VE server.

To run this pipeline, you must ensure the following requirements are fulfilled.

## Proxmox VE

This pipeline should be compatible with any version of Proxmox VE 8.0 or
greater.

#### Step 1

Ensure that you have at least two bridge interfaces configured:

- **vmbrX**: Interface for accessing CAPE and also provide Internet access to
  the VM.
- **vmbrY**: Interface for internal network without Internet access to allow
  communication between CAPE and Windows.

#### Step 2

Create 2 VMs, one with Ubuntu 24.04 (CAPE) and another with Windows 10
(cuckoo1). Ubuntu VM should have both interfaces attached, while Windows VM just
need vmbrY.

#### Step 3

Place both the scripts from [proxmox
folder](https://github.com/iciouss/automated-ioc-extractor/tree/main/proxmox)
in /var/vz/lib/snippets/ and configure
[hookscript.sh](https://github.com/iciouss/automated-ioc-extractor/blob/main/proxmox/hookscript.sh)
to run when Windows VM starts. Do it with command:

`qm set <vmid> ---hookscript local:snippets/hookscript.sh`

## Ubuntu 24.04 (CAPE)

Ensure Ubuntu 24.04 VM is installed and updated.

#### Step 1

Configure the external interface with an accessible IP address (attached to vmbrX), and the second
interface (attached to vmbrY) with an internal private IP (for example,
10.0.0.1/24).

#### Step 2

Install CAPEv2 following [this
guide](https://capev2.readthedocs.io/en/latest/installation/index.html) (only
CAPE steps install are required, not KVM).

After installing CAPE, ensure these services are running:

- cape.service
- cape-web.service
- cape-rooter.service
- cape-processor.service

If some are not running, fix the errors (usually installing packages using
poetry) and restart them until they are running.

#### Step 3

Configure the following config files:

- **cuckoo.conf**: Set machinery to "proxmox" and configure the result server so it listens on the IP attached to vmbrY (internal).
- **proxmox.conf**: Configure root@pam user and password (or generate a new one
  from Proxmox), connection details and guest name, IP address and snapshot
  name.
- **auxiliary.conf**: Configure the internal interface.
- **routing.conf**: Configure enable_pcap to true.

Restart the services and ensure everything is running.

#### Step 3

Run
[setup.sh](https://github.com/iciouss/automated-ioc-extractor/blob/main/setup.sh)
script to prepare the full environment for the pipeline.

## Windows 10

Ensure that Windows VM is installed and updated.
Then configure the following security features:

- Disable Automatic Updates via GPO.
- Disable Real-Time Protection via GPO.
- Disable UAC privilege escalation request and set it to automatically grant
  admin
  privileges via GPO.
- Disable Windows Firewall for both private and public networks.
- Install and configure [Autologon](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon) to automatically login on start-up.
- Disable unnecesary services using Windows 10 [debloating](https://github.com/W4RH4WK/Debloat-Windows-10) scripts.
- Install Python 3.6 or greater and configure a Scheduled Task to run [agent.py](https://github.com/kevoreilly/CAPEv2/blob/master/agent/agent.py) at login.
- Install additional software required for analysis (PDF, browser, winRAR...)
- Give it a static IP address in the range of vmbrY (internal network) and
  configure CAPE machine as gateway.

Turn off the machine, create a snapshot and name it accordingly to what's
configured on CAPE's proxmox.conf file.

---

# Usage

To use this script, first you need to enable Python virtual environment with`pyenv activate python3-tools`.
Then place the malware sample in some folder in CAPE machine
and run it with:

```bash
./ioc_extractor.py --file <malware file> --output-folder <output folder> --vt-api-key <API key for VirusTotal analysis>
```

For additional options, check usage with

```
./ioc_extractor.py --help
```

---

# Tests

The repository ships with unit tests for the pure-logic helpers (IOC
filtering and result extraction) that do not require the external analysis
tools or a running CAPE instance.

Install `pytest` (if it is not already available) and run the suite from the
repository root:

```bash
pip install pytest
python3 -m pytest tests/
```
