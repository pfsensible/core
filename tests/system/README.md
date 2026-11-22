# Tests against a real pfSense appliance

This suite runs the collection's actual Ansible modules over SSH against a fresh
pfSense VM. It uses the appliance's installed PHP, configuration parser, apply
hooks, services, and FreeBSD PF kernel. It does not patch module methods or assert
the collection's synthetic `commands` strings. Existing unit tests remain useful
for failure injection and modules not yet covered here.

The first scenario covers a URL-table alias referenced by a firewall rule:

* Create, update, and delete configuration through the real modules.
* Inspect `/cf/conf/config.xml` independently using ElementTree.
* Read downloaded alias-table files and query the live kernel with `pfctl`.
  The observer checks both root and nested anchor rulesets, including private
  tables used by newer pfSense releases. Evidence records the rule anchors and
  verifies the effective table separately in each scope.
* Require a second identical apply to report no change and leave config bytes unchanged.
* Require check mode to leave persisted configuration and PF entries unchanged.
* Delete the cache and verify that a repeated apply repairs runtime state.
* Reboot and verify that the configuration and live PF rule/table survive.
* Verify deletion and repeated deletion.

The NAT port-forward scenario creates a rule with separate source and destination
ports, then checks the saved NAT and associated filter rules and the live PF
redirect and pass entries. It also verifies idempotence, check mode, a change to
both match ports, and repeated deletion. The translated target port differs from
the incoming destination port so the checks can distinguish them.

The interface gateway scenario configures an unused adapter with a static IPv4
address and an upstream gateway in one task. It checks the saved interface and
gateway, the address on the live adapter, and the gateway in pfSense's native
gateway inventory. It also verifies check mode, an unchanged repeat apply,
a gateway address update, and cleanup.

The VIP scenario checks that IP Alias, CARP, and an IP Alias stacked on CARP
appear on the expected interface, with the expected VHID where applicable.
It also verifies that Proxy ARP is registered on the selected interface and
that Proxy ARP and Other addresses are absent from interface assignments.
It verifies saved configuration, idempotence, and deletion for each case.

The suite inspects appliance configuration and kernel rules. Packet delivery and
package behavior such as HAProxy are outside its current coverage.

Filter reloads run asynchronously on pfSense. After create/update, action changes,
reboot, and deletion, the suite polls observed PF state instead of assuming a module
return means the kernel has finished applying the change. It waits for the requested
action and table contents, or for the deleted rule to disappear. Private tables are
checked in the scope visible to each rule. Polling is bounded by `pf_wait_retries`
(default 60) and `pf_wait_delay` (default 1 second). A reload that never converges
still fails with the last observed state; the suite does not force a synchronous
reload or disable its runtime assertions.

Evidence also includes `/var/run/filter_reload_status` messages and modification
time. pfSense normally appends `Done` on successful reload, but that may be from an
earlier run. The `filter` lock (`/tmp/filter.lock`) serializes running reloads; its
existence does not mean the lock is held, and acquiring it does not prove a queued
reload has started. These are diagnostic signals rather than substitutes for
checking that this test's desired PF state has appeared.

The observer is reinstalled after reboot because pfSense clears `/tmp`. This
reinstalls only test tooling; it does not reapply aliases or rules before checking
their persistence. Missing/broken observation tools fail immediately, while a valid
observation of pending PF state is retried.

Both initial setup and the reboot scenario wait for `/var/run/booting` to disappear
before making further configuration changes. SSH availability and loaded PF rules
do not establish that native startup has finished: `filter_configure()` suppresses
reload requests while the boot marker exists. The wait is bounded by
`system_boot_timeout` (default 600 seconds); observer and final diagnostic output
also record the boot marker so this race can be distinguished from reload failures.

## Hypervisor and networking

`run.py` runs QEMU on Linux, selects KVM when `/dev/kvm` is accessible, and falls
back to TCG software emulation. The base image must boot with legacy BIOS.
Each run writes to a new qcow2 overlay and never modifies the base disk.

| Adapter | Guest device | MAC | Configuration |
| --- | --- | --- | --- |
| WAN | `vtnet0` | `52:54:00:12:34:01` | DHCP on QEMU user network `10.0.2.0/24` |
| LAN | `vtnet1` | `52:54:00:12:34:02` | Static `192.168.100.2/24` |
| Test uplink | `vtnet2` | `52:54:00:12:34:03` | Initially unassigned on QEMU user network `198.51.100.0/24` |

All QEMU user networks use `restrict=on` to disable guest-initiated connections
outside the isolated network. SSH is forwarded from **127.0.0.1:2222** on the
runner to `192.168.100.2:22`. QEMU's host-side LAN address is `192.168.100.1`.
No host bridge, TAP interface, production network,
or public SSH listener is required. Fixtures are served on guest loopback.
The HTTP server is detached from the Ansible command's standard descriptors and
writes its own log. Each apply first checks that the fixture returns HTTP 200 and
the expected address. CI also records its PID, listening socket, request/error log,
and alias cache in `fixture-http.log` to distinguish fixture failures from native
URL-table downloader failures.

We control adapter models, PCI insertion order, MACs, subnets, and forwarding in
`run.py`. A later packet-flow suite can replace user networking with dedicated
TAP interfaces and Linux network namespaces for test clients on each side.
Changing device order/subnets requires updating the prepared image as well.

## Prepare an image once

Use a **dedicated disposable appliance**, with synthetic configuration only.
Never use a backup of a deployed firewall. Install pfSense CE from the official
[Netgate installer](https://docs.netgate.com/pfsense/en/latest/install/download-installer-image.html)
in QEMU with the WAN and LAN VirtIO adapters above and a VirtIO disk, using BIOS boot.
The installer download currently requires a Netgate account; CI therefore consumes
a prepared image rather than attempting an unattended account-based installation.

1. Assign WAN to `vtnet0` with DHCP and LAN to `vtnet1` at `192.168.100.2/24`.
   Leave LAN anti-lockout enabled and enable SSH with root public-key login.
   Complete initial setup so no interactive interface assignment remains.
2. Ensure `/usr/local/bin` contains an installed Python supported by the Ansible
   version in the workflow (Python 3.7-3.12 for ansible-core 2.17), and that
   `/usr/local/bin/php` and `/sbin/pfctl` work. Do not install packages during CI boot.
   The harness detects `python3` or a versioned executable such as `python3.11`;
   an unversioned symlink is not required. The detected path is used for Ansible,
   the state observer, and the local fixture HTTP server.
3. Copy `files/seed.sh` to `/usr/local/etc/rc.d/pfsensible-ci.sh` on the appliance.
   Set its mode to `0700` and create `/root/pfsensible-ci-appliance`:

   ```sh
   chmod 700 /usr/local/etc/rc.d/pfsensible-ci.sh
   touch /root/pfsensible-ci-appliance
   ```

   pfSense executes executable `.sh` files in that directory at boot. The script
   mounts the seed CD at `/dev/cd0` and installs that run's generated public key.
   Do not embed a private SSH key in the base image. On a normal boot without the
   seed CD this helper cannot authorize a CI key; prepare via console as needed.
4. Ensure PF is enabled and leave `vtnet2` unassigned if it is present. Keep the
   names `ci_urltable`, `CI URL table test`, `CI NAT port forward test`, `CI_UPLINK`,
   and `CI_UPLINK_GW` available. Leave loopback port 18080 and the fixture's redirect
   target `192.168.100.80` unused. Shut down cleanly.
5. Export a self-contained qcow2 disk with no backing/data files. For example,
   flatten an existing qcow2 image on the hypervisor host:

   ```sh
   qemu-img convert -f qcow2 -O qcow2 installed.qcow2 pfsense-ci.qcow2
   xz -T0 -k pfsense-ci.qcow2
   sha256sum pfsense-ci.qcow2.xz
   ```

   Gzip (`gzip -k pfsense-ci.qcow2`) is also supported, as is an uncompressed disk.
   Calculate the checksum of the exact file you will serve, after compression.

6. Host the image file at an HTTPS URL you control. Publish only images you are permitted
   to redistribute. Record the pfSense version, image preparation, and SHA-256.

The seed key is fresh for every run, and the disk overlay is discarded afterward.
QEMU serial output and Ansible logs are retained, so the image must contain no
production credentials or sensitive configuration.

## Enable GitHub Actions

Set these repository **Actions variables**:

* `PFSENSE_VM_IMAGE_URL`: HTTPS URL of a qcow2 image, optionally gzip- or xz-compressed.
* `PFSENSE_VM_IMAGE_SHA256`: SHA-256 of the **downloaded file**, after compression
  if applicable (64 hexadecimal characters).

CI verifies the download before decompressing it, detects compression from the file
contents (so signed URLs and query strings work), and unpacks it to a qcow2 disk for
QEMU. Verification or decompression failures stop the job. The local VM runner
continues to accept an uncompressed qcow2 disk; decompress local downloads first.

`.github/workflows/system.yml` runs on pull requests, pushes to `master`, and manual
dispatch. Until an image URL is configured, the VM job is explicitly skipped.
The hash is mandatory: a missing or incorrect hash fails the download step.
The workflow uses no appliance password or persistent SSH secret, so a publicly
downloadable image also permits fork PR testing without repository secrets.
Nested virtualization is not guaranteed on hosted runners; TCG may boot much more
slowly. CI grants the runner user access to `/dev/kvm` when that device exists;
`vm.json` records whether it was present and which accelerator was selected.
The job has a 45-minute limit, including a 10-minute initial boot deadline.

The workflow installs only required apt packages (`--no-install-recommends`) and
caches apt archives and pip downloads. Dependencies are listed in
`apt-packages.txt` and `requirements.txt`. Cache keys include those files, the
runner OS/architecture, and the UTC week, with earlier caches used as fallbacks.
The cache is saved immediately after installation, even if a later appliance test
fails. The first run still downloads packages; later runs reuse matching versions.
`apt-get update` and package installation still run so cached downloads do not
replace dependency resolution or package setup.

Artifacts contain Ansible output with observed state, serial/QEMU logs, the guest
version, QEMU invocation, and final PF rules/tables. They also include the last SSH
probe result, QEMU monitor status/block/network information, and a VGA screenshot
(`screen.png`, or `screen.ppm` on older QEMU). An empty serial log does not establish
that the guest failed to boot: a VGA-only image may never write to the serial port.
Inspect the screenshot for firmware boot errors, interface assignment prompts,
or a running console before diagnosing an SSH timeout. VM disks and private SSH keys
are not uploaded. Failed assertions fail the job; there is no continue-on-error.

SSH readiness is checked separately from appliance prerequisites. Once SSH works,
missing files, PHP, or compatible Python fail immediately and are reported in
`preflight.log`; they do not wait for the full boot timeout.

## Run locally

Install QEMU, `qemu-img`, `xorriso`, OpenSSH clients, and ansible-core 2.17 on a Linux
host, then run from the collection checkout:

```sh
python3 tests/system/run.py --image /path/to/pfsense-ci.qcow2
```

Use `--output /path/to/empty-directory` for another run, `--ssh-port` to choose a
different loopback port, or `--boot-timeout` to allow slower emulation. The default
output is `tests/output/system`. The runner builds an isolated collection search
path pointing at this checkout, waits for authenticated SSH, invokes the playbook,
collects evidence, and terminates QEMU even if the playbook fails.

## Scenario layout and reusable cases

`playbook.yml` only orchestrates setup, module suites, reboot persistence, and
cleanup. The files are organized by responsibility:

| Files | Responsibility |
| --- | --- |
| `common/setup.yml`, `common/http_fixture.yml` | Appliance preflight and fixture services |
| `common/change_apply_verify.yml` | Apply one change, check `changed`, and verify its effects |
| `modules/alias/` | Alias creation, idempotence, check mode, URL updates, cache repair, and deletion |
| `modules/interface/` | Static interface and gateway creation, native gateway visibility, check mode, idempotence, update, and cleanup |
| `modules/nat_port_forward/` | NAT match and translated ports, associated filter rule, idempotence, check mode, and deletion |
| `modules/rule/` | Rule apply/verification, idempotence, action changes, and deletion |
| `modules/virtual_ip/` | Saved VIP entries, interface addresses, CARP VHIDs, Proxy ARP registrations, and deletion |
| `scenarios/persistence.yml` | Reboot and verify without reapplying configuration |
| `scenarios/cleanup.yml` | Delete dependent rules before aliases |
| `observe.yml`, `verify.yml` | Shared state collection, bounded PF polling, and URL-table/rule assertions |

The current suites share one synthetic namespace. Alias tests create a referencing
rule so kernel table behavior can be checked; the rule suite then exercises that
rule. Their ordering is explicit in `playbook.yml`.

To add a module, create its explicit module call in `modules/<module>/apply.yml`
and independent assertions in its verification file. Reuse the case template:

```yaml
- name: Check a rule action change
  ansible.builtin.include_tasks: "{{ playbook_dir }}/common/change_apply_verify.yml"
  vars:
    system_apply_tasks: "{{ playbook_dir }}/modules/rule/apply.yml"
    system_verify_tasks: "{{ playbook_dir }}/modules/rule/verify.yml"
    system_case:
      name: Change rule action to block
      args: "{{ rule_args | combine({'action': 'block'}) }}"
      changed: true
```

The apply file must register the actual module result as `system_change_result`
and honor `system_case.check_mode` (default false). `system_case.args` supplies its
module arguments, and `system_case.changed` is the expected result. The verifier
must collect fresh state in `appliance`, including `config_sha256`. It can reuse
`observe.yml` or provide module-specific observations and assertions.

Set `unchanged_config: true` for idempotence cases. The template records a fresh
digest before applying and requires it to stay unchanged afterward. Check-mode
cases get this check automatically; their verifier must assert the original saved
state, not the previewed arguments. Fault injection, such as removing a runtime
cache, remains an explicit preparation task before the case.

Validate independent observations from the appliance, including service/kernel
behavior where relevant, rather than comparing the module's `commands` field.
Use only the disposable guest; the marker preflight and snapshot overlay are
deliberate safeguards.
