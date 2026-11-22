"""Run state-based integration tests against a disposable QEMU pfSense VM."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
import atexit
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]

APPLIANCE_PREFLIGHT = """
failed=0
for path in /root/pfsensible-ci-appliance /etc/version; do
    if [ ! -f "$path" ]; then
        echo "Missing required file: $path" >&2
        failed=1
    fi
done
if [ ! -x /usr/local/bin/php ]; then
    echo "Missing executable: /usr/local/bin/php" >&2
    failed=1
fi
python=
for candidate in /usr/local/bin/python3 /usr/local/bin/python3.12 /usr/local/bin/python3.11 \\
                 /usr/local/bin/python3.10 /usr/local/bin/python3.9 /usr/local/bin/python3.8 /usr/local/bin/python3.7; do
    if [ -x "$candidate" ] && "$candidate" -c \\
        'import sys; sys.exit(not ((3, 7) <= sys.version_info[:2] <= (3, 12)))'; then
        python=$candidate
        break
    fi
done
if [ -z "$python" ]; then
    echo "No compatible Python 3.7-3.12 executable found in /usr/local/bin" >&2
    failed=1
else
    printf 'PFSENSIBLE_PYTHON=%s\\n' "$python"
    "$python" --version
fi
exit "$failed"
"""


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def stop_on_signal(signum, frame):
    raise SystemExit(128 + signum)


def capture_monitor(path, output):
    """Capture the VGA screen and machine state even when guest SSH never starts."""
    evidence = {}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
            monitor.settimeout(5)
            monitor.connect(str(path))
            with monitor.makefile("rwb") as stream:
                evidence["greeting"] = json.loads(stream.readline())

                def command(name, arguments=None):
                    request = {"execute": name}
                    if arguments is not None:
                        request["arguments"] = arguments
                    stream.write(json.dumps(request).encode() + b"\n")
                    stream.flush()
                    while True:
                        reply = json.loads(stream.readline())
                        if "return" in reply or "error" in reply:
                            return reply

                evidence["capabilities"] = command("qmp_capabilities")
                for name in ("query-status", "query-block"):
                    evidence[name] = command(name)
                for name in ("info network", "info usernet"):
                    evidence[name] = command("human-monitor-command", {"command-line": name})
                evidence["screenshot"] = command("screendump", {
                    "filename": str(output / "screen.png"), "format": "png"})
                if "error" in evidence["screenshot"]:
                    evidence["screenshot_ppm"] = command("screendump", {"filename": str(output / "screen.ppm")})
    except (OSError, ValueError) as error:
        evidence["capture_error"] = str(error)
    (output / "monitor.json").write_text(json.dumps(evidence, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path, help="Prepared BIOS-bootable qcow2 appliance")
    parser.add_argument("--output", type=Path, default=ROOT / "tests/output/system")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--boot-timeout", type=int, default=600)
    parser.add_argument("--ansible-playbook", default="ansible-playbook")
    args = parser.parse_args()
    if not 1024 <= args.ssh_port <= 65535:
        parser.error("--ssh-port must be between 1024 and 65535")
    image = args.image.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Refuse reusing previous credentials, overlays, or evidence.
    if any(output.iterdir()):
        parser.error("--output must be an empty directory")
    for executable in ("qemu-img", "qemu-system-x86_64", "xorriso", "ssh", "ssh-keygen", args.ansible_playbook):
        if not shutil.which(executable):
            parser.error("Required executable is missing: " + executable)
    info = json.loads(run(["qemu-img", "info", "--output=json", str(image)],
                          capture_output=True, text=True).stdout)
    if info["format"] != "qcow2" or info.get("backing-filename") or info.get("data-file"):
        parser.error("Use a self-contained qcow2 image with no backing/data file")

    key = output / "ssh-key"
    signal.signal(signal.SIGTERM, stop_on_signal)
    atexit.register(key.unlink, missing_ok=True)
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    seed = output / "seed"
    seed.mkdir()
    shutil.copyfile(str(key) + ".pub", seed / "authorized_keys")
    run(["xorriso", "-as", "mkisofs", "-quiet", "-R", "-J",
         "-o", str(output / "seed.iso"), str(seed)])
    overlay = output / "appliance.qcow2"
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(overlay)])

    collection_path = output / "collections/ansible_collections/pfsensible"
    collection_path.mkdir(parents=True)
    (collection_path / "core").symlink_to(ROOT, target_is_directory=True)
    ssh_options = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                   "-o", "StrictHostKeyChecking=accept-new",
                   "-o", "UserKnownHostsFile=" + str(output / "known_hosts"),
                   "-o", "IdentitiesOnly=yes"]
    ssh = ["ssh", "-i", str(key), "-p", str(args.ssh_port)] + ssh_options + ["root@127.0.0.1"]
    inventory = {"all": {"children": {"pfsense": {"hosts": {"appliance": {
        "ansible_host": "127.0.0.1", "ansible_port": args.ssh_port,
        "ansible_user": "root", "ansible_ssh_private_key_file": str(key),
        "ansible_ssh_common_args": shlex.join(ssh_options),
        "ansible_remote_tmp": "/tmp/pfsensible-ansible",
    }}}}}}
    accelerated = os.access("/dev/kvm", os.R_OK | os.W_OK)
    monitor_directory = tempfile.TemporaryDirectory(prefix="pfsensible-qmp-")
    atexit.register(monitor_directory.cleanup)
    monitor_path = Path(monitor_directory.name) / "monitor.sock"
    qemu = ["qemu-system-x86_64", "-machine", "pc", "-accel", "kvm" if accelerated else "tcg",
            "-cpu", "host" if accelerated else "max", "-smp", "2", "-m", "2048",
            "-display", "none", "-monitor", "none",
            "-qmp", "unix:" + str(monitor_path) + ",server=on,wait=off",
            "-serial", "file:" + str(output / "serial.log"),
            "-drive", "file=" + str(overlay) + ",if=virtio,format=qcow2",
            "-drive", "file=" + str(output / "seed.iso") + ",media=cdrom,readonly=on,format=raw",
            "-netdev", "user,id=wan,restrict=on",
            "-device", "virtio-net-pci,netdev=wan,mac=52:54:00:12:34:01",
            "-netdev", ("user,id=lan,net=192.168.100.0/24,host=192.168.100.1,restrict=on,"
                        "hostfwd=tcp:127.0.0.1:{0}-192.168.100.2:22".format(args.ssh_port)),
            "-device", "virtio-net-pci,netdev=lan,mac=52:54:00:12:34:02",
            "-netdev", "user,id=gateway_test,net=198.51.100.0/24,host=198.51.100.1,restrict=on",
            "-device", "virtio-net-pci,netdev=gateway_test,mac=52:54:00:12:34:03"]
    metadata = {"accelerator": "kvm" if accelerated else "tcg",
                "kvm_present": os.path.exists("/dev/kvm"), "command": qemu}
    (output / "vm.json").write_text(json.dumps(metadata, indent=2))
    env = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(output / "collections"),
               ANSIBLE_LOCAL_TEMP=str(output / "ansible-tmp"), ANSIBLE_NOCOLOR="1")
    process = None
    try:
        with (output / "qemu.log").open("w") as qemu_log:
            process = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=qemu_log, stderr=qemu_log)
        deadline = time.monotonic() + args.boot_timeout
        while True:
            if process.poll() is not None:
                raise RuntimeError("QEMU exited before SSH was ready; inspect qemu.log and serial.log")
            try:
                ready = subprocess.run(ssh + ["true"],
                                       capture_output=True, timeout=15, check=False)
                (output / "ssh.log").write_text(
                    "Exit code: {0}\n".format(ready.returncode) +
                    ready.stdout.decode(errors="replace") + ready.stderr.decode(errors="replace"))
                if ready.returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                (output / "ssh.log").write_text("SSH readiness probe exceeded its 15-second deadline\n")
            if time.monotonic() >= deadline:
                raise TimeoutError("Appliance boot/SSH timed out; inspect screen.png or screen.ppm, monitor.json, and ssh.log")
            time.sleep(2)
        version = run(ssh + ["cat /etc/version; uname -a"], capture_output=True, text=True)
        (output / "version.txt").write_text(version.stdout)
        print(version.stdout, flush=True)
        preflight = subprocess.run(ssh + ["/bin/sh -s"], input=APPLIANCE_PREFLIGHT,
                                   capture_output=True, text=True, timeout=30, check=False)
        details = preflight.stdout + preflight.stderr
        (output / "preflight.log").write_text("Exit code: {0}\n".format(preflight.returncode) + details)
        if preflight.returncode:
            raise RuntimeError("Appliance SSH is ready, but prerequisite checks failed:\n" + details)
        interpreters = [line.split("=", 1)[1] for line in preflight.stdout.splitlines()
                        if line.startswith("PFSENSIBLE_PYTHON=")]
        if len(interpreters) != 1:
            raise RuntimeError("Unable to identify appliance Python; inspect preflight.log")
        inventory["all"]["children"]["pfsense"]["hosts"]["appliance"]["ansible_python_interpreter"] = interpreters[0]
        (output / "inventory.json").write_text(json.dumps(inventory, indent=2))
        with (output / "ansible.log").open("w") as log:
            result = subprocess.run([args.ansible_playbook, "-i", str(output / "inventory.json"),
                                     str(ROOT / "tests/system/playbook.yml")],
                                    env=env, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=1800, check=False)
        print((output / "ansible.log").read_text(), flush=True)
        if result.returncode:
            raise RuntimeError("Appliance assertions failed; inspect ansible.log")
    finally:
        if process is not None and process.poll() is None:
            capture_monitor(monitor_path, output)
            pf_commands = (
                "/sbin/pfctl -a \"*\" -sr; /sbin/pfctl -v -s Anchors; /sbin/pfctl -a \"*\" -s Tables; "
                "printf \"\\nFilter reload status:\\n\"; tail -n 80 /var/run/filter_reload_status; "
                "printf \"\\nNative boot marker:\\n\"; "
                "if test -e /var/run/booting; then echo present; else echo absent; fi"
            )
            http_commands = (
                "printf \"Fixture server PID:\\n\"; cat /tmp/pfsensible-system/http.pid; "
                "printf \"\\nListening sockets:\\n\"; /usr/bin/sockstat -4 -l -p 18080; "
                "printf \"\\nHTTP server log:\\n\"; tail -n 100 /tmp/pfsensible-system/http.log; "
                "printf \"\\nAlias cache:\\n\"; cat /var/db/aliastables/ci_urltable.txt"
            )
            for filename, command in (("pf-state.txt", pf_commands), ("fixture-http.log", http_commands)):
                try:
                    state = subprocess.run(ssh + [command],
                                           capture_output=True, text=True, timeout=15, check=False)
                    (output / filename).write_text(state.stdout + state.stderr)
                except subprocess.TimeoutExpired:
                    # Diagnostics are best-effort; a timeout must not prevent VM shutdown.
                    (output / filename).write_text("Diagnostic collection exceeded its 15-second deadline\n")
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        # Never include VM disks or private SSH keys in diagnostic artifacts.
        key.unlink(missing_ok=True)
        overlay.unlink(missing_ok=True)
        monitor_directory.cleanup()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
