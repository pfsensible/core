"""Read live OpenVPN management and tunnel interface state on pfSense."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import socket
import subprocess
import sys


def management_status(instance, command):
    """Return a management command's response once the daemon answers."""
    path = "/var/etc/openvpn/{0}/sock".format(instance)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        try:
            connection.connect(path)
            connection.sendall((command + "\n").encode("ascii"))
            with connection.makefile(encoding="utf-8") as stream:
                lines = []
                for line in stream:
                    line = line.rstrip("\r\n")
                    if line == "END":
                        return lines
                    if line.startswith("ERROR:"):
                        raise RuntimeError("{0} {1} failed: {2}".format(instance, command, line))
                    if not line.startswith(">"):
                        lines.append(line)
                return lines
        except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError, socket.timeout) as error:
            return [str(error)]


def interface_addresses(interface):
    # The tunnel interface may be missing while OpenVPN starts.
    result = subprocess.run(["/sbin/ifconfig", interface], capture_output=True, text=True, check=False)
    return re.findall(r"^\s+inet (\S+)", result.stdout, re.MULTILINE)


def daemon_pid(instance):
    pid_path = Path("/var/run/openvpn_{0}.pid".format(instance))
    try:
        return int(pid_path.read_text())
    except FileNotFoundError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server_id", type=int)
    parser.add_argument("client_id", type=int)
    parser.add_argument("common_name")
    parser.add_argument("server_address")
    parser.add_argument("client_address")
    args = parser.parse_args()

    server_instance = "server{0}".format(args.server_id)
    client_instance = "client{0}".format(args.client_id)
    server = management_status(server_instance, "status 3")
    client = management_status(client_instance, "state 1")
    pids = {"server": daemon_pid(server_instance), "client": daemon_pid(client_instance)}
    server_addresses = interface_addresses("ovpns{0}".format(args.server_id))
    client_addresses = interface_addresses("ovpnc{0}".format(args.client_id))
    # The server reports the certificate common name and virtual IPv4 address.
    sessions = [line.split("\t") for line in server if line.startswith("CLIENT_LIST\t")]
    states = [line.split(",") for line in client]
    print(json.dumps({
        "config_sha256": sha256(Path("/cf/conf/config.xml").read_bytes()).hexdigest(),
        "pids": pids,
        "server_status": server,
        "client_state": client,
        "server_interface_addresses": server_addresses,
        "client_interface_addresses": client_addresses,
    }, indent=2))
    server_has_session = any(row[1] == args.common_name and row[3] == args.client_address for row in sessions)
    client_connected = any(row[1:4] == ["CONNECTED", "SUCCESS", args.client_address] for row in states)
    ready = (
        server_has_session
        and client_connected
        and all(pids.values())
        and args.server_address in server_addresses
        and args.client_address in client_addresses
    )
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
