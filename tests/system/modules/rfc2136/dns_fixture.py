"""Accept signed DNS UPDATE messages for the appliance's test record."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from pathlib import Path
import socketserver
import struct
import sys
import xml.etree.ElementTree as ET

import dns.message
import dns.name
import dns.opcode
import dns.rdatatype
import dns.rcode
import dns.tsig
import dns.tsigkeyring

UPDATES = Path(__file__).resolve().parent / "rfc2136-updates.jsonl"
ZONE = dns.name.from_text("ci.example.")
HOST = dns.name.from_text("firewall.ci.example.")
DESCRIPTION = "CI RFC 2136 test"
KEYRING = dns.tsigkeyring.from_text({"ci-update.ci.example.": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="})


class UpdateHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        prefix = self.rfile.read(2)
        if not prefix:
            return
        request = dns.message.from_wire(self.rfile.read(struct.unpack("!H", prefix)[0]), keyring=KEYRING)
        response = dns.message.make_response(request)
        if request.opcode() != dns.opcode.UPDATE or len(request.question) != 1 or request.question[0].name != ZONE:
            response.set_rcode(dns.rcode.NOTAUTH)
        elif not request.had_tsig or request.keyalgorithm != dns.tsig.HMAC_SHA256:
            response.set_rcode(dns.rcode.REFUSED)
        else:
            records = [
                {"ttl": rrset.ttl, "address": rdata.address}
                for rrset in request.authority
                if rrset.name == HOST and rrset.rdtype == dns.rdatatype.A and rrset.deleting is None
                for rdata in rrset
            ]
            with UPDATES.open("a") as updates:
                updates.write(json.dumps(records) + "\n")
            if not records:
                response.set_rcode(dns.rcode.REFUSED)
        wire = response.to_wire()
        self.wfile.write(struct.pack("!H", len(wire)) + wire)


def observe():
    root = ET.parse("/cf/conf/config.xml")
    entries = [
        {field.tag: field.text or "" for field in entry if field.tag != "keydata"}
        for entry in root.findall("dnsupdates/dnsupdate")
        if entry.findtext("descr") == DESCRIPTION
    ]
    updates = [json.loads(line) for line in UPDATES.read_text().splitlines()] if UPDATES.exists() else []
    log = Path("/var/log/dyndns.log")
    messages = [line for line in log.read_text(errors="replace").splitlines() if HOST.to_text(omit_final_dot=True) in line] if log.exists() else []
    print(json.dumps({"entries": entries, "updates": updates, "dyndns_log": messages[-10:]}))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        with socketserver.TCPServer(("127.0.0.1", 15353), UpdateHandler) as server:
            server.serve_forever()
    else:
        observe()
