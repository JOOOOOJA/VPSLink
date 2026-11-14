"""Installed, immutable forced command. Never executes code supplied over SSH."""
import json
import os
import runpy
import sys
from pathlib import Path


def serve(folder):
    policy_path = folder / "policy.json"
    policy = json.loads(policy_path.read_text())
    relay = runpy.run_path(str(folder / "relay.py"), run_name="vpslink_shared")
    # Function globals are the original module dictionary, not runpy's returned copy.
    scope = relay["main"].__globals__
    source = policy["Source"]
    source.update(PeerKeys=[policy["Peer"]], PeerCount=1, CanProvision=False)
    scope["INVENTORY"] = {"Sources": [source]}
    dispatch = scope["dispatch"]

    def restricted(kind, data):
        # Revocation applies to already-open sessions as well as future logins.
        if not policy_path.is_file():
            raise ValueError("revoked")
        if kind == "I" and not data:
            try:
                checked = scope["local_udp_test"]()
            except OSError:
                checked = False
            scope["reply"]("I", {"UdpEcho": checked, "Details": "Restricted invitation bridge",
                                "Sources": [source], "Ports": source["Ports"]})
        elif kind == "S":
            req = json.loads(data)
            if req != {"Host": policy["Host"], "Port": policy["Port"]}:
                raise ValueError("target")
            dispatch(kind, data)
        elif kind == "T":
            req = json.loads(data)
            if req != {"Id": source["Id"], "Peer": policy["Peer"]}:
                raise ValueError("peer")
            dispatch(kind, data)
        elif kind in ("D", "P"):
            dispatch(kind, data)
        else:
            raise ValueError("forbidden")

    scope["dispatch"] = restricted
    scope["main"]()


if __name__ == "__main__":
    # SSH_ORIGINAL_COMMAND is deliberately ignored. No shell or uploaded Python runs.
    try:
        serve(Path(__file__).resolve().parent)
    except (ValueError, OSError, KeyError, TypeError):
        sys.exit(1)
