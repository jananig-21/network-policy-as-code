"""Static checks for a firewall policy before it is rendered to device config.

Run:  python validator/policy_check.py policies/branch_office.yml
Exits non-zero if any ERROR-level finding is present.
"""
import ipaddress
import sys

import yaml

# Ports that should never be exposed to an untrusted source.
RISKY_PORTS = {23: "telnet", 21: "ftp", 445: "smb", 3389: "rdp", 161: "snmp"}


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def net(policy, name):
    return ipaddress.ip_network(policy["objects"][name]["cidr"])


def covers(outer, inner, policy):
    """True if rule `outer` matches every packet that rule `inner` matches."""
    if not net(policy, inner["src"]).subnet_of(net(policy, outer["src"])):
        return False
    if not net(policy, inner["dst"]).subnet_of(net(policy, outer["dst"])):
        return False
    if outer["proto"] != "ip" and outer["proto"] != inner["proto"]:
        return False
    if "port" in outer and outer.get("port") != inner.get("port"):
        return False
    return True


def check(policy):
    findings = []  # (level, rule, message)
    rules = policy.get("rules", [])
    names = set()

    for i, r in enumerate(rules):
        name = r.get("name", f"rule#{i}")
        for key in ("src", "dst", "proto", "action"):
            if key not in r:
                findings.append(("ERROR", name, f"missing field '{key}'"))
        if any(k not in r for k in ("src", "dst", "proto", "action")):
            continue
        for obj in (r["src"], r["dst"]):
            if obj not in policy.get("objects", {}):
                findings.append(("ERROR", name, f"unknown object '{obj}'"))
        if r["src"] not in policy["objects"] or r["dst"] not in policy["objects"]:
            continue
        if name in names:
            findings.append(("ERROR", name, "duplicate rule name"))
        names.add(name)
        if not r.get("justification"):
            findings.append(("ERROR", name, "no justification recorded"))

        is_any = lambda o: net(policy, o).prefixlen == 0
        last = i == len(rules) - 1
        if r["action"] == "permit" and is_any(r["src"]) and is_any(r["dst"]):
            findings.append(("ERROR", name, "permits any -> any (violates least privilege)"))
        if r["action"] == "permit" and r["proto"] == "ip" and not last:
            findings.append(("WARN", name, "permits all protocols; scope to a port"))
        port = r.get("port")
        if r["action"] == "permit" and is_any(r["src"]) and port in RISKY_PORTS:
            findings.append(("ERROR", name, f"exposes {RISKY_PORTS[port]} ({port}) to any source"))

        # Shadowing: an earlier rule already matches all of this rule's traffic.
        for j in range(i):
            prev = rules[j]
            if all(k in prev for k in ("src", "dst", "proto", "action")) and \
               prev["src"] in policy["objects"] and prev["dst"] in policy["objects"] and \
               covers(prev, r, policy):
                findings.append(("ERROR" if prev["action"] != r["action"] else "WARN", name,
                                 f"shadowed by earlier rule '{prev.get('name', j)}'"))
                break

    if not rules or rules[-1].get("action") != "deny" or rules[-1].get("proto") != "ip":
        findings.append(("ERROR", "<policy>", "last rule must be an explicit 'deny ip any any'"))
    return findings


def main(path):
    findings = check(load(path))
    for level, rule, msg in findings:
        print(f"{level:5} {rule}: {msg}")
    errors = sum(1 for f in findings if f[0] == "ERROR")
    print(f"{len(findings)} finding(s), {errors} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
