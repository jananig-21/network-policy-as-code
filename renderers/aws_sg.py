"""Render a firewall policy to Terraform for AWS security groups.

Run:  python renderers/aws_sg.py policies/branch_office.yml build/branch-office_aws
Writes <out_dir>/main.tf. Exits non-zero if the policy cannot be expressed.

Security groups are allow-only and stateful, so the mapping differs from an ACL:
- every non-'any' object used by a permit rule becomes one security group;
- a permit rule src -> dst becomes an ingress rule on dst's group (from src's CIDR)
  and an egress rule on src's group (to dst's CIDR); the 'any' side gets no group;
- the final 'deny ip any any' is the security groups' implicit deny, and Terraform
  removes AWS's default allow-all egress rule, so only listed traffic is allowed;
- any other deny rule cannot be expressed and is reported as an error.
"""
import re
import sys
from pathlib import Path

import yaml

PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "ip": "-1"}


class RenderError(Exception):
    pass


def ident(name):
    """Terraform resource name from a policy name: letters, digits, underscores."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name).lower()


def hcl(value):
    if isinstance(value, int):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def block(header, attrs, indent=""):
    """One HCL block with '=' aligned the way `terraform fmt` does."""
    width = max(len(k) for k, _ in attrs)
    body = [f"{indent}  {k.ljust(width)} = {v}" for k, v in attrs]
    return "\n".join([f"{indent}{header} {{", *body, f"{indent}}}"])


def render(policy):
    objects, rules = policy["objects"], policy["rules"]
    prefix = policy["policy_name"].lower()
    cidr = lambda o: objects[o]["cidr"]
    is_any = lambda o: cidr(o) == "0.0.0.0/0"

    for i, r in enumerate(rules):
        last = i == len(rules) - 1
        if r["action"] == "deny" and not (last and is_any(r["src"]) and is_any(r["dst"]) and r["proto"] == "ip"):
            raise RenderError(f"rule '{r['name']}': security groups cannot express a deny rule")
        if r["proto"] not in PROTOCOLS:
            raise RenderError(f"rule '{r['name']}': unsupported protocol '{r['proto']}'")
    permits = [r for r in rules if r["action"] == "permit"]

    groups = []
    for r in permits:
        for o in (r["src"], r["dst"]):
            if not is_any(o) and o not in groups:
                groups.append(o)

    out = [f"# Generated from {policy['policy_name']} by network-policy-as-code. Do not edit by hand.",
           "terraform {\n"
           "  required_providers {\n"
           "    aws = {\n"
           '      source  = "hashicorp/aws"\n'
           '      version = "~> 5.0"\n'
           "    }\n"
           "  }\n"
           "}",
           'variable "vpc_id" {\n  description = "VPC that the security groups belong to"\n  type        = string\n}']
    for o in groups:
        out.append(block(f'resource "aws_security_group" "{ident(o)}"', [
            ("name", hcl(f"{prefix}-{o}")),
            ("description", hcl(f"{o} ({cidr(o)}), from policy {policy['policy_name']}")),
            ("vpc_id", "var.vpc_id"),
        ]))

    for r in permits:
        if r["proto"] == "ip":
            ports = []
        else:  # a TCP/UDP rule without a port means every port
            lo, hi = (r["port"], r["port"]) if "port" in r else (0, 65535)
            ports = [("from_port", lo), ("to_port", hi)]
        sides = [("ingress", r["dst"], r["src"]), ("egress", r["src"], r["dst"])]
        for direction, owner, peer in sides:
            if is_any(owner):
                continue
            attrs = [("security_group_id", f"aws_security_group.{ident(owner)}.id"),
                     ("description", hcl(f"{r['name']}: {r['justification']}")),
                     ("cidr_ipv4", hcl(cidr(peer))),
                     ("ip_protocol", hcl(PROTOCOLS[r["proto"]]))]
            attrs += [(k, hcl(v)) for k, v in ports]
            kind = "aws_vpc_security_group_ingress_rule" if direction == "ingress" else "aws_vpc_security_group_egress_rule"
            out.append(block(f'resource "{kind}" "{ident(r["name"])}_{direction}"', attrs))

    out.append(f"# {rules[-1]['name']}: implicit in security groups (anything not allowed above is denied)")
    return "\n\n".join(out) + "\n"


def main(path, out_dir):
    with open(path) as f:
        policy = yaml.safe_load(f)
    try:
        text = render(policy)
    except RenderError as e:
        print(f"ERROR {e}")
        return 1
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "main.tf").write_text(text)
    print(f"wrote {Path(out_dir) / 'main.tf'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
