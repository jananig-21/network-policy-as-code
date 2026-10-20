import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "validator"))
import policy_check as pc  # noqa: E402


def messages(path):
    return [(lvl, rule, msg) for lvl, rule, msg in pc.check(pc.load(path))]


def test_branch_office_policy_is_clean():
    errors = [f for f in messages(ROOT / "policies/branch_office.yml") if f[0] == "ERROR"]
    assert errors == []


def test_bad_policy_catches_every_problem():
    found = messages(ROOT / "tests/fixtures/bad_policy.yml")
    text = " | ".join(f"{lvl} {rule}: {msg}" for lvl, rule, msg in found)
    assert "allow-all: permits any -> any" in text
    assert "telnet-in: exposes telnet (23)" in text
    assert "telnet-in: no justification" in text
    assert "duplicate rule name" in text
    assert "shadowed by earlier rule 'allow-all'" in text
    assert "last rule must be an explicit 'deny ip any any'" in text


def test_shadowing_respects_ports_and_subnets():
    policy = {
        "objects": {"any": {"cidr": "0.0.0.0/0"}, "a": {"cidr": "10.0.0.0/24"}, "b": {"cidr": "10.0.1.0/24"}},
        "rules": [
            {"name": "r1", "src": "a", "dst": "b", "proto": "tcp", "port": 22, "action": "permit", "justification": "x"},
            {"name": "r2", "src": "a", "dst": "b", "proto": "tcp", "port": 443, "action": "permit", "justification": "x"},
            {"name": "deny", "src": "any", "dst": "any", "proto": "ip", "action": "deny", "justification": "x"},
        ],
    }
    assert not any("shadowed" in m for _, _, m in pc.check(policy))


def test_cli_exit_codes():
    assert pc.main(str(ROOT / "policies/branch_office.yml")) == 0
    assert pc.main(str(ROOT / "tests/fixtures/bad_policy.yml")) == 1
