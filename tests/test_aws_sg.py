import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "renderers"))
import aws_sg  # noqa: E402


def branch_office():
    return yaml.safe_load((ROOT / "policies/branch_office.yml").read_text())


def test_branch_office_renders_groups_and_rules():
    tf = aws_sg.render(branch_office())
    for obj in ("corp_lan", "dmz_web", "mgmt_jump", "ad_servers", "dns_resolvers"):
        assert f'resource "aws_security_group" "{obj}"' in tf
    assert 'resource "aws_security_group" "any"' not in tf
    # any -> dmz_web:443 is ingress only; the 'any' side has no group.
    assert '"web_https_in_ingress"' in tf
    assert '"web_https_in_egress"' not in tf
    # corp_lan -> any:443 is egress only.
    assert '"lan_web_out_egress"' in tf
    assert '"lan_web_out_ingress"' not in tf
    # corp_lan -> dns_resolvers:53/udp needs both sides.
    assert '"lan_to_dns_ingress"' in tf and '"lan_to_dns_egress"' in tf
    assert 'ip_protocol       = "udp"' in tf
    assert "# default-deny: implicit in security groups" in tf


def test_ports_and_peer_cidrs():
    tf = aws_sg.render(branch_office())
    ssh = tf.split('"mgmt_ssh_ingress" {')[1].split("}")[0]
    assert "aws_security_group.dmz_web.id" in ssh
    assert 'cidr_ipv4         = "10.10.250.10/32"' in ssh
    assert "from_port         = 22" in ssh and "to_port           = 22" in ssh


def test_mid_policy_deny_cannot_be_rendered():
    policy = branch_office()
    policy["rules"].insert(0, {"name": "block-host", "src": "mgmt_jump", "dst": "dmz_web",
                               "proto": "tcp", "port": 80, "action": "deny", "justification": "x"})
    with pytest.raises(aws_sg.RenderError, match="block-host"):
        aws_sg.render(policy)


def test_cli_writes_main_tf(tmp_path):
    assert aws_sg.main(str(ROOT / "policies/branch_office.yml"), str(tmp_path)) == 0
    assert (tmp_path / "main.tf").read_text().startswith("# Generated from BRANCH-OFFICE")
