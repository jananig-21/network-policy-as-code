# Network Policy as Code

Write a firewall policy once in YAML, check it for common security mistakes, and render it to **Cisco ASA** and **Cisco IOS** access lists and to **Terraform for AWS security groups** with **Ansible**. A GitHub Actions pipeline runs the checks on every push and blocks policies that break the rules.

## Why

Hand-edited ACLs drift, collect `permit any any` shortcuts, and pick up rules that never match because an earlier rule already does. Keeping the policy in version control and checking it before it reaches a device catches those problems in code review instead of in production.

## What it does

1. **`policies/branch_office.yml`** describes network objects (CIDRs) and ordered rules, each with a written justification.
2. **`validator/policy_check.py`** runs static checks:
   - **ERROR** `permit` from any source to any destination (least-privilege violation)
   - **ERROR** risky services (telnet, FTP, SMB, RDP, SNMP) exposed to any source
   - **ERROR** rules with no justification, duplicate names, or unknown objects
   - **ERROR / WARN** shadowed rules: an earlier rule already matches all of a later rule's traffic (an error if the actions differ)
   - **ERROR** missing explicit `deny ip any any` at the end
   - **WARN** `permit ip` rules that allow every protocol
3. **`playbooks/build.yml`** (Ansible, runs locally) loads the policy, fails if the checker reports any error, and renders:
   - `build/<policy>_asa.cfg` (ASA `object network` + `access-list ... extended`)
   - `build/<policy>_ios.cfg` (IOS `ip access-list extended` with wildcard masks)
   - `build/<policy>_aws/main.tf` (Terraform: one `aws_security_group` per object, `aws_vpc_security_group_ingress_rule` / `egress_rule` per permit), via **`renderers/aws_sg.py`**
4. **`.github/workflows/ci.yml`** runs the unit tests, a playbook syntax check, a full build, `terraform fmt -check` and `terraform validate` on the generated Terraform, and a negative test proving a bad policy fails, then uploads the generated configs.

## Run it

```bash
pip install -r requirements.txt
pytest -q tests
ansible-playbook playbooks/build.yml
ansible-playbook playbooks/build.yml -e policy_file=$PWD/tests/fixtures/bad_policy.yml   # fails, by design
terraform -chdir=build/branch-office_aws init -backend=false && terraform -chdir=build/branch-office_aws validate
```

## Example output (Cisco IOS)

```
ip access-list extended BRANCH-OFFICE
 remark web-https-in: Public HTTPS to DMZ web tier
 permit tcp any 172.16.10.0 0.0.0.255 eq 443
 remark mgmt-ssh: Admin SSH only from the jump host
 permit tcp 10.10.250.10 0.0.0.0 172.16.10.0 0.0.0.255 eq 22
 ...
 deny ip any any log
```

The bad-policy fixture produces 6 errors, including `permits any -> any`, `exposes telnet (23) to any source`, and a rule shadowed by an earlier one.

## Limitations / next steps

- Security groups are allow-only, so the AWS output supports exactly one deny: the final `deny ip any any`, which becomes the groups' implicit deny (Terraform also removes AWS's default allow-all egress). Any other deny rule stops the build with an error.
- Generates configs only; pushing to devices (e.g. with the `cisco.ios` / `cisco.asa` Ansible collections) and `terraform apply` are not included.
- Rules match a single port; port ranges and object groups are not modelled.
- Shadowing reports the first covering rule; it does not detect partial overlaps.
