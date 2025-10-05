# Infrastructure-as-Code
# Problem Statement:
# Create a Python script that validates Infrastructure-as-Code (IaC) templates (e.g., Terraform or CloudFormation)
# for best practices. The tool should:
# Parse the template files and identify misconfigurations (e.g., open security groups, missing tags, hardcoded secrets).
# Suggest improvements based on a predefined ruleset.
# Optionally, integrate with a CI/CD pipeline to run checks automatically.
# Provide a summary of issues with severity levels.

#!/usr/bin/env python3

"""
iac_linter.py

A lightweight Infrastructure-as-Code linter for:
 - Terraform (HCL) files (.tf)
 - CloudFormation templates (YAML / JSON)

Checks for:
 - Open security groups (0.0.0.0/0) to sensitive ports
 - Missing resource tags
 - Hard-coded secrets in templates
 - Public S3 buckets
 - Wildcard IAM policies
 - Simple heuristics for other common misconfigurations

Produces:
 - Human-readable summary to stdout
 - JSON machine-readable output with severity levels
 - Exit code 2 if HIGH issues found, 1 if only MEDIUM/LOW, 0 if clean
"""

import os
import sys
import argparse
import json
import fnmatch
from collections import defaultdict

# optional imports
try:
    import hcl2
except Exception:
    hcl2 = None

import yaml

# --------- Ruleset config ----------
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    5432: "Postgres",
    3306: "MySQL",
    1433: "MSSQL",
    6379: "Redis",
    9200: "Elasticsearch"
}
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# keywords that suggest a secret/hardcoded value
SECRET_KEYWORDS = ["password", "passwd", "secret", "token", "apikey", "api_key", "access_key", "private_key"]

# --------- Utilities ----------
def load_yaml_or_json(path):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        return yaml.safe_load(text)
    except Exception:
        try:
            return json.loads(text)
        except Exception:
            return None

def parse_hcl_file(path):
    if hcl2 is None:
        return None
    with open(path, "r", encoding="utf-8") as f:
        try:
            return hcl2.load(f)
        except Exception:
            return None

# --------- Detector helpers ----------
def add_issue(issues, severity, title, file_path, location=None, resource=None, suggestion=None):
    issues.append({
        "severity": severity,
        "title": title,
        "file": file_path,
        "location": location,
        "resource": resource,
        "suggestion": suggestion
    })

def is_value_literal(value):
    """Rudimentary check: strings / numbers are treated as literals.
       In templating languages the actual check is more complex; this is a heuristic."""
    if isinstance(value, str):
        # treat template references (like ${var.foo} or !Ref or {"Ref": ...}) as non-literal by pattern
        if "${" in value or value.strip().startswith("Fn::") or value.strip().startswith("Ref"):
            return False
    return isinstance(value, (str, int, float, bool))

# --------- Checks for CloudFormation (dict) ----------
def check_cloudformation(doc, path, issues):
    if not isinstance(doc, dict):
        return
    resources = doc.get("Resources", {})
    # Check resources
    for name, res in resources.items():
        rtype = res.get("Type", "")
        props = res.get("Properties", {}) or {}
        # Security Group
        if rtype in ("AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"):
            check_cf_security_group(name, rtype, props, path, issues)
        # S3 Bucket public access (heuristic)
        if rtype == "AWS::S3::Bucket":
            check_cf_s3_bucket(name, props, path, issues)
        # IAM policies
        if rtype in ("AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::User"):
            check_cf_iam(name, props, path, issues)
        # RDS / DB instances - look for plaintext password
        if rtype in ("AWS::RDS::DBInstance",):
            check_cf_db_instance(name, props, path, issues)
        # Any resource: missing Tags?
        if isinstance(props, dict):
            check_missing_tags_cf(name, props, path, issues)
        # Search for hard-coded secrets anywhere in properties
        search_for_secrets_in_cf(name, props, path, issues)

def check_cf_security_group(name, rtype, props, path, issues):
    # SecurityGroup has SecurityGroupIngress / Egress lists
    for key in ("SecurityGroupIngress", "SecurityGroupEgress", "Ingress", "Egress"):
        rules = props.get(key) or []
        if isinstance(rules, dict):
            rules = [rules]
        for rule in rules:
            # check CidrIp or CidrIpv6
            cidr = rule.get("CidrIp") or rule.get("CidrIpv6") or rule.get("Cidr")
            from_port = rule.get("FromPort") or rule.get("Port") or rule.get("From")
            to_port = rule.get("ToPort") or rule.get("To") or from_port
            if cidr and isinstance(cidr, str) and ("0.0.0.0/0" in cidr or "::/0" in cidr):
                # If ports are missing or wide range, mark severity depending on port
                try:
                    fp = int(from_port) if from_port is not None else None
                except Exception:
                    fp = None
                label = f"{name} allows {cidr} on ports {from_port}-{to_port}"
                if fp in SENSITIVE_PORTS:
                    add_issue(issues, HIGH, f"Open Security Group to {SENSITIVE_PORTS.get(fp, fp)}",
                              path, location=name, resource=name,
                              suggestion="Restrict the source CIDR to known networks or use a bastion host.")
                else:
                    # If unspecified or wide (0-65535) => HIGH, else MEDIUM
                    if fp is None or (isinstance(fp, int) and fp == 0):
                        add_issue(issues, HIGH, "Security Group allows traffic from anywhere", path, location=name, resource=name,
                                  suggestion="Limit inbound CIDR ranges and use least privilege on ports.")
                    else:
                        add_issue(issues, MEDIUM, "Security Group allows wide inbound access", path, location=name, resource=name,
                                  suggestion="Consider restricting the port range or CIDR.")

def check_cf_s3_bucket(name, props, path, issues):
    p = props
    acl = p.get("AccessControl")
    public_policy = False
    if acl and isinstance(acl, str) and acl.lower() in ("publicread", "public-read", "authenticated-read"):
        public_policy = True
    # BucketPolicy next to resource would be separate; we can't always see that. Use ACL + PublicAccessBlock as heuristic
    public_access_block = p.get("PublicAccessBlockConfiguration") or p.get("PublicAccessBlockConfiguration", {})
    blocked = public_access_block.get("BlockPublicAcls") or public_access_block.get("BlockPublicPolicy")
    if public_policy or (isinstance(blocked, bool) and not blocked):
        add_issue(issues, HIGH, "Public S3 bucket", path, location=name, resource=name,
                  suggestion="Disable public access, enable BlockPublicAcls/BlockPublicPolicy, and add bucket policies to limit access.")

def check_cf_iam(name, props, path, issues):
    # If PolicyDocument with Statement contains Action or Resource = "*"
    policy_doc = props.get("PolicyDocument") or props.get("PolicyDocument", {})
    statements = policy_doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for s in statements:
        res = s.get("Resource")
        act = s.get("Action")
        if res == "*" or res == ["*"]:
            add_issue(issues, HIGH, "IAM policy grants access to all resources (*)", path, location=name, resource=name,
                      suggestion="Scope the Resource to the minimum required ARNs.")
        if act == "*" or act == ["*"]:
            add_issue(issues, HIGH, "IAM policy grants all actions (*)", path, location=name, resource=name,
                      suggestion="Limit allowed actions to required API calls.")

def check_cf_db_instance(name, props, path, issues):
    pw = props.get("MasterUserPassword") or props.get("MasterUserPassword")
    if pw and is_value_literal(pw):
        add_issue(issues, HIGH, "Database master password is hard-coded", path, location=name, resource=name,
                  suggestion="Store secrets in Secrets Manager or use parameter references.")

def check_missing_tags_cf(name, props, path, issues):
    # CloudFormation tags are usually 'Tags' list; check for presence
    tags = props.get("Tags")
    if tags is None:
        # not all resources require tags but this is a best-practice check
        add_issue(issues, LOW, "Resource missing Tags", path, location=name, resource=name,
                  suggestion="Add Tags (Environment, Owner, Project) to help with cost allocation and management.")

def search_for_secrets_in_cf(name, props, path, issues):
    # Traverse props dict for any property key containing SECRET_KEYWORDS and literal values
    def recurse(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                keylow = str(k).lower()
                if any(sk in keylow for sk in SECRET_KEYWORDS) and is_value_literal(v):
                    add_issue(issues, HIGH, f"Hardcoded secret-like value in property '{prefix + k}'", path, location=name, resource=name,
                              suggestion="Reference a secure parameter store or Secrets Manager instead of embedding secrets.")
                recurse(v, prefix + k + ".")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                recurse(item, f"{prefix}[{idx}].")
    recurse(props)

# --------- Checks for Terraform HCL (parsed) ----------
def check_terraform(parsed, path, issues):
    if not isinstance(parsed, dict):
        return

    resources = parsed.get("resource", [])
    # Normalize to list form
    if not isinstance(resources, list):
        resources = [resources]

    for resource_block in resources:
        if not isinstance(resource_block, dict):
            continue

        for rtype, named in resource_block.items():
            if not isinstance(named, dict):
                continue

            for rname, body in named.items():
                if not isinstance(body, dict):
                    continue

                if rtype in ("aws_security_group", "aws_security_group_rule"):
                    check_tf_security_group(rtype, rname, body, path, issues)
                if rtype in ("aws_s3_bucket",):
                    check_tf_s3_bucket(rtype, rname, body, path, issues)
                if rtype in ("aws_iam_policy", "aws_iam_role"):
                    check_tf_iam(rtype, rname, body, path, issues)

                # generic checks
                check_missing_tags_tf(rtype, rname, body, path, issues)
                search_for_secrets_in_tf(rtype, rname, body, path, issues)

def check_tf_security_group(rtype, rname, body, path, issues):
    # body may contain ingress/egress blocks
    ingress = body.get("ingress") or []
    egress = body.get("egress") or []
    if isinstance(ingress, dict):
        ingress = [ingress]
    if isinstance(egress, dict):
        egress = [egress]
    for block in ingress + egress:
        cidr = block.get("cidr_blocks") or block.get("cidr_block")
        # cidr_blocks could be a list
        if isinstance(cidr, list):
            for c in cidr:
                if isinstance(c, str) and ("0.0.0.0/0" in c or "::/0" in c):
                    from_port = block.get("from_port") or block.get("from")
                    try:
                        fp = int(from_port) if from_port is not None else None
                    except Exception:
                        fp = None
                    if fp in SENSITIVE_PORTS:
                        add_issue(issues, HIGH, f"Open Security Group to {SENSITIVE_PORTS.get(fp, fp)}", path, location=rname, resource=rtype,
                                  suggestion="Restrict CIDR ranges or narrow the port range.")
                    else:
                        add_issue(issues, MEDIUM, "Security group allows wide inbound access", path, location=rname, resource=rtype,
                                  suggestion="Limit the source CIDR range.")
        elif isinstance(cidr, str):
            if "0.0.0.0/0" in cidr or "::/0" in cidr:
                add_issue(issues, MEDIUM, "Security group allows traffic from anywhere", path, location=rname, resource=rtype,
                          suggestion="Restrict inbound CIDR ranges and use least privilege on ports.")

def check_tf_s3_bucket(rtype, rname, body, path, issues):
    acl = body.get("acl")
    if isinstance(acl, str) and acl.lower() in ("public-read", "publicread", "public-read-write"):
        add_issue(issues, HIGH, "Public S3 bucket (acl)", path, location=rname, resource=rtype,
                  suggestion="Set acl to private and add bucket policy to limit access.")

def check_tf_iam(rtype, rname, body, path, issues):
    policy = body.get("policy") or body.get("inline_policy") or {}
    # policy may be JSON string or map
    if isinstance(policy, str):
        try:
            parsed = json.loads(policy)
            statements = parsed.get("Statement", [])
        except Exception:
            statements = []
    elif isinstance(policy, dict):
        statements = policy.get("Statement", []) or []
    else:
        statements = []
    if isinstance(statements, dict):
        statements = [statements]
    for s in statements:
        res = s.get("Resource")
        act = s.get("Action")
        if res == "*" or res == ["*"]:
            add_issue(issues, HIGH, "IAM policy grants access to all resources (*)", path, location=rname, resource=rtype,
                      suggestion="Scope resources to required ARNs.")
        if act == "*" or act == ["*"]:
            add_issue(issues, HIGH, "IAM policy grants all actions (*)", path, location=rname, resource=rtype,
                      suggestion="Limit actions to required API calls.")

def check_missing_tags_tf(rtype, rname, body, path, issues):
    tags = body.get("tags")
    if tags is None:
        add_issue(issues, LOW, "Resource missing tags", path, location=rname, resource=rtype,
                  suggestion="Add tags like Environment, Owner, Project.")

def search_for_secrets_in_tf(rtype, rname, body, path, issues):
    # recursive search for keys with secret keywords and literal values
    def recurse(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if any(sk in k.lower() for sk in SECRET_KEYWORDS) and is_value_literal(v):
                    add_issue(issues, HIGH, f"Hardcoded secret-like variable '{prefix + k}'", path, location=rname, resource=rtype,
                              suggestion="Move secret to variable, environment, or secret manager.")
                recurse(v, prefix + k + ".")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                recurse(item, f"{prefix}[{idx}].")
    recurse(body)

# --------- File discovery ----------
def discover_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, filenames in os.walk(p):
                for fname in filenames:
                    if fname.endswith(".tf") or fname.endswith(".yml") or fname.endswith(".yaml") or fname.endswith(".json"):
                        files.append(os.path.join(root, fname))
        elif os.path.isfile(p):
            files.append(p)
        else:
            # glob pattern?
            for match in fnmatch.filter(os.listdir("."), p):
                files.append(match)
    return sorted(set(files))

# --------- Main runner ----------
def analyze(paths, output_json=False):
    files = discover_files(paths)
    if not files:
        print("No template files discovered. Provide file paths or directories.")
        return 0
    issues = []
    for f in files:
        if f.endswith(".tf"):
            parsed = parse_hcl_file(f)
            if parsed is None:
                # Try naive read to avoid crash
                print(f"[warn] could not parse HCL file {f}. Is python-hcl2 installed and file valid?")
                continue
            check_terraform(parsed, f, issues)
        elif f.endswith(".yaml") or f.endswith(".yml") or f.endswith(".json"):
            parsed = load_yaml_or_json(f)
            if parsed is None:
                print(f"[warn] could not parse YAML/JSON file {f}")
                continue
            check_cloudformation(parsed, f, issues)
        else:
            # skip
            continue
    # Summarize
    summary = defaultdict(int)
    for it in issues:
        summary[it["severity"]] += 1
    # Print human readable report
    print("==== IaC Linter Report ====")
    print(f"Files scanned: {len(files)}")
    print(f"Issues found: {len(issues)} (HIGH: {summary[HIGH]}, MEDIUM: {summary[MEDIUM]}, LOW: {summary[LOW]})\n")
    # Order issues by severity
    def sev_key(i):
        if i["severity"] == HIGH: return 0
        if i["severity"] == MEDIUM: return 1
        return 2
    for it in sorted(issues, key=sev_key):
        print(f"[{it['severity']}] {it['title']}")
        print(f"  file: {it['file']}")
        if it.get("location"):
            print(f"  resource: {it.get('resource')} (logical id: {it.get('location')})")
        if it.get("suggestion"):
            print(f"  suggestion: {it['suggestion']}")
        print()
    # JSON output
    result = {
        "files_scanned": len(files),
        "counts": {"high": summary[HIGH], "medium": summary[MEDIUM], "low": summary[LOW]},
        "issues": issues
    }
    if output_json:
        print("=== JSON Output ===")
        print(json.dumps(result, indent=2))
    # Exit codes: 2 if any HIGH, 1 if any other issues, 0 if clean
    if summary[HIGH] > 0:
        return 2
    if (summary[MEDIUM] + summary[LOW]) > 0:
        return 1
    return 0

# --------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Lightweight IaC linter for Terraform and CloudFormation.")
    parser.add_argument("paths", nargs="+", help="Files or directories to scan (supports .tf, .yml, .yaml, .json)")
    parser.add_argument("--json", action="store_true", help="Also print JSON output")
    args = parser.parse_args()
    rc = analyze(args.paths, output_json=args.json)
    sys.exit(rc)

if __name__ == "__main__":
    main()
