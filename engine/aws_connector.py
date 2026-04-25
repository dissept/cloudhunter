# engine/aws_connector.py
# this is where all the actual scanning happens for AWS
# it finds the misconfigurations and then calls shared.py to add CVSS and MITRE info
# for now it only checks S3 buckets and EC2 security groups, that is Phase 1

import csv
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

# shared.py has the CVSS scoring and MITRE mapping logic
# i put it there so i dont have to repeat the same code when i add azure later
from engine.shared import enrich_finding, get_fieldnames


# -----------------------------------------------------------------------
# small helper functions used in multiple places below
# -----------------------------------------------------------------------

def _utc() -> str:
    # just returns the current time in UTC so we know when the scan ran
    # i store this in the evidence JSON for each finding
    return datetime.now(timezone.utc).isoformat()


def _is_world(cidr: str) -> bool:
    # checks if a CIDR is open to literally everyone on the internet
    # 0.0.0.0/0 is all IPv4, ::/0 is all IPv6
    # if a security group has these it means any person or bot can connect
    return cidr in ("0.0.0.0/0", "::/0")


def _safe_json(x: Any) -> str:
    # converts anything to a JSON string without crashing
    # the default=str part handles datetime objects which json.dumps cant do normally
    # if something goes really wrong we just return an empty object instead of breaking
    try:
        return json.dumps(x, default=str)
    except Exception:
        return "{}"


# -----------------------------------------------------------------------
# the main scan function - this does all the real AWS work
# -----------------------------------------------------------------------

def scan_aws(output_path: str) -> int:
    # this runs all the checks, adds CVSS and MITRE info, and writes the CSV
    # returns the number of findings so main.py can print a summary

    # all findings go into this list before we write them to the file
    findings: List[Dict[str, Any]] = []

    # boto3 picks up credentials automatically from environment variables
    # or from ~/.aws/credentials if you have the AWS CLI configured
    s3 = boto3.client("s3")
    session = boto3.session.Session()

    # EC2 needs a region, we fall back to us-east-1 if nothing is configured
    region = session.region_name or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)

    # -----------------------------------------------------------------------
    # CHECK 1 - S3 buckets
    # -----------------------------------------------------------------------
    # public S3 buckets are one of the most common causes of cloud data breaches
    # this maps to MITRE T1530 (Data from Cloud Storage Object)
    # we check three things: Public Access Block, bucket policy, and ACLs
    # -----------------------------------------------------------------------

    buckets = s3.list_buckets().get("Buckets", [])

    for b in buckets:
        name = b["Name"]

        # check 1a - Public Access Block
        # PAB is the AWS setting that blocks all public access at the bucket level
        # all 4 settings need to be True otherwise a bad policy could expose the bucket
        pab = None
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            # these two error codes just mean PAB was never configured, not a real error
            if code not in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
                # something else went wrong, save the error so we can debug it later
                pab = {"error": str(e)}

        # check if all 4 PAB settings are switched on
        pab_fully_enabled = False
        if isinstance(pab, dict) and "error" not in pab:
            needed = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            pab_fully_enabled = all(bool(pab.get(k)) for k in needed)

        # check 1b - bucket policy
        # even without PAB a bucket policy with Principal: "*" gives public access
        # Principal "*" means any person or unauthenticated request can perform the action
        policy_public = False
        policy = None
        try:
            policy_str = s3.get_bucket_policy(Bucket=name).get("Policy")
            if policy_str:
                policy = json.loads(policy_str)
                statements = policy.get("Statement", [])
                # sometimes Statement is a single dict instead of a list, we handle both
                if isinstance(statements, dict):
                    statements = [statements]
                for st in statements:
                    # only Allow statements matter here, Deny cant give public access
                    if st.get("Effect") != "Allow":
                        continue
                    principal = st.get("Principal")
                    # principal "*" or {"AWS": "*"} both mean open to everyone
                    if principal == "*" or (isinstance(principal, dict) and any(v == "*" for v in principal.values())):
                        policy_public = True
                        break
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                policy = {"error": str(e)}

        # check 1c - ACLs
        # ACLs are the old way to control bucket access, AWS now recommends disabling them
        # AllUsers = public internet, AuthenticatedUsers = any AWS account (also bad)
        acl_public = False
        acl = None
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                uri = g.get("Grantee", {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    acl_public = True
                    break
        except ClientError as e:
            acl = {"error": str(e)}

        # only make a finding if there is actually something wrong
        # we dont want to flag every single bucket, only the ones with real problems
        if (not pab_fully_enabled) or policy_public or acl_public:
            finding = {
                "provider": "aws",
                "check_id": "AWS.S3.PUBLIC",
                "resource_type": "s3_bucket",
                "resource_id": name,
                # high if we confirmed public access via policy or ACL, medium if just PAB missing
                "severity": "high" if (policy_public or acl_public) else "medium",
                "title": "S3 bucket may be publicly accessible",
                "description": "PublicAccessBlock not fully enabled and/or policy/ACL indicates possible public access.",
                "region": "global",  # S3 is a global service, buckets dont belong to one region
                "evidence_json": _safe_json({
                    "bucket": name,
                    "pab": pab,
                    "policy_public": policy_public,
                    "policy": policy,
                    "acl_public": acl_public,
                    "acl": acl,
                    "time": _utc(),
                }),
            }
            # enrich_finding adds the CVSS score and MITRE technique from shared.py
            # this is what makes Cloudhunter different from Prowler or ScoutSuite
            finding = enrich_finding(finding)
            findings.append(finding)

    # -----------------------------------------------------------------------
    # CHECK 2 - EC2 security groups
    # -----------------------------------------------------------------------
    # SSH on port 22 and RDP on port 3389 should never be open to 0.0.0.0/0
    # attackers scan for these constantly, you can see thousands of attempts on shodan.io
    # SSH maps to MITRE T1021.004 and RDP to T1021.001
    # -----------------------------------------------------------------------

    sgs = ec2.describe_security_groups().get("SecurityGroups", [])

    for sg in sgs:
        sg_id = sg.get("GroupId", "unknown")

        for perm in sg.get("IpPermissions", []):
            ip_proto = perm.get("IpProtocol")
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            # work out which dangerous ports this rule covers
            ports = set()
            if ip_proto == "-1":
                # protocol -1 means all traffic, so it definitely covers SSH and RDP
                ports.update([22, 3389])
            else:
                if from_port is None or to_port is None:
                    continue
                # port ranges can include 22 or 3389 without being exactly those ports
                if from_port <= 22 <= to_port:
                    ports.add(22)
                if from_port <= 3389 <= to_port:
                    ports.add(3389)

            if not ports:
                # this rule doesnt touch SSH or RDP so we skip it
                continue

            # check if any of the CIDRs in this rule are open to the world
            world = []
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp")
                if cidr and _is_world(cidr):
                    world.append(cidr)
            for r in perm.get("Ipv6Ranges", []):
                cidr = r.get("CidrIpv6")
                if cidr and _is_world(cidr):
                    world.append(cidr)

            if not world:
                # exposed ports but not to the internet, fine
                continue

            # one finding per dangerous port so the report is clear about which port is the problem
            for port in ports:
                finding = {
                    "provider": "aws",
                    "check_id": "AWS.SG.OPEN_SSH" if port == 22 else "AWS.SG.OPEN_RDP",
                    "resource_type": "security_group",
                    "resource_id": sg_id,
                    "severity": "high",
                    "title": "SG allows world access to SSH" if port == 22 else "SG allows world access to RDP",
                    "description": f"Inbound port {port} exposed to {', '.join(world)}",
                    "region": region,
                    "evidence_json": _safe_json({
                        "sg": sg_id,
                        "port": port,
                        "world": world,
                        "perm": perm,
                        "time": _utc(),
                    }),
                }
                finding = enrich_finding(finding)
                findings.append(finding)

    # -----------------------------------------------------------------------
    # write everything to CSV
    # -----------------------------------------------------------------------
    # get_fieldnames() from shared.py keeps the column order consistent
    # so when i add azure_connector later the CSV structure will be the same

    fieldnames = get_fieldnames()
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        # extrasaction ignore means extra keys in a finding wont crash the writer
        w.writeheader()
        w.writerows(findings)

    return len(findings)


def scan_aws_demo(output_path: str) -> int:
    # demo mode - skips all the boto3 API calls and uses fake findings instead
    # i import demo_data here rather than at the top so it only loads when needed
    # the fake findings still go through enrich_finding() so CVSS and MITRE are real
    from engine.demo_data import get_demo_findings

    findings = get_demo_findings()

    fieldnames = get_fieldnames()
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(findings)

    return len(findings)