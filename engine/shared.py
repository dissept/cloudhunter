# engine/shared.py
# This file has the shared logic that all cloud connectors will use
# I put CVSS scoring and MITRE mapping here so I dont repeat code in every connector
# This is important for the thesis because it shows modular design (see architecture diagram)

# ---------------------------------------------------------------------------------
# CVSS v3.1 base scores - I calculated these manually using the CVSS calculator
# at https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
# The vector strings show exactly how I got each score (important for evaluation chapter)
# ---------------------------------------------------------------------------------

# Each check_id maps to: (cvss_score, cvss_vector, mitre_technique_id, mitre_technique_name)
# I use a dict so adding new checks later is easy - just add a new line

RULES: dict[str, dict] = {

    # S3 bucket with public ACL or public bucket policy
    # Attack Network (AN) = None, Privileges Required (PR) = None
    # This is very dangerous because anyone on internet can read/download the data
    "AWS.S3.PUBLIC_HIGH": {
        "cvss_score": 7.5,
        # AV:N = attack from network, AC:L = low complexity, PR:N = no privileges needed
        # UI:N = no user interaction, S:U = unchanged scope, C:H = high confidentiality impact
        # I:N = no integrity impact, A:N = no availability impact
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "high",
        # T1530 = "Data from Cloud Storage Object" - attacker reads files from public bucket
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage Object",
        "mitre_tactic": "Collection",
        "mitre_url": "https://attack.mitre.org/techniques/T1530/",
    },

    # S3 bucket where Public Access Block is not fully configured
    # Lower score than above because just missing PAB doesnt mean bucket is actually public
    # but its still a risk because one wrong policy in future would expose everything
    "AWS.S3.PUBLIC": {
        "cvss_score": 5.3,
        # Same as above but C:L = low confidentiality because not confirmed exposed yet
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "medium",
        # Same technique - attacker could access data if they find the bucket
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage Object",
        "mitre_tactic": "Collection",
        "mitre_url": "https://attack.mitre.org/techniques/T1530/",
    },

    # Security group with SSH (port 22) open to the whole internet
    # Very high score because attacker can try to brute force or use stolen keys
    "AWS.SG.OPEN_SSH": {
        "cvss_score": 8.6,
        # AV:N network attack, AC:L easy, PR:N no privs, S:C scope changes (can pivot to other systems)
        # C:H confidentiality high because if they get in they can read everything on the server
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "severity": "high",
        # T1021.004 = Remote Services: SSH - attacker logs in via SSH
        "mitre_id": "T1021.004",
        "mitre_name": "Remote Services: SSH",
        "mitre_tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/004/",
    },

    # Security group with RDP (port 3389) open to the whole internet
    # Same score as SSH - both are very bad, RDP has had many CVEs historically
    "AWS.SG.OPEN_RDP": {
        "cvss_score": 8.6,
        # Same vector as SSH - same risk level basically
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "severity": "high",
        # T1021.001 = Remote Services: Remote Desktop Protocol
        "mitre_id": "T1021.001",
        "mitre_name": "Remote Services: Remote Desktop Protocol",
        "mitre_tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/001/",
    },
}

# Default rule for check_ids that are not in the dict above
# Shouldnt happen but just in case I add a new check and forget to add the rule
_FALLBACK_RULE = {
    "cvss_score": 0.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "severity": "info",
    "mitre_id": "T0000",
    "mitre_name": "Unknown",
    "mitre_tactic": "Unknown",
    "mitre_url": "https://attack.mitre.org/",
}


def enrich_finding(finding: dict) -> dict:
    """
    This function takes a raw finding from any connector (aws, azure, etc)
    and adds the CVSS score, vector, and MITRE info to it.

    I call it 'enrich' because we are adding more information to what we already have.
    The connectors do the detection work, this function does the scoring work.
    This separation is what my architecture diagram shows.

    Args:
        finding: dict with at least 'check_id' key from the connector

    Returns:
        same dict but with cvss and mitre fields added
    """

    check_id = finding.get("check_id", "")

    # Special case: S3 findings have two possible severities
    # If the policy or ACL is public then its worse than just missing PAB
    # I check the severity that the connector already set to decide which rule to use
    if check_id == "AWS.S3.PUBLIC":
        if finding.get("severity") == "high":
            # policy_public or acl_public was True in aws_connector.py
            rule = RULES["AWS.S3.PUBLIC_HIGH"]
        else:
            # only PAB is missing, no confirmed public access yet
            rule = RULES["AWS.S3.PUBLIC"]
    else:
        # For everything else just look up the rule normally
        # .get() with fallback means we dont crash if check_id is unknown
        rule = RULES.get(check_id, _FALLBACK_RULE)

    # Add all the scoring fields to the finding
    # I copy() the rule so modifying finding later doesnt affect the RULES dict
    finding["cvss_score"] = rule["cvss_score"]
    finding["cvss_vector"] = rule["cvss_vector"]
    finding["mitre_id"] = rule["mitre_id"]
    finding["mitre_name"] = rule["mitre_name"]
    finding["mitre_tactic"] = rule["mitre_tactic"]
    finding["mitre_url"] = rule["mitre_url"]

    return finding


def get_fieldnames() -> list[str]:
    """
    Returns the CSV column names in the order I want them.
    I put this in shared.py so both aws_connector and future azure_connector
    use the same columns - otherwise the CSV files would be inconsistent.
    """
    return [
        "provider",
        "check_id",
        "resource_type",
        "resource_id",
        "severity",
        # CVSS columns - these are the main contribution vs Prowler/ScoutSuite
        "cvss_score",
        "cvss_vector",
        # MITRE columns - map finding to real attacker technique
        "mitre_id",
        "mitre_name",
        "mitre_tactic",
        "mitre_url",
        # Human readable info
        "title",
        "description",
        "region",
        # Raw evidence as JSON so we can always go back and check
        "evidence_json",
    ]