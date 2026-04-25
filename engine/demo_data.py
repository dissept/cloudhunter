# engine/demo_data.py
# fake findings for the --demo mode so the tool can run without real AWS credentials
# the findings here are made up but they are based on real misconfiguration patterns
# from the Microsoft 2022 study and Rahman et al. 2020 in my literature review
# the important thing is they go through the exact same enrich_finding() as real findings
# so the CVSS scores and MITRE mapping are genuine, only the cloud data is synthetic

from engine.shared import enrich_finding


def get_demo_findings() -> list[dict]:
    # five fake findings covering all three check types
    # i used demo- prefix on resource names so its obvious they are not real
    raw: list[dict] = [

        # public S3 bucket - the most classic cloud breach scenario
        # Principal "*" in the bucket policy means anyone on the internet can read it
        # this is how a lot of big data leaks happen, someone leaves a backup bucket open
        {
            "provider": "aws",
            "check_id": "AWS.S3.PUBLIC",
            "resource_type": "s3_bucket",
            "resource_id": "demo-company-backups-2024",
            "severity": "high",
            "title": "S3 bucket may be publicly accessible",
            "description": (
                "PublicAccessBlock is not fully enabled. "
                "Bucket policy contains Principal: '*' which grants public read access."
            ),
            "region": "global",
            "evidence_json": (
                '{"bucket": "demo-company-backups-2024", '
                '"pab": {"BlockPublicAcls": false, "IgnorePublicAcls": false, '
                '"BlockPublicPolicy": false, "RestrictPublicBuckets": false}, '
                '"policy_public": true, "acl_public": false}'
            ),
        },

        # S3 bucket where Public Access Block is just missing, no confirmed public access yet
        # medium not high because the bucket is not actually public right now
        # but if someone adds a wrong policy tomorrow it would be exposed immediately
        {
            "provider": "aws",
            "check_id": "AWS.S3.PUBLIC",
            "resource_type": "s3_bucket",
            "resource_id": "demo-static-assets-prod",
            "severity": "medium",
            "title": "S3 bucket may be publicly accessible",
            "description": (
                "PublicAccessBlock is not configured. "
                "No public policy or ACL found, but missing PAB means a future mistake "
                "could expose this bucket."
            ),
            "region": "global",
            "evidence_json": (
                '{"bucket": "demo-static-assets-prod", '
                '"pab": null, '
                '"policy_public": false, "acl_public": false}'
            ),
        },

        # security group with SSH open to 0.0.0.0/0
        # this means literally anyone on the internet can try to log in via SSH
        # attackers scan for port 22 constantly, you can see it live on shodan.io
        {
            "provider": "aws",
            "check_id": "AWS.SG.OPEN_SSH",
            "resource_type": "security_group",
            "resource_id": "sg-0abc123def456a789",
            "severity": "high",
            "title": "SG allows world access to SSH",
            "description": "Inbound port 22 exposed to 0.0.0.0/0 — anyone on the internet can attempt SSH.",
            "region": "us-east-1",
            "evidence_json": (
                '{"sg": "sg-0abc123def456a789", '
                '"port": 22, "world": ["0.0.0.0/0"], '
                '"protocol": "tcp", "from_port": 22, "to_port": 22}'
            ),
        },

        # same security group also has RDP open to the world
        # RDP has had really bad CVEs historically like BlueKeep and DejaBlue
        # combined with open SSH this is a very bad security group
        {
            "provider": "aws",
            "check_id": "AWS.SG.OPEN_RDP",
            "resource_type": "security_group",
            "resource_id": "sg-0abc123def456a789",
            "severity": "high",
            "title": "SG allows world access to RDP",
            "description": "Inbound port 3389 exposed to 0.0.0.0/0 — anyone on the internet can attempt RDP.",
            "region": "us-east-1",
            "evidence_json": (
                '{"sg": "sg-0abc123def456a789", '
                '"port": 3389, "world": ["0.0.0.0/0"], '
                '"protocol": "tcp", "from_port": 3389, "to_port": 3389}'
            ),
        },

        # a second security group with SSH open, this time on both IPv4 and IPv6
        # shows the tool catches the same problem across multiple resources
        # and that it handles ::/0 (IPv6) as well as 0.0.0.0/0 (IPv4)
        {
            "provider": "aws",
            "check_id": "AWS.SG.OPEN_SSH",
            "resource_type": "security_group",
            "resource_id": "sg-0def987abc654b321",
            "severity": "high",
            "title": "SG allows world access to SSH",
            "description": "Inbound port 22 exposed to 0.0.0.0/0 and ::/0 (IPv4 and IPv6).",
            "region": "us-east-1",
            "evidence_json": (
                '{"sg": "sg-0def987abc654b321", '
                '"port": 22, "world": ["0.0.0.0/0", "::/0"], '
                '"protocol": "tcp", "from_port": 0, "to_port": 65535}'
            ),
        },
    ]

    # run all the fake findings through the real enrichment pipeline
    # CVSS and MITRE come from shared.py, same as in a real scan
    return [enrich_finding(f) for f in raw]