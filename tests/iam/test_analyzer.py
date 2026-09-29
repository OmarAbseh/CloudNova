"""IAM analyzer: catches anti-patterns and privilege-escalation vectors."""

from cloudnova.iam import analyze_policy


def _ids(doc):
    return {f.check_id for f in analyze_policy(doc)}


def test_full_wildcard_is_critical():
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    findings = analyze_policy(doc)
    full = [f for f in findings if f.check_id == "IAM_FULL_WILDCARD"]
    assert full and full[0].severity.value == "critical"


def test_service_wildcard_iam_is_critical():
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
    findings = [f for f in analyze_policy(doc) if f.check_id == "IAM_SERVICE_WILDCARD"]
    assert findings and findings[0].severity.value == "critical"


def test_service_wildcard_s3_is_high():
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"}]}
    findings = [f for f in analyze_policy(doc) if f.check_id == "IAM_SERVICE_WILDCARD"]
    assert findings and findings[0].severity.value == "high"


def test_explicit_privesc_action_flagged():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "arn:aws:iam::1:role/x"}
        ]
    }
    assert "IAM_PRIVESC_ACTION" in _ids(doc)


def test_wildcard_does_not_double_report_privesc_actions():
    # iam:* is flagged as a service wildcard; we don't also list every escalation
    # action it implies (that would be noise).
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
    assert "IAM_PRIVESC_ACTION" not in _ids(doc)


def test_privesc_combo_flagged():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
        ]
    }
    combo = [f for f in analyze_policy(doc) if f.check_id == "IAM_PRIVESC_COMBO"]
    assert combo and combo[0].severity.value == "critical"


def test_wildcard_principal_flagged():
    doc = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    assert "IAM_WILDCARD_PRINCIPAL" in _ids(doc)


def test_notaction_allow_flagged():
    doc = {"Statement": [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]}
    assert "IAM_NOTACTION_ALLOW" in _ids(doc)


def test_scoped_policy_is_clean():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ]
    }
    assert analyze_policy(doc) == []


def test_malformed_input_does_not_crash():
    assert analyze_policy("not a policy") == []
    assert analyze_policy({"Statement": "nope"}) == []
