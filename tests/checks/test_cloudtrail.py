import json
from pathlib import Path

from cloudnova.core.engine import Engine


def _findings(root: Path):
    return Engine().scan_path(root).findings


def test_real_cloudtrail_wildcard_iam_detected(tmp_path: Path):
    # The exact real-schema record the old prototype scored ZERO on.
    doc = {
        "Records": [
            {
                "eventName": "PutRolePolicy",
                "requestParameters": {
                    "roleName": "AdminRole",
                    "policyDocument": json.dumps(
                        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
                    ),
                },
            }
        ]
    }
    (tmp_path / "ct.json").write_text(json.dumps(doc), encoding="utf-8")
    ids = {f.check_id for f in _findings(tmp_path)}
    assert "CT_IAM_WILDCARD_ADMIN" in ids


def test_scoped_policy_not_flagged(tmp_path: Path):
    doc = {
        "Records": [
            {
                "eventName": "PutRolePolicy",
                "requestParameters": {
                    "roleName": "AppRole",
                    "policyDocument": json.dumps(
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::b/*",
                                }
                            ]
                        }
                    ),
                },
            }
        ]
    }
    (tmp_path / "ct.json").write_text(json.dumps(doc), encoding="utf-8")
    assert not _findings(tmp_path)


def test_public_acl_detected_by_acl_not_name(tmp_path: Path):
    # Bucket name has no "public" in it; the ACL is what makes it public.
    doc = {
        "Records": [
            {
                "eventName": "PutObject",
                "requestParameters": {"bucketName": "corp-data", "x-amz-acl": "public-read"},
            }
        ]
    }
    (tmp_path / "ct.json").write_text(json.dumps(doc), encoding="utf-8")
    assert {f.check_id for f in _findings(tmp_path)} == {"CT_S3_PUBLIC_ACL"}


def test_private_acl_not_flagged(tmp_path: Path):
    doc = {
        "Records": [
            {
                "eventName": "PutObject",
                "requestParameters": {"bucketName": "public-facing-site", "x-amz-acl": "private"},
            }
        ]
    }
    (tmp_path / "ct.json").write_text(json.dumps(doc), encoding="utf-8")
    # Named "public-facing-site" but private ACL -> the prototype's false positive, now gone.
    assert not _findings(tmp_path)
