"""Mock detectors for fast Chandra testing - no AWS API calls."""

from chandra.briefing.schemas import Finding
from chandra.tools.base import DetectorContext


def find_idle_ec2(ctx: DetectorContext):
    return [
        Finding(
            kra="cost",
            severity="medium",
            resource_arn="arn:aws:ec2:us-east-1:827295473120:instance/i-0123456789abcdef0",
            resource_type="AWS::EC2::Instance",
            region="us-east-1",
            title="EC2 i-0123456789abcdef0 (t2.micro) idle: avg CPU 2.50% over 14d",
            evidence={"InstanceId": "i-0123456789abcdef0", "AverageCPU": 2.5},
            recommendation="Right-size or terminate unused instance.",
            detector_id="COST-001-idle-ec2",
        )
    ]


def find_unattached_ebs(ctx: DetectorContext):
    return [
        Finding(
            kra="cost",
            severity="low",
            resource_arn="arn:aws:ec2:us-east-1:827295473120:volume/vol-0987654321abcdef0",
            resource_type="AWS::EC2::Volume",
            region="us-east-1",
            title="EBS volume vol-0987654321abcdef0 (100 GiB, gp2) is unattached",
            evidence={"VolumeId": "vol-0987654321abcdef0", "Size": 100},
            recommendation="Delete if not needed.",
            detector_id="COST-002-unattached-ebs",
        )
    ]


def find_unused_eips(ctx: DetectorContext):
    return [
        Finding(
            kra="cost",
            severity="low",
            resource_arn="arn:aws:ec2:us-east-1:827295473120:elastic-ip/eipalloc-0abcdef123456789",
            resource_type="AWS::EC2::EIP",
            region="us-east-1",
            title="Elastic IP 203.0.113.1 is allocated but not associated",
            evidence={"PublicIp": "203.0.113.1"},
            recommendation="Release if not in use.",
            detector_id="COST-003-unused-eip",
        )
    ]


def find_untagged_billable(ctx: DetectorContext):
    return []


def find_public_s3_buckets(ctx: DetectorContext):
    return [
        Finding(
            kra="security",
            severity="critical",
            resource_arn="arn:aws:s3:::my-public-bucket",
            resource_type="AWS::S3::Bucket",
            region="us-east-1",
            title="S3 bucket my-public-bucket is publicly exposed",
            evidence={"PublicAccessBlockConfiguration": None},
            recommendation="Enable Block Public Access.",
            detector_id="SEC-001-public-s3",
        )
    ]


def find_open_security_groups(ctx: DetectorContext):
    return [
        Finding(
            kra="security",
            severity="critical",
            resource_arn="arn:aws:ec2:us-east-1:827295473120:security-group/sg-0123456789abcdef0",
            resource_type="AWS::EC2::SecurityGroup",
            region="us-east-1",
            title="Security group sg-0123456789abcdef0 exposes 22 (SSH) to 0.0.0.0/0",
            evidence={"GroupId": "sg-0123456789abcdef0"},
            recommendation="Restrict to corporate CIDR.",
            detector_id="SEC-002-open-sg-ssh",
        )
    ]


def find_stale_access_keys(ctx: DetectorContext):
    return [
        Finding(
            kra="security",
            severity="high",
            resource_arn="arn:aws:iam::827295473120:user/alice",
            resource_type="AWS::IAM::AccessKey",
            region="global",
            title="IAM access key for alice is 95d old (threshold 90d)",
            evidence={"UserName": "alice", "AccessKeyId": "AKIA...", "AgeDays": 95},
            recommendation="Rotate the key.",
            detector_id="SEC-003-stale-key",
        )
    ]


def check_root_mfa(ctx: DetectorContext):
    return [
        Finding(
            kra="security",
            severity="critical",
            resource_arn=f"arn:aws:iam::{ctx.account_id}:root",
            resource_type="AWS::IAM::RootAccount",
            region="global",
            title="AWS account root user does not have MFA enabled",
            evidence={"SummaryMap": {"AccountMFAEnabled": 0}},
            recommendation="Enable MFA on root account immediately.",
            detector_id="SEC-004-root-mfa",
        )
    ]


def find_overly_permissive_iam(ctx: DetectorContext):
    return []


def check_cloudtrail_multi_region(ctx: DetectorContext):
    return [
        Finding(
            kra="compliance",
            severity="critical",
            resource_arn=f"arn:aws:cloudtrail::{ctx.account_id}:account",
            resource_type="AWS::CloudTrail::Account",
            region="global",
            title="No multi-region CloudTrail with log-file validation is actively logging",
            evidence={"CompliantTrailsFound": 0},
            recommendation="Enable multi-region CloudTrail.",
            detector_id="COMP-002-no-cloudtrail",
        )
    ]


def check_config_recorder(ctx: DetectorContext):
    return [
        Finding(
            kra="compliance",
            severity="high",
            resource_arn=f"arn:aws:config:us-east-1:{ctx.account_id}:recorder",
            resource_type="AWS::Config::ConfigurationRecorder",
            region="us-east-1",
            title="AWS Config recorder is not active in us-east-1",
            evidence={"ConfigurationRecorders": []},
            recommendation="Enable AWS Config.",
            detector_id="COMP-003-no-config-recorder",
        )
    ]


def check_encryption_at_rest_rds(ctx: DetectorContext):
    return []


def check_encryption_at_rest_ebs(ctx: DetectorContext):
    return [
        Finding(
            kra="compliance",
            severity="high",
            resource_arn="arn:aws:ec2:us-east-1:827295473120:volume/vol-unencrypted123",
            resource_type="AWS::EC2::Volume",
            region="us-east-1",
            title="EBS volume vol-unencrypted123 (50 GiB) is unencrypted",
            evidence={"VolumeId": "vol-unencrypted123", "Encrypted": False},
            recommendation="Enable EBS encryption-by-default.",
            detector_id="COMP-004-ebs-unencrypted",
        )
    ]


def check_s3_default_encryption(ctx: DetectorContext):
    return []


def mock_performance_detector(ctx: DetectorContext):
    return []


def mock_reliability_detector(ctx: DetectorContext):
    return []