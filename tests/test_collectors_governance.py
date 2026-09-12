import boto3
from moto import mock_aws

from shared.awslib.collectors import compute, cost, observability, security


@mock_aws
def test_config_recorder_status_reports_recording(ctx):
    cfg = boto3.client("config", region_name="us-east-1")
    iam = boto3.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(
        RoleName="config-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )["Role"]["Arn"]
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="config-bucket")
    cfg.put_configuration_recorder(
        ConfigurationRecorder={"name": "default", "roleARN": role_arn, "recordingGroup": {"allSupported": True}}
    )
    cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "config-bucket"})
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")

    status = security.config_recorder_status(ctx, "us-east-1")

    assert status["Recording"] is True
    assert len(status["Recorders"]) == 1


@mock_aws
def test_config_recorder_status_not_recording_when_absent(ctx):
    status = security.config_recorder_status(ctx, "us-east-1")
    assert status["Recording"] is False
    assert status["Recorders"] == []


@mock_aws
def test_instances_allowing_imdsv1_flagged():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    images = ec2.describe_images()["Images"]
    ami_id = images[0]["ImageId"] if images else "ami-12345678"
    ec2.run_instances(
        ImageId=ami_id,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        MetadataOptions={"HttpTokens": "optional"},
    )
    reservations = ec2.describe_instances()["Reservations"]
    instances = [i for r in reservations for i in r["Instances"]]

    flagged = compute.instances_allowing_imdsv1(instances)
    assert len(flagged) == 1


def test_plaintext_load_balancer_listeners_detects_http():
    lbs = [
        {
            "LoadBalancerArn": "arn:1",
            "LoadBalancerName": "web",
            "_Listeners": [{"Protocol": "HTTP", "Port": 80}, {"Protocol": "HTTPS", "Port": 443}],
        }
    ]
    findings = compute.plaintext_load_balancer_listeners(lbs)
    assert len(findings) == 1
    assert findings[0]["Port"] == 80


def test_expiring_certificates_filters_by_window():
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    certs = [
        {"CertificateArn": "expired", "DomainName": "expired.example.com", "NotAfter": now - datetime.timedelta(days=5)},
        {"CertificateArn": "soon", "DomainName": "soon.example.com", "NotAfter": now + datetime.timedelta(days=10)},
        {"CertificateArn": "later", "DomainName": "later.example.com", "NotAfter": now + datetime.timedelta(days=200)},
    ]
    expiring = compute.expiring_certificates(certs, within_days=30)
    assert {c["CertificateArn"] for c in expiring} == {"expired", "soon"}


@mock_aws
def test_budgets_returns_configured_budgets(ctx):
    bg = boto3.client("budgets", region_name="us-east-1")
    bg.create_budget(
        AccountId="123456789012",
        Budget={
            "BudgetName": "monthly-cost",
            "BudgetLimit": {"Amount": "1000", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )

    result = cost.budgets(ctx)
    assert any(b["BudgetName"] == "monthly-cost" for b in result)


@mock_aws
def test_observability_alarms_without_actions(ctx):
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_alarm(
        AlarmName="no-action-alarm",
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    cw.put_metric_alarm(
        AlarmName="with-action-alarm",
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        AlarmActions=["arn:aws:sns:us-east-1:123456789012:alerts"],
    )

    result = observability.collect_region_observability(ctx, "us-east-1")

    assert len(result["Alarms"]) == 2
    no_action_names = {a["AlarmName"] for a in result["AlarmsWithNoActions"]}
    assert no_action_names == {"no-action-alarm"}
