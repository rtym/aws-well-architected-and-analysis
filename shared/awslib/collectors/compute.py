"""Compute inventory: EC2 instances, Auto Scaling groups, EBS, ELB/ALB/NLB."""
from __future__ import annotations

from ..session import AwsContext, ignore_access_denied, paginate


def describe_instances(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    instances = []
    for reservation in paginate(ec2, "describe_instances", "Reservations"):
        instances.extend(reservation["Instances"])
    return instances


def describe_auto_scaling_groups(ctx: AwsContext, region: str) -> list[dict]:
    asg = ctx.client("autoscaling", region=region)
    return list(paginate(asg, "describe_auto_scaling_groups", "AutoScalingGroups"))


def describe_volumes(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_volumes", "Volumes"))


def describe_snapshots(ctx: AwsContext, region: str, owner_ids: list[str] | None = None) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return list(paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=owner_ids or ["self"]))


def describe_addresses(ctx: AwsContext, region: str) -> list[dict]:
    ec2 = ctx.client("ec2", region=region)
    return ec2.describe_addresses().get("Addresses", [])


def describe_load_balancers_v2(ctx: AwsContext, region: str) -> list[dict]:
    """ALB/NLB/GWLB via the elbv2 API."""
    elbv2 = ctx.client("elbv2", region=region)
    lbs = list(paginate(elbv2, "describe_load_balancers", "LoadBalancers"))
    for lb in lbs:
        lb["_TargetGroups"] = elbv2.describe_target_groups(
            LoadBalancerArn=lb["LoadBalancerArn"]
        ).get("TargetGroups", [])
        lb["_Listeners"] = elbv2.describe_listeners(
            LoadBalancerArn=lb["LoadBalancerArn"]
        ).get("Listeners", [])
    return lbs


# ListCertificates returns only RSA_1024 and RSA_2048 certificates unless
# asked for the others -- ECDSA and larger RSA certificates were silently
# skipped by the expiry check.
ACM_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]


@ignore_access_denied(default=list)
def describe_acm_certificates(ctx: AwsContext, region: str) -> list[dict]:
    acm = ctx.client("acm", region=region)
    summaries = list(
        paginate(
            acm, "list_certificates", "CertificateSummaryList",
            Includes={"keyTypes": ACM_ALL_KEY_TYPES},
        )
    )
    certs = []
    for summary in summaries:
        certs.append(acm.describe_certificate(CertificateArn=summary["CertificateArn"])["Certificate"])
    return certs


def describe_classic_load_balancers(ctx: AwsContext, region: str) -> list[dict]:
    elb = ctx.client("elb", region=region)
    return list(paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions"))


def unattached_volumes(volumes: list[dict]) -> list[dict]:
    return [v for v in volumes if v.get("State") == "available"]


def unassociated_eips(addresses: list[dict]) -> list[dict]:
    return [a for a in addresses if not a.get("AssociationId")]


def instances_allowing_imdsv1(instances: list[dict]) -> list[dict]:
    """SEC06 evidence (FSBP EC2.8): instances where IMDSv2 is not enforced
    (HttpTokens != 'required'), leaving them exposed to SSRF-based
    credential theft via the instance metadata service. Instances with the
    metadata endpoint switched off entirely aren't exposed, and terminated
    instances (still listed for about an hour) no longer exist."""
    return [
        i
        for i in instances
        if i.get("MetadataOptions", {}).get("HttpTokens") != "required"
        and i.get("MetadataOptions", {}).get("HttpEndpoint") != "disabled"
        and i.get("State", {}).get("Name") not in ("terminated", "shutting-down")
    ]


def _redirects_to_https(listener: dict) -> bool:
    """An HTTP listener whose every default action redirects to HTTPS is
    the recommended setup (FSBP ELB.1), not a plaintext exposure."""
    actions = listener.get("DefaultActions") or []
    return bool(actions) and all(
        a.get("Type") == "redirect"
        and (a.get("RedirectConfig") or {}).get("Protocol") == "HTTPS"
        for a in actions
    )


TLS_PASSTHROUGH_PORT = 443


def plaintext_load_balancer_listeners(load_balancers: list[dict]) -> list[dict]:
    """SEC09 evidence: ALB/NLB listeners on HTTP/TCP instead of HTTPS/TLS,
    excluding HTTP listeners that only redirect to HTTPS and TCP listeners
    on port 443. A TCP listener on 443 is how a Network Load Balancer
    passes TLS through to targets that terminate it themselves; the
    listener protocol alone can't show that traffic as plaintext, and
    flagging it sent readers after load balancers that were set up right."""
    findings = []
    for lb in load_balancers:
        for listener in lb.get("_Listeners", []):
            if listener.get("Protocol") == "HTTP" and _redirects_to_https(listener):
                continue
            if listener.get("Protocol") == "TCP" and listener.get("Port") == TLS_PASSTHROUGH_PORT:
                continue
            if listener.get("Protocol") in ("HTTP", "TCP"):
                findings.append(
                    {
                        "LoadBalancerArn": lb["LoadBalancerArn"],
                        "LoadBalancerName": lb.get("LoadBalancerName"),
                        "Port": listener.get("Port"),
                        "Protocol": listener.get("Protocol"),
                    }
                )
    return findings


def expiring_certificates(certificates: list[dict], within_days: int = 30) -> list[dict]:
    """Certs expiring within the window, counting already-expired ones too
    (both need action) but not certs with plenty of runway left."""
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    threshold = now + datetime.timedelta(days=within_days)
    findings = []
    for cert in certificates:
        not_after = cert.get("NotAfter")
        if not_after and not_after <= threshold:
            findings.append(
                {
                    "CertificateArn": cert.get("CertificateArn"),
                    "DomainName": cert.get("DomainName"),
                    "NotAfter": not_after,
                    "InUse": bool(cert.get("InUseBy")),
                }
            )
    return findings


def idle_instance_candidates(instances: list[dict]) -> list[dict]:
    """Instances that are running but have no Name tag / are stopped-and-billed
    for attached EBS -- a cheap static signal; CPU-based idleness needs
    CloudWatch metrics and is layered on top by the cost-optimization skill."""
    return [i for i in instances if i.get("State", {}).get("Name") == "stopped"]


def collect_region_compute(ctx: AwsContext, region: str) -> dict:
    volumes = describe_volumes(ctx, region)
    addresses = describe_addresses(ctx, region)
    instances = describe_instances(ctx, region)
    load_balancers = describe_load_balancers_v2(ctx, region)
    certificates = describe_acm_certificates(ctx, region)
    return {
        "Region": region,
        "Instances": instances,
        "AutoScalingGroups": describe_auto_scaling_groups(ctx, region),
        "Volumes": volumes,
        "Addresses": addresses,
        "LoadBalancersV2": load_balancers,
        "ClassicLoadBalancers": describe_classic_load_balancers(ctx, region),
        "AcmCertificates": certificates,
        "Snapshots": describe_snapshots(ctx, region),
        "UnattachedVolumes": unattached_volumes(volumes),
        "UnassociatedEips": unassociated_eips(addresses),
        "StoppedInstances": idle_instance_candidates(instances),
        "InstancesAllowingImdsv1": instances_allowing_imdsv1(instances),
        "PlaintextListeners": plaintext_load_balancer_listeners(load_balancers),
        "ExpiringCertificates": expiring_certificates(certificates),
    }
