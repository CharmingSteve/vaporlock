"""
create_security_groups.py

Creates random nested AWS security groups using boto3.
Security groups reference other security groups as inbound/outbound sources,
producing a tangled graph useful for later mapping and alerting work.

Usage:
    python create_security_groups.py [--region REGION] [--vpc-id VPC_ID]
                                     [--count COUNT] [--prefix PREFIX]
                                     [--dry-run] [--cleanup]

    --region   AWS region (default: us-east-1)
    --vpc-id   Target VPC ID. If omitted the default VPC is used.
    --count    Number of security groups to create (default: 5)
    --prefix   Name prefix for created groups (default: vaporlock)
    --dry-run  Print what would be created without calling AWS
    --cleanup  Delete all security groups whose names start with PREFIX
"""

import argparse
import random
import sys

import boto3
from botocore.exceptions import ClientError

# Ports used when building random rules
COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]
PROTOCOLS = ["tcp", "udp"]


def get_or_create_default_vpc(ec2) -> str:
    """Return the default VPC id for the current region, creating it if absent."""
    response = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpcs = response.get("Vpcs", [])
    if vpcs:
        return vpcs[0]["VpcId"]
    print("No default VPC found; creating one …")
    vpc = ec2.create_default_vpc()
    return vpc["Vpc"]["VpcId"]


def create_security_group(ec2, name: str, description: str, vpc_id: str) -> dict:
    """Create a single security group and return the AWS response object."""
    response = ec2.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "ManagedBy", "Value": "vaporlock"},
                ],
            }
        ],
    )
    group_id = response["GroupId"]
    print(f"  Created security group: {name} ({group_id})")
    return {"GroupId": group_id, "GroupName": name}


def random_cidr_rule(protocol: str) -> dict:
    """Build an inbound IP permission rule with a random CIDR and port."""
    port = random.choice(COMMON_PORTS)
    octet = random.randint(1, 254)
    cidr = f"10.{octet}.0.0/16"
    return {
        "IpProtocol": protocol,
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": cidr, "Description": f"random-{cidr}"}],
    }


def random_sg_rule(protocol: str, source_group_id: str, owner_id: str) -> dict:
    """Build an inbound IP permission that references another security group."""
    port = random.choice(COMMON_PORTS)
    return {
        "IpProtocol": protocol,
        "FromPort": port,
        "ToPort": port,
        "UserIdGroupPairs": [
            {
                "GroupId": source_group_id,
                "UserId": owner_id,
                "Description": f"nested-ref-{source_group_id}",
            }
        ],
    }


def add_rules(ec2, target_id: str, owner_id: str, all_group_ids: list[str]) -> None:
    """Add a random mix of CIDR and security-group-reference rules to target_id."""
    ip_permissions = []

    # One or two CIDR-based rules
    for _ in range(random.randint(1, 2)):
        protocol = random.choice(PROTOCOLS)
        ip_permissions.append(random_cidr_rule(protocol))

    # Zero to two security-group-reference rules (nested references)
    candidates = [gid for gid in all_group_ids if gid != target_id]
    num_nested = min(random.randint(0, 2), len(candidates))
    for source_id in random.sample(candidates, k=num_nested):
        protocol = random.choice(PROTOCOLS)
        ip_permissions.append(random_sg_rule(protocol, source_id, owner_id))

    if not ip_permissions:
        return

    try:
        ec2.authorize_security_group_ingress(
            GroupId=target_id,
            IpPermissions=ip_permissions,
        )
        nested = [
            p["UserIdGroupPairs"][0]["GroupId"]
            for p in ip_permissions
            if "UserIdGroupPairs" in p
        ]
        if nested:
            print(f"    {target_id} references: {nested}")
    except ClientError as exc:
        # Duplicate rules are not fatal
        if exc.response["Error"]["Code"] == "InvalidPermission.Duplicate":
            print(f"    Skipped duplicate rule on {target_id}")
        else:
            raise


def cleanup(ec2, prefix: str) -> None:
    """Delete all security groups whose Name tag starts with prefix."""
    paginator = ec2.get_paginator("describe_security_groups")
    groups = []
    for page in paginator.paginate(
        Filters=[{"Name": "tag:ManagedBy", "Values": ["vaporlock"]}]
    ):
        groups.extend(page["SecurityGroups"])

    target = [g for g in groups if g.get("GroupName", "").startswith(prefix)]
    if not target:
        print(f"No security groups with prefix '{prefix}' found.")
        return

    # Remove cross-references first to avoid dependency errors
    for group in target:
        gid = group["GroupId"]
        try:
            current = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
            if current.get("IpPermissions"):
                ec2.revoke_security_group_ingress(
                    GroupId=gid,
                    IpPermissions=current["IpPermissions"],
                )
        except ClientError:
            pass

    for group in target:
        gid = group["GroupId"]
        name = group.get("GroupName", gid)
        try:
            ec2.delete_security_group(GroupId=gid)
            print(f"  Deleted: {name} ({gid})")
        except ClientError as exc:
            print(f"  Could not delete {name} ({gid}): {exc}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create random nested AWS security groups for testing."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--vpc-id", dest="vpc_id", default=None, help="Target VPC ID")
    parser.add_argument(
        "--count", type=int, default=5, help="Number of security groups to create"
    )
    parser.add_argument(
        "--prefix", default="vaporlock", help="Name prefix for created groups"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned actions without calling AWS",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Delete previously created vaporlock security groups",
    )
    args = parser.parse_args()

    if args.dry_run:
        print(f"[dry-run] Would create {args.count} security groups")
        print(f"[dry-run] Region : {args.region}")
        print(f"[dry-run] VPC    : {args.vpc_id or '<default VPC>'}")
        print(f"[dry-run] Prefix : {args.prefix}")
        print("[dry-run] Each group would receive random CIDR and sg-reference rules.")
        return

    ec2 = boto3.client("ec2", region_name=args.region)

    if args.cleanup:
        print(f"Cleaning up security groups with prefix '{args.prefix}' …")
        cleanup(ec2, args.prefix)
        return

    vpc_id = args.vpc_id or get_or_create_default_vpc(ec2)
    print(f"Using VPC: {vpc_id}")

    # Fetch caller identity for UserIdGroupPairs
    sts = boto3.client("sts", region_name=args.region)
    owner_id = sts.get_caller_identity()["Account"]

    print(f"\nCreating {args.count} security groups …")
    groups: list[dict] = []
    for i in range(1, args.count + 1):
        name = f"{args.prefix}-sg-{i:03d}"
        desc = f"vaporlock auto-generated security group {i}"
        try:
            group = create_security_group(ec2, name, desc, vpc_id)
            groups.append(group)
        except ClientError as exc:
            print(f"  Error creating {name}: {exc}", file=sys.stderr)

    if not groups:
        print("No security groups were created.", file=sys.stderr)
        sys.exit(1)

    all_ids = [g["GroupId"] for g in groups]
    print(f"\nAdding random rules (including nested sg references) …")
    for group in groups:
        add_rules(ec2, group["GroupId"], owner_id, all_ids)

    print(f"\nDone. Created {len(groups)} security groups in VPC {vpc_id}.")
    print("Group IDs:", ", ".join(all_ids))
    print(
        f"\nTo remove them later:\n"
        f"  python create_security_groups.py --region {args.region} --cleanup"
    )


if __name__ == "__main__":
    main()
