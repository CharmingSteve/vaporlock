# vaporlock

Tools for generating, mapping, and alerting on confusing AWS security group configurations.

## create_security_groups.py

Creates a set of randomly nested AWS security groups in a target VPC.
Each group is given a random mix of CIDR-based and security-group-reference
inbound rules, producing the tangled graphs that later mapping and alerting
work will analyse.

### Prerequisites

```bash
pip install -r requirements.txt
```

AWS credentials must be configured (e.g. via `aws configure`, environment
variables, or an IAM role).

### Usage

```
python create_security_groups.py [options]

Options:
  --region   AWS region (default: us-east-1)
  --vpc-id   Target VPC ID; uses the default VPC if omitted
  --count    Number of security groups to create (default: 5)
  --prefix   Name prefix for created groups (default: vaporlock)
  --dry-run  Print planned actions without calling AWS
  --cleanup  Delete all security groups previously created by this script
```

### Examples

```bash
# Preview what would be created
python create_security_groups.py --dry-run

# Create 10 nested security groups in us-west-2
python create_security_groups.py --region us-west-2 --count 10

# Target a specific VPC
python create_security_groups.py --vpc-id vpc-0abc123 --count 8

# Clean up afterwards
python create_security_groups.py --region us-west-2 --cleanup
```