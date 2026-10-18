# Part III apparatus — EJBCA CE host in AWS
# Discipline: everything tagged var.project_tag; `terraform destroy` is the teardown and
# was written before the buildout (research notes, 2026-08-16 rule). No resource in this
# file survives a destroy; nothing here stores state the book needs beyond the run.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project = var.project_tag
      Purpose = "pqc-book-part3-issuance-lab"
    }
  }
}

# --- Network: one small dedicated VPC, one public subnet. The NLB experiments
# (passthrough vs termination A/B) attach here later; keeping the lab in its own
# VPC means the teardown surface is the VPC, not the account.

resource "aws_vpc" "lab" {
  cidr_block           = "10.44.0.0/24"
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_tag}-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.44.0.0/26"
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.project_tag}-public" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project_tag}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.project_tag}-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --- Security: admin plane restricted to the operator's address; nothing open to the world.
# The DPoD Luna Cloud HSM is reached OUTBOUND (client bundle egress 443), so no inbound
# rule exists for it — worth a sentence in the chapter: the HSM never dials you.

resource "aws_security_group" "ejbca" {
  name        = "${var.project_tag}-ejbca"
  description = "EJBCA lab host - admin from operator CIDR only"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from operator"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  ingress {
    description = "EJBCA admin/RA TLS from operator"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  ingress {
    description = "EJBCA container HTTPS (8443) from operator, pre-proxy bring-up"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  egress {
    description = "All egress (image pulls, DPoD Luna Cloud HSM, updates)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Host: current Amazon Linux 2023 x86_64 AMI via SSM parameter (never a hardcoded AMI id).

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "ejbca" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.ejbca.id]
  key_name               = var.key_name

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    ejbca_image = var.ejbca_image
  })

  # ERRATUM (2026-10-09, Chapter 21 session): the SSM parameter above tracks the CURRENT AL2023 AMI, which is right
  # for the first build and wrong for every build after it. When Amazon published a newer AMI, `terraform plan`
  # proposed "aws_instance.ejbca must be replaced" — destroying the CA host and its Docker volumes (PostgreSQL,
  # three CAs, the issuing key). Caught by the Chapter 17 rule: read the plan, expect zero destroys. The AMI is a
  # decision made once; later drift in the data source must not replace the host.
  # user_data is frozen for the same reason: the template gained the Compose/Buildx installs during
  # assembly (they were performed by hand in Runbooks 04 and D), and cloud-init only runs at first boot
  # anyway. A fresh apply of this module gets the new template; the live host must not be replaced for it.
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  tags = { Name = "${var.project_tag}-ejbca" }
}

# --- Elastic IP: a static public address, owned and pinned to the instance, so a
# stop/start no longer changes it. Declared in code like everything else — the fix
# for the churning-IP problem is a resource, not a console click.
#
# Cost note for the reader: since Feb 2024 AWS meters ALL public IPv4 by the hour
# (the auto-assigned address was already being charged), so associating an EIP to a
# RUNNING instance costs about the same as the ephemeral address it replaces. The
# EIP-specific charge to remember is for an EIP that is ALLOCATED BUT NOT ASSOCIATED
# — a stopped instance still holds its EIP, so the meter runs while the compute does
# not. Release the EIP at teardown (terraform destroy does this); do not leave a lab
# EIP allocated and idle. This is the cloud's stale-credential lesson in billing form:
# a reserved thing you forgot you reserved.

resource "aws_eip" "ejbca" {
  domain   = "vpc"
  instance = aws_instance.ejbca.id
  tags     = { Name = "${var.project_tag}-eip" }

  # The IP is allocated independently of the instance; associating it here means a
  # stop/start keeps the address. depends_on makes the IGW-before-EIP ordering explicit.
  depends_on = [aws_internet_gateway.igw]
}
