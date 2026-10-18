# Part III, Chapter 21 — the fleet and the load balancer. Added 2026-09-27; everything here is OFF by default
# (fleet_size = 0, enable_nlb = false), so `terraform plan` on the Chapter 17 apparatus shows no change until the
# operator sets them in terraform.tfvars. Same VPC, same tags, same teardown handle: `terraform destroy` removes all
# of it. main.tf is untouched — it is what Chapter 17 published.
#
# What Chapter 21 measures with this:
#   1. Issuance at scale — labs/part3-aws/issue-batch.sh on the CA host: N leaves through the CLI, timed → certs/s,
#      and with the instance's hourly price, $/certificate. Nothing here is needed for that; it runs on the CA host.
#   2. A fleet of nginx nodes (Amazon Linux 2023, OpenSSL 3.5.7) each generating its own ML-DSA-65 key and CSR at
#      boot (USERGENERATED discipline: the CA never sees a private key), serving TLS 1.3 with ssl_ecdh_curve
#      leading with X25519MLKEM768. The operator collects the CSRs, PQC-Issuing-CA issues, the certs go back.
#   3. A Network Load Balancer in TCP passthrough: the hybrid handshake and the ML-DSA-65 certificate travel
#      untouched, so `openssl s_client -connect <nlb>:443 -groups X25519MLKEM768 -sigalgs mldsa65` should complete.
#   4. The Application Load Balancer question is measured by hand, not declared here: an ALB terminates TLS with an
#      ACM certificate, so the experiment is `aws acm import-certificate` with the ML-DSA-65 leaf — expected to be
#      refused — and a look at the ALB TLS policies for a hybrid group. The refusal is the finding ("whose TLS
#      stack are you on?" at the cloud edge), and it needs no resources to demonstrate.
# IAM: the pqc-lab group needs ElasticLoadBalancingFullAccess for step 3 (attach in the console as in Chapter 17).
# NLB targets with client-IP preservation see the OPERATOR's address, so the node security group admits 443 from
# admin_cidr (the probes) and from the VPC (health checks) — never from 0.0.0.0/0.

resource "aws_security_group" "node" {
  count       = var.fleet_size > 0 ? 1 : 0
  name        = "${var.project_tag}-node"
  description = "Fleet node - SSH/TLS from operator; TLS from VPC for NLB health checks"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from operator (CSR collection, cert install)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  ingress {
    description = "TLS from operator, directly and via NLB (client IP preserved)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  ingress {
    description = "TLS from the VPC (NLB health checks)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }
  ingress {
    description = "TLS from the CA host EIP (NLB preserves the client address, so probes via the balancer arrive from it)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["${aws_eip.ejbca.public_ip}/32"]
  }
  egress {
    description = "All egress (dnf)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "node" {
  count                  = var.fleet_size
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.node_instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.node[0].id]
  key_name               = var.key_name

  user_data = templatefile("${path.module}/node-user-data.sh.tftpl", {
    node_name = "pqc-node${count.index + 1}.example.internal"
  })

  lifecycle {
    ignore_changes = [ami]   # same lesson as main.tf: a newer AMI must not rebuild a node that holds a key and a certificate
  }

  tags = { Name = "${var.project_tag}-node${count.index + 1}" }
}

# --- Network Load Balancer, TCP passthrough on 443. No certificate on the balancer; the nodes terminate TLS.

resource "aws_lb" "nlb" {
  count              = var.enable_nlb && var.fleet_size > 0 ? 1 : 0
  name               = "${var.project_tag}-nlb"
  load_balancer_type = "network"
  internal           = false
  subnets            = [aws_subnet.public.id]
  tags               = { Name = "${var.project_tag}-nlb" }
}

resource "aws_lb_target_group" "tls" {
  count       = var.enable_nlb && var.fleet_size > 0 ? 1 : 0
  name        = "${var.project_tag}-tg443"
  port        = 443
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.lab.id
  health_check {
    protocol = "TCP"
    port     = "443"
  }
}

resource "aws_lb_target_group_attachment" "node" {
  count            = var.enable_nlb ? var.fleet_size : 0
  target_group_arn = aws_lb_target_group.tls[0].arn
  target_id        = aws_instance.node[count.index].id
  port             = 443
}

resource "aws_lb_listener" "tcp443" {
  count             = var.enable_nlb && var.fleet_size > 0 ? 1 : 0
  load_balancer_arn = aws_lb.nlb[0].arn
  port              = 443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tls[0].arn
  }
}
