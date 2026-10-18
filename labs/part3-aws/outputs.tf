output "ejbca_public_ip" {
  description = "Stable Elastic IP of the EJBCA host — unchanged across stop/start."
  value       = aws_eip.ejbca.public_ip
}

output "ssh_command" {
  value = "ssh -i ~/.ssh/pqc-lab ec2-user@${aws_eip.ejbca.public_ip}"
}

output "vpc_id" {
  description = "Lab VPC — the entire teardown surface. `terraform destroy` must leave the account as if this never existed."
  value       = aws_vpc.lab.id
}

output "digest_reminder" {
  value = "After first boot: `cat ~/EJBCA-IMAGE-DIGEST.txt` on the host and record it in docker-labs/vendor/EJBCA-VERSIONS.md"
}

# --- Chapter 21

output "node_public_ips" {
  description = "Fleet nodes (Chapter 21) — CSR collection and certificate install over SSH; empty when fleet_size = 0."
  value       = aws_instance.node[*].public_ip
}

output "nlb_dns_name" {
  description = "NLB front door (TCP passthrough) — empty when enable_nlb = false."
  value       = try(aws_lb.nlb[0].dns_name, "")
}
