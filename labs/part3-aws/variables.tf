variable "project_tag" {
  description = "Tag applied to every resource; also the teardown handle (destroy finds nothing untagged)."
  type        = string
  default     = "pqc-book-part3"
}

variable "aws_region" {
  description = "Deployment region. IAD/us-east-1 default matches the author's measured network locality."
  type        = string
  default     = "us-east-1"
}

variable "admin_cidr" {
  description = "CIDR allowed to reach SSH and the EJBCA admin UI. Set to <your-public-ip>/32; never 0.0.0.0/0."
  type        = string
}

variable "key_name" {
  description = "Name of an EXISTING EC2 key pair in the region (created/imported by the operator; private key never leaves them)."
  type        = string
}

variable "instance_type" {
  description = "EJBCA host size. t3.xlarge (4 vCPU/16 GiB) is the issuance-measurement baseline; t3.large suffices for bring-up."
  type        = string
  default     = "t3.large"
}

variable "ejbca_image" {
  description = "EJBCA CE container image. Replace tag with the @sha256 digest recorded in docker-labs/vendor/EJBCA-VERSIONS.md at first pull."
  type        = string
  default     = "keyfactor/ejbca-ce"
}

variable "root_volume_gb" {
  description = "Root EBS volume size. EJBCA + its database + logs during scale runs."
  type        = number
  default     = 40
}

# --- Chapter 21: fleet and load balancer (fleet.tf). Off by default; set in terraform.tfvars when the chapter runs.

variable "fleet_size" {
  description = "Number of nginx fleet nodes (Chapter 21). 0 = none; the Chapter 17 apparatus is unchanged."
  type        = number
  default     = 0
}

variable "node_instance_type" {
  description = "Fleet node size. t3.micro serves a static page with an ML-DSA-65 certificate comfortably."
  type        = string
  default     = "t3.micro"
}

variable "enable_nlb" {
  description = "Create the Network Load Balancer (TCP passthrough, 443) in front of the fleet. Requires fleet_size > 0 and ElasticLoadBalancingFullAccess on the lab user."
  type        = bool
  default     = false
}
