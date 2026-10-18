# Part III AWS Apparatus — EJBCA Issuance Lab

*The Terraform here is the book's value-added layer around unmodified upstream EJBCA (decision 2026-09-06): the reader reproduces the enterprise deployment, not a fork. Credentials rule: the operator runs `terraform`/`aws` with their own credentials; nothing here embeds a secret.*

## Where Terraform runs (read this first)

Terraform is not infrastructure; it is a program on **your workstation** that calls the AWS API and keeps a local ledger — the state file — of what it built. Nothing exists in the cloud before the first `apply`, and nothing should remain after the last `destroy`. You do not need an EC2 instance to run Terraform; the EC2 instance is what Terraform *creates*. The state file (`terraform.tfstate`) is how `destroy` knows exactly what to delete — keep it, and keep it out of version control (see `.gitignore`): it records resource details that do not belong in a public repository.

## Installing Terraform on Windows

Two routes; either ends at the same verification command. Versions below were current at time of writing (Terraform 1.16.1, September 2, 2026) — check for the current release at time of use.

**Route 1 — winget** (ships with Windows 11; the package manager verifies the publisher for you):

```bat
winget install HashiCorp.Terraform
```

Open a **new** terminal afterward (PATH changes do not reach already-open windows — a two-minute mystery every reader is spared by this sentence). Note that winget's catalog may trail HashiCorp's newest release by a version — `terraform -version` will say so in a banner. That is the package-manager trade (verified convenience over absolute freshness) and it is harmless here: this lab requires only ≥ 1.5. Measured live during writing: winget delivered 1.15.8 while 1.16.1 was current, and everything below ran identically.

**Route 2 — direct download, checksum-verified.** HashiCorp publishes every release with a SHA256SUMS file beside it, and Windows carries the verification instrument natively — the same `certutil` this book used to examine certificates:

```bat
curl.exe -LO https://releases.hashicorp.com/terraform/1.16.1/terraform_1.16.1_windows_amd64.zip
curl.exe -LO https://releases.hashicorp.com/terraform/1.16.1/terraform_1.16.1_SHA256SUMS

certutil -hashfile terraform_1.16.1_windows_amd64.zip SHA256
findstr windows_amd64 terraform_1.16.1_SHA256SUMS
```

The two hashes must match exactly; then unzip `terraform.exe` to a directory on your PATH (e.g. `C:\Terraform`, added under System Properties → Environment Variables). This route is the air-gapped-estate and change-controlled-workstation path — and it practices the book's discipline on the book's own tooling: verify the instrument before trusting what it builds.

**Either route, prove the install:**

```bat
terraform -version
```

Expected: `Terraform v1.16.1 on windows_amd64` (or newer; this lab's configuration requires ≥ 1.5).

## Creating the lab IAM user (do not use root keys)

The AWS CLI needs an access key, and the one non-negotiable is where it comes from: a dedicated IAM user, never the account root. AWS's own guidance is that root access keys should not exist at all — the root identity cannot be permission-bounded, so a leaked root key is the whole account. A lab user, by contrast, is exactly as dangerous as the policies attached to it, and can be deleted the day the lab ends.

In the AWS Console (exact screens shift with AWS's UI; the nouns are stable), the flow the console itself steers you toward is group-first, and it is the better pattern — permissions belong to the group, people belong to the group, and neither has to be re-derived when the other changes:

1. **IAM → User groups → Create group** — name it `pqc-lab-group` and attach two policies: `AmazonEC2FullAccess` and `AmazonSSMReadOnlyAccess`.
2. **IAM → Users → Create user** — name it `pqc-lab`, and do *not* grant console access (this user is API-only: no password, nothing to phish). At the permissions step, **add the user to `pqc-lab-group`** rather than attaching policies directly.
3. Open the created user: **Security credentials → Create access key → Command Line Interface (CLI)** → create, and record both values immediately — the secret is displayed once and never again.

The effective permissions are identical to attaching the policies directly (verified during writing — the console recommended the group flow, we followed it, and the identity behaved the same). What the indirection buys is administrative: a second lab member is one "add user to group" click, and when the NLB phase adds `ElasticLoadBalancingFullAccess`, it is attached once to the group, not per-user.

An honest note on the permission choice: `AmazonEC2FullAccess` is broader than this lab strictly needs, and a production estate would write a least-privilege policy naming the specific actions. The trade is deliberate and worth understanding: a hand-tuned policy for a tutorial goes stale with every AWS API addition and fails readers in undiagnosable ways ("UnauthorizedOperation" three resources into an apply), while the managed policy is stable, scoped to one service, and attached to a disposable user in a lab account. When the NLB experiments begin, `ElasticLoadBalancingFullAccess` joins it — added then, not before, so the user's permissions grow only when the lab does.

Configure and prove:

```bash
aws configure        # paste the two keys; region us-east-1; output json
aws sts get-caller-identity
```

The identity check should return an ARN ending `user/pqc-lab` — the control plane speaks for the lab user, not for root, and the workstation is ready.

Teardown includes the identity: when Part III's measurements are done, **IAM → Users → pqc-lab → Delete**. Credentials that outlive their purpose are the cloud's stale-CRL problem — revocation you meant to do and didn't.

## Bring-up

```bash
cd labs/part3-aws
terraform init
terraform apply \
  -var admin_cidr="$(curl -s https://checkip.amazonaws.com)/32" \
  -var key_name=<existing-ec2-keypair-name>
```

What this creates (all tagged `pqc-book-part3`): one /24 VPC with a public subnet, an admin-only security group (SSH/443/8443 from your address; the DPoD HSM is outbound-only — the HSM never dials you), and one Amazon Linux 2023 instance that installs Docker, **pre-pulls the EJBCA image and records its digest** to `~/EJBCA-IMAGE-DIGEST.txt` (copy that value into `docker-labs/vendor/EJBCA-VERSIONS.md`). EJBCA is deliberately *not* started by cloud-init — the first start is a transcribed runbook step.

## Teardown (written before the buildout, per project rule)

```bash
terraform destroy
# verification — both must return empty:
aws ec2 describe-instances --filters "Name=tag:Project,Values=pqc-book-part3" \
  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text
aws ec2 describe-vpcs --filters "Name=tag:Project,Values=pqc-book-part3" \
  --query 'Vpcs[].VpcId' --output text
```

Cost discipline: the instance is the only metered resource of consequence; `aws ec2 stop-instances` between sessions, destroy at the end of each phase. The HSM trial clock is independent of all of this — nothing here touches DPoD until the client bundle is uploaded by hand.

## Sequence (matches the runbooks)

1. `terraform apply` → host up, image pre-pulled, digest recorded.
2. **Software-token dry run** (Runbook 02-soft, HSM-free): start EJBCA with its default soft crypto token, stand up a throwaway ML-DSA CA, issue one certificate, verify it with OpenSSL 3.5.7 — proves the whole pipeline while the HSM is unreachable.
3. On DPoD access: upload the Luna client bundle to `/opt/dpod`, run the mechanism gate from the instance (Runbook 01 Step 4 targets), bind the EJBCA crypto token via PKCS#11.
4. Scale issuance + measurement harness; NLB passthrough/termination A/B attaches to this VPC.
5. `terraform destroy`; verify empty; keep only transcripts and data.
