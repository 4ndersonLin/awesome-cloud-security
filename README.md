<br/>
<div align="center">

A curated list of awesome cloud security related resources.

</div>
<br/>

# Awesome Cloud Security
🛡️Awesome Cloud Security Resources ⚔️

# Contents
- [Standards](#standards)
- [Tools](#tools)
- [Reading materials](#reading-materials)
- [Contributing](#contributing)

# Standards
- [Compliances](#compliances)
- [Benchmarks](#benchmarks)

## Compliances
* [CSA STAR](https://cloudsecurityalliance.org/star/)
* [ISO/IEC 27017:2015](https://www.iso.org/standard/43757.html)
* [ISO/IEC 27018:2019](https://www.iso.org/standard/76559.html)
* [MTCS SS 584](https://www.imda.gov.sg/regulations-and-licensing-listing/ict-standards-and-quality-of-service/IT-Standards-and-Frameworks/ComplianceAndCertification)

## Benchmarks
* [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks/)

# Tools
- [Infrastrcture](#infrastrcture)
- [Container](#container)
- [Serverless](#serverless)
- [Application](#application)
- [Native tools](#nativetools)

## Infrastrcture
* [aws_pwn](https://github.com/dagrz/aws_pwn): A collection of AWS penetration testing junk
* [aws-vault](https://github.com/99designs/aws-vault): A vault for securely storing and accessing AWS credentials in development environments.
* [azucar](https://github.com/nccgroup/azucar): Security auditing tool for Azure environments
* [cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat): "Vulnerable by Design" AWS deployment tool.
* [Cloudmapper](https://github.com/duo-labs/cloudmapper): Analyze your AWS environments.
* [Cloudsploit Scans](https://github.com/cloudsploit/scans): Cloud security configuration checks.
* [Cloud-custodian](https://github.com/cloud-custodian/cloud-custodian): Rules engine for cloud security, cost optimization, and governance.
* [cs suite](https://github.com/SecurityFTW/cs-suite): Tool for auditing the security posture of AWS/GCP/Azure.
* [Forseti security](https://github.com/forseti-security/forseti-security): GCP inventory monitoring and policy enforcement tool.
* [Open policy agent](https://www.openpolicyagent.org/): Policy-based control tool.
* [pacbot](https://github.com/tmobile/pacbot): Policy as Code Bot.
* [pacu](https://github.com/RhinoSecurityLabs/pacu): The AWS exploitation framework.
* [Prowler](https://github.com/toniblyx/prowler): Command line tool for AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool.
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite): Multi-cloud security auditing tool.
* [Security Monkey](https://github.com/Netflix/security_monkey): Monitors AWS, GCP, OpenStack, and GitHub orgs for assets and their changes over time.
* [tfsec](https://github.com/liamg/tfsec): Static analysis powered security scanner for Terraform code.
* [Zeus](https://github.com/DenizParlak/Zeus): AWS Auditing & Hardening Tool.

## Container as a service
* [auditkube](https://github.com/opszero/auditkube): Audit for for EKS, AKS and GKE for HIPAA/PCI/SOC2 compliance and cloud security.
* [ccat](https://github.com/RhinoSecurityLabs/ccat): Cloud Container Attack Tool.
* [Falco](https://github.com/falcosecurity/falco): Container runtime security.
* [mkit](https://github.com/darkbitio/mkit): Managed kubernetes inspection tool.
* [Open policy agent](https://www.openpolicyagent.org/): Policy-based control tool.

## SaaS
* [Function Shield](https://github.com/puresec/FunctionShield): Protection/destection lib of aws lambda and gcp function.
* [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute): A script to enumerate Google Storage buckets.
* [Lambda Guard](https://github.com/Skyscanner/LambdaGuard): AWS Lambda auditing tool.
* [S3 Inspector](https://github.com/kromtech/s3-inspector): Tool to check AWS S3 bucket permissions.
* [Serverless Goat](https://github.com/OWASP/Serverless-Goat): A serverless application demonstrating common serverless security flaws

## Native tools
* AWS
  * [Artifact](https://aws.amazon.com/artifact/): Compliance report selfservice.
  * [Certificate Manager](https://aws.amazon.com/certificate-manager/): Private CA and certificate management service.
  * [CloudTrail](https://aws.amazon.com/cloudtrail/): Record and log API call on AWS.
  * [Config](https://aws.amazon.com/config/): Configuration and resources relationship monitoring.
  * [Detective](https://aws.amazon.com/detective/): Analyze and visualize security data and help security investigations.
  * [Firewall Manager](https://aws.amazon.com/firewall-manager/): Firewall management service.
  * [GuardDuty](https://aws.amazon.com/guardduty/): IDS service
  * [CloudHSM](https://aws.amazon.com/cloudhsm/): HSM service.
  * [Inspector](https://aws.amazon.com/inspector/): Vulnerability discover and assessment service.
  * [KMS](https://aws.amazon.com/kms/): KMS service
  * [Macie](https://aws.amazon.com/macie/): Fully managed data security and data privacy service for S3.
  * [Secret Manager](https://aws.amazon.com/secrets-manager/): Credential management service.
  * [Security Hub](https://aws.amazon.com/security-hub/): Integration service for other AWS and third-party security service. 
  * [Shield](https://aws.amazon.com/shield/): DDoS protection service.
  * [VPC Flowlog](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html): Log of network traffic.
  * [WAF](https://aws.amazon.com/waf/): Web application firewall service.
* Azure
  * [Application Gateway](https://azure.microsoft.com/en-us/services/application-gateway/): L7 load balancer with optional WAF function.
  * [DDoS Protection](https://azure.microsoft.com/en-us/services/ddos-protection/): DDoS protection service.
  * [Dedicated HSM](https://azure.microsoft.com/en-us/services/azure-dedicated-hsm/): HSM service.
  * [Key Vault](https://azure.microsoft.com/en-us/services/key-vault/): KMS service
  * [Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/): API log and monitoring related service.
  * [Security Center](https://azure.microsoft.com/en-us/services/security-center/): Integration service for other Azure and third-party security service.
  * [Sentinel](https://azure.microsoft.com/zh-tw/services/azure-sentinel/): SIEM service.
* GCP
  * [Access Transparency](https://cloud.google.com/access-transparency): Transparency log and control of GCP.
  * [Apigee Sense](https://cloud.google.com/apigee/api-management/apigee-sense): API security monitoring, detection, mitigation.
  * [Armor](https://cloud.google.com/armor): DDoS protection and WAF service
  * [Asset Inventory](https://cloud.google.com/asset-inventory): Asset monitoring service.
  * [Audit Logs](https://cloud.google.com/audit-logs): API logs.
  * [Cloud HSM](https://cloud.google.com/hsm): HSM service
  * [Context-aware Access](https://cloud.google.com/context-aware-access): Enable zero trust access to applications and infrastructure.
  * [DLP](https://cloud.google.com/dlp): DLP service:
  * [EKM](https://cloud.google.com/ekm): External key management service
  * [Identity-Aware Proxy](https://cloud.google.com/iap): Identity-Aware Proxy for protect the internal service.
  * [KMS](https://cloud.google.com/kms): KMS service
  * [Policy Intelligence](https://cloud.google.com/policy-intelligence): Detect the policy related risk.
  * [Security Command Center](https://cloud.google.com/security-command-center): Integration service for other GCP security service.
  * [Security Scanner](https://cloud.google.com/security-scanner): Application security scanner for GAE, GCE, GKE.
  * [Event Threat Detection](https://cloud.google.com/event-threat-detection): Threat dection service.
  * [VPC Service Controls](https://cloud.google.com/vpc-service-controls): GCP service security perimeter control.

# Reading Materials
- [AWS](#aws)
- [Azure](#azure)
- [GCP](#gcp)
- [Others](#others)

## AWS
1. [Overiew of AWS Security](https://aws.amazon.com/security/)
2. [AWS-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation): A centralized source of all AWS IAM privilege escalation methods.
## Azure
1. [Overiew of Azure Security](https://azure.microsoft.com/en-us/overview/security/)
2. [Azure security fundamentals](https://docs.microsoft.com/en-us/azure/security/fundamentals/)
3. [MicroBurst](https://github.com/NetSPI/MicroBurst): A collection of scripts for assessing Microsoft Azure security
## GCP
1. [Overiew of GCP Security](https://cloud.google.com/security)
2. [gke security scenarios demo](https://github.com/GoogleCloudPlatform/gke-security-scenarios-demo)

## Others
1. [Cloud Security Research](https://github.com/RhinoSecurityLabs/Cloud-Security-Research)
2. [CSA cloud security guidance v4](https://cloudsecurityalliance.org/artifacts/security-guidance-v4/)

# Contributing
See [contributing](https://github.com/4ndersonLin/awesome-cloud-security/blob/master/CONTRIBUTING.md)
