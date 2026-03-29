# IMDS Token (Azure)

Materials for **security research and lab exercises** focused on the Azure **Instance Metadata Service (IMDS)** and **managed identities**: obtaining OAuth tokens from inside a VM and using them against Azure APIs (ARM, Key Vault, Microsoft Graph, Log Analytics, and related services).

Use only in environments you own or are explicitly authorized to test.

## Contents

| File | Description |
|------|-------------|
| [`imds-tokem-collector.ps1`](imds-tokem-collector.ps1) | PowerShell script run **on the VM**. Calls IMDS for an ARM token and additional audience tokens, decodes JWT claims for subscription/resource group/VM context, enumerates resources and RBAC, probes Key Vault and Graph where tokens allow, and writes output under `%USERPROFILE%\Desktop\loot`. No extra modules required. |
| [`imds-token-commands.cmd`](imds-token-commands.cmd) | **Reference command cheat sheet** (markdown-style layout). Staged `curl` examples for token theft, audience spray, reconnaissance, RBAC, Key Vault, VM Run Command, snapshots/disks, Log Analytics queries, Azure OpenAI, Microsoft Graph, and cleanup. Intended for shells with `curl` and `jq`; adjust variables and placeholders for your lab. |

## Prerequisites

- An Azure VM with a **user-assigned or system-assigned managed identity** and IMDS reachable at `169.254.169.254`.
- For the PowerShell collector: Windows PowerShell or PowerShell on the VM.
- For the command reference: a Unix-style shell (or equivalent) with `curl` and `jq` if you use the `TOKEN=$(jq …)` patterns.

## See also

- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-security) (Microsoft Learn)
