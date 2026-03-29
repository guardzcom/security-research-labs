# Entra ID Enterprise Applications — Known Client IDs

> Reference: Microsoft first-party apps, FOCI members, BroCI brokers, phishing targets, and known-bad apps.
> Sources: Secureworks FOCI Research, merill/microsoft-info, GraphPreConsentExplorer, entrascopes.com, Microsoft Learn, SpecterOps, Red Canary.
> Last updated: 2026-03-26

---

## Microsoft Tenant IDs

| Tenant ID | Owner |
|-----------|-------|
| `f8cdef31-a31e-4b4a-93e4-5f571e91255a` | Microsoft Services |
| `72f988bf-86f1-41af-91ab-2d7cd011db47` | Microsoft Corp (Redmond) |

---

## FOCI — Family of Client IDs (36 members)

Apps that share a Family Refresh Token (FRT). Authenticate as App A, refresh token works for App B.
Source: [secureworks/family-of-client-ids-research](https://github.com/secureworks/family-of-client-ids-research)

| Client ID | Application |
|-----------|-------------|
| `00b41c95-dab0-4487-9791-b9d2c32c80f2` | Office 365 Management |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Microsoft Azure CLI |
| `0ec893e0-5785-4de6-99da-4ed124e5296c` | Office UWP PWA |
| `1950a258-227b-4e31-a9cf-717495945fc2` | Microsoft Azure PowerShell |
| `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Microsoft Teams |
| `22098786-6e16-43cc-a27d-191a01a1e3b5` | Microsoft To-Do Client |
| `26a7ee05-5602-4d76-a7ba-eae8b7b67941` | Windows Search |
| `27922004-5251-4030-b22d-91ecd9a37ea4` | Outlook Mobile |
| `2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8` | Microsoft Bing Search for Microsoft Edge |
| `4813382a-8fa7-425e-ab75-3b753aab3abb` | Microsoft Authenticator App |
| `4e291c71-d680-4d0e-9640-0a3358e31177` | PowerApps |
| `57336123-6e14-4acc-8dcf-287b6088aa28` | Microsoft Whiteboard Client |
| `57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0` | Microsoft Flow |
| `66375f6b-983f-4c2c-9701-d680650f588f` | Microsoft Planner |
| `844cca35-0656-46ce-b636-13f48b0eecbd` | Microsoft Stream Mobile Native |
| `872cd9fa-d31f-45e0-9eab-6e460a02d1f1` | Visual Studio |
| `87749df4-7ccf-48f8-aa87-704bad0e0e16` | Microsoft Teams Device Admin Agent |
| `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223` | Microsoft Intune Company Portal |
| `a40d7d7d-59aa-447e-a655-679a4107e548` | Accounts Control UI |
| `a569458c-7f2b-45cb-bab9-b7dee514d112` | Yammer iPhone |
| `ab9b8c07-8f02-4f72-87fa-80105867a763` | OneDrive SyncEngine |
| `af124e86-4e96-495a-b70a-90f90ab96707` | OneDrive iOS App |
| `b26aadf8-566f-4478-926f-589f601d9c74` | OneDrive |
| `be1918be-3fe3-4be9-b32b-b542fc27f02e` | M365 Compliance Drive Client |
| `c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12` | Microsoft Power BI |
| `cab96880-db5b-4e15-90a7-f3f1d62ffe39` | Microsoft Defender Platform |
| `cf36b471-5b44-428c-9ce7-313bf84528de` | Microsoft Bing Search |
| `d326c1ce-6cc6-4de2-bebc-4591e5e13ef0` | SharePoint |
| `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office |
| `d7b530a4-7680-4c23-a8bf-c52c121d2e87` | Microsoft Edge Enterprise New Tab Page |
| `dd47d17a-3194-4d86-bfd5-c6ae6f5651e3` | Microsoft Defender for Mobile |
| `e9b154d0-7658-433b-bb25-6b8e0a8a7c59` | Outlook Lite |
| `e9c51622-460d-4d3d-952d-966a5b1da34c` | Microsoft Edge |
| `eb539595-3fe1-474e-9c1d-feb3625d1be5` | Microsoft Tunnel |
| `ecd6b820-32c2-49b6-98a6-444530e5a77a` | Microsoft Edge |
| `f05ff7c9-f75a-4acd-a3b5-f4b6a870245d` | SharePoint Android |
| `f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34` | Microsoft Edge |

---

## BroCI — Broker Client IDs (NAA-Enabled)

Apps that can broker token requests for nested apps. Carries MFA state across apps.
Source: [SpecterOps NAA/BroCI Research](https://specterops.io/blog/2025/10/15/naa-or-broci-let-me-explain/)

| Client ID | Application | Broker Capability |
|-----------|-------------|-------------------|
| `4813382a-8fa7-425e-ab75-3b753aab3abb` | Microsoft Authenticator | Mobile app broker |
| `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223` | Intune Company Portal | Intune-managed app broker |
| `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | Azure Portal | Web app broker |
| `74658136-14ec-4630-ad9b-26e160ff0fc6` | ADIbizaUX | Azure Portal nested broker |
| `5e3ce6c0-2b1f-4285-8d4b-75ee78787346` | Teams Web | Web app broker |
| `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Teams Desktop/Mobile | Desktop/mobile broker |
| `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office | Office apps broker |

---

## Device Code Phishing — High-Value Targets

First-party client IDs used in device code phishing to appear legitimate.
Source: Storm-2372 (Microsoft), Volexity, Proofpoint

| Client ID | Application | Why Effective |
|-----------|-------------|---------------|
| `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office | Most common, universally trusted |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure CLI | Pre-trusted, bypasses consent |
| `1950a258-227b-4e31-a9cf-717495945fc2` | Azure PowerShell | Admin-targeted |
| `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Microsoft Teams | High adoption, trusted |
| `29d9ed98-a469-4536-ade2-f981bc1d605e` | Microsoft Authentication Broker | Storm-2372 shifted to this |
| `27922004-5251-4030-b22d-91ecd9a37ea4` | Outlook Mobile | Email pretext |
| `ab9b8c07-8f02-4f72-87fa-80105867a763` | OneDrive SyncEngine | File-sharing pretext |

---

## Core Microsoft Services — Well-Known App IDs

| Client ID | Application | Category |
|-----------|-------------|----------|
| `00000002-0000-0ff1-ce00-000000000000` | Office 365 Exchange Online | Exchange |
| `00000003-0000-0000-c000-000000000000` | Microsoft Graph | API |
| `00000003-0000-0ff1-ce00-000000000000` | Office 365 SharePoint Online | SharePoint |
| `00000006-0000-0ff1-ce00-000000000000` | Microsoft Office | Productivity |
| `00000007-0000-0ff1-ce00-000000000000` | Microsoft Teams Services | Teams |
| `00000009-0000-0000-c000-000000000000` | Power BI Service | Analytics |
| `4345a7b9-9a63-4910-a426-35363201d503` | O365 Suite UX | Portal |
| `4765445b-32c6-49b0-83e6-1d93765276ca` | Office Portal | Portal |
| `89bee1f7-5e6e-4d8a-9f3d-ecd601259da7` | Office 365 Management | Management |
| `de8bc8b5-d9f9-48b1-a8ad-b748da725064` | Graph Explorer | Developer |
| `14d82eec-204b-4c2f-b7e8-296a70dab67e` | Microsoft Graph CLI Tools | Developer |

---

## Azure and Developer Tools

| Client ID | Application | Category |
|-----------|-------------|----------|
| `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | Azure Portal | Portal |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure CLI | CLI |
| `fb78d390-0c51-40cd-8e17-fdbfab77341b` | Azure CLI (alt) | CLI |
| `1950a258-227b-4e31-a9cf-717495945fc2` | Azure PowerShell | CLI |
| `872cd9fa-d31f-45e0-9eab-6e460a02d1f1` | Visual Studio | IDE |
| `2ff814a6-3304-4ab8-85cb-cd0e6f879c1d` | Azure Databricks | Data |
| `2746ea77-4702-4b45-80ca-3c97e680e8b7` | Azure Data Explorer | Data |
| `cb2ff863-7f30-4ced-ab89-a00194bcf6d9` | Azure AI Studio App | AI |
| `d7304df8-741f-47d3-9bc2-df0e24e2071f` | Azure ML Workbench Web | AI |

---

## Identity and Security

| Client ID | Application | Category |
|-----------|-------------|----------|
| `1b730954-1685-4b74-9bfd-dac224a7b894` | Azure AD PowerShell / AADInternals | Identity |
| `cb1056e2-e479-49de-ae31-7812af012ed8` | Azure AD Connect | Sync |
| `6bf85cfa-ac8a-4be5-b5de-425a0d0dc016` | Entra AD Synchronization Service | Sync |
| `dda27c27-f274-469f-8005-cce10f270009` | AAD Password Protection Proxy | Security |
| `55747057-9b5d-4bd4-b387-abf52a8bd489` | Azure AD Application Proxy Connector | Proxy |
| `38aa3b87-a06d-4817-b275-7a316988d93b` | Windows Sign In | Auth |
| `19db86c3-b2b9-44cc-b339-36da233a3be2` | My Signins | Auth |
| `98785600-1bb7-4fb9-b9fa-19afe2c8a360` | Azure Security Insights | Security |
| `bb3d68c2-d09e-4455-94a0-e323996dbaa3` | Medeina Service (Security Copilot) | Security |
| `bb5ffd56-39eb-458c-a53a-775ba21277da` | Security Copilot | Security |

---

## Teams and Communication

| Client ID | Application | Category |
|-----------|-------------|----------|
| `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Microsoft Teams | Desktop/Mobile |
| `5e3ce6c0-2b1f-4285-8d4b-75ee78787346` | Teams Web | Web |
| `cc15fd57-2c6c-4117-a88c-83b1d56b4bbe` | Microsoft Teams Admin | Admin |
| `0ec893e0-5785-4de6-99da-4ed124e5296c` | Teams Web Client | Web |
| `87749df4-7ccf-48f8-aa87-704bad0e0e16` | Teams Device Admin Agent | Devices |
| `8e55a7b1-6766-4f0a-8610-ecacfe3d569a` | Microsoft Teams Copilot Bot | AI |
| `4cba1704-a0c1-45ee-9d41-fe75b4ef9190` | Teams Chat Service App | Backend |
| `78462efa-e271-409c-a90b-ce3fbd93538a` | Teams Admin Gateway Service | Backend |
| `66c23536-2118-49d3-bc66-54730b057680` | Skype Core Calling Service | Calling |

---

## Exchange and Email

| Client ID | Application | Category |
|-----------|-------------|----------|
| `00000002-0000-0ff1-ce00-000000000000` | Office 365 Exchange Online | Core |
| `1150aefc-07de-4228-b2b2-042a536703c0` | Exchange Online | Service |
| `34421fbe-f100-4e5b-9c46-2fea25aa7b88` | Exchange Online | Service |
| `82d8ab62-be52-a567-14ea-1616c4ee06c4` | Exchange Online | Service |
| `a3883eba-fbe9-48bd-9ed3-dca3e0e84250` | Exchange Online | Service |
| `aa813f0e-407a-459d-93af-805f2bf10f33` | Exchange Online | Service |
| `d396de1f-10d4-4023-aae2-5bb3d724ba9a` | Exchange Online | Service |
| `fe053c5f-3692-4f14-aef2-ee34fc081cae` | Exchange Online | Service |
| `27922004-5251-4030-b22d-91ecd9a37ea4` | Outlook Mobile | Client |
| `e9b154d0-7658-433b-bb25-6b8e0a8a7c59` | Outlook Lite | Client |
| `9199bf20-a13f-4107-85dc-02114787ef48` | One Outlook Web | Client |
| `87223343-80b1-4097-be13-2332ffa1d666` | Outlook Web App Widgets | Widgets |
| `b24835c0-6b13-41e7-822c-94c9effb98ee` | FrontendTransport | Transport |
| `61c28d8b-814f-4a57-9c7f-8cd0580aead2` | Iris Provider EOP Web Service | EOP |

---

## SharePoint, OneDrive, and Storage

| Client ID | Application | Category |
|-----------|-------------|----------|
| `00000003-0000-0ff1-ce00-000000000000` | Office 365 SharePoint Online | Core |
| `d326c1ce-6cc6-4de2-bebc-4591e5e13ef0` | SharePoint | Client |
| `f05ff7c9-f75a-4acd-a3b5-f4b6a870245d` | SharePoint Android | Mobile |
| `ab9b8c07-8f02-4f72-87fa-80105867a763` | OneDrive SyncEngine | Sync |
| `af124e86-4e96-495a-b70a-90f90ab96707` | OneDrive iOS App | Mobile |
| `b26aadf8-566f-4478-926f-589f601d9c74` | OneDrive | Desktop |
| `9bc3ab49-b65d-410a-85ad-de819febfddc` | SharePoint Online Management Shell | Admin |

---

## Power Platform

| Client ID | Application | Category |
|-----------|-------------|----------|
| `4e291c71-d680-4d0e-9640-0a3358e31177` | PowerApps | Apps |
| `3e62f81e-590b-425b-9531-cad6683656cf` | PowerApps (apps.powerapps.com) | Web |
| `a8f7a65c-f5ba-4859-b2d6-df772c264e9d` | make.powerapps.com | Maker |
| `57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0` | Microsoft Flow | Automation |
| `7ab7862c-4c57-491e-8a45-d52a7e023983` | Power Apps and Power Automate | Combined |
| `c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12` | Microsoft Power BI | Analytics |
| `7f67af8a-fedc-4b08-8b4e-37c4d127b6cf` | Power BI Desktop | Desktop |
| `b52893c8-bc2e-47fc-918b-77022b299bbc` | Power BI Data Refresh | Backend |
| `871c010f-5e61-4fb1-83ac-98610a7e9110` | Microsoft Power BI | Service |
| `a672d62c-fc7b-4e81-a576-e60dc46e951d` | Power Query for Excel | Data |
| `49676daf-ff23-4aac-adcc-55472d4e2ce0` | Power Platform API Tools | API |

---

## Intune, Endpoint, and Device Management

| Client ID | Application | Category |
|-----------|-------------|----------|
| `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223` | Intune Company Portal | MDM |
| `4c1a3aed-b389-4824-99b0-514c07906851` | Intune DeviceCheckIn | MDM |
| `163b648b-025e-455b-9937-a7f39a65d171` | SSO Extension Intune | SSO |
| `de50c81f-5f80-4771-b66b-cebd28ccdfc1` | Device Management Client | MDM |
| `7e9f2fca-0cd8-4a6c-a1a0-7ffe48aec7c6` | Intune Remote Help | Support |
| `c6e44401-4d0a-4542-ab22-ecd4c90d28d7` | App Protection | MAM |
| `61ae9cd9-7bca-458c-affc-861e2f24ba3b` | Windows Update for Business DS | Updates |
| `d5097d05-956f-4ae2-b6a2-eff25f5689b3` | WUfB Cloud Extensions PowerShell | Updates |
| `8c420feb-03df-47cc-8a05-55df0cf3064b` | Azure Update Center | Updates |

---

## Compliance, Purview, and Governance

| Client ID | Application | Category |
|-----------|-------------|----------|
| `be1918be-3fe3-4be9-b32b-b542fc27f02e` | M365 Compliance Drive Client | Compliance |
| `cedebc57-38a2-4f0a-8472-dfcbba5b04c6` | M365 Compliance Drive | Compliance |
| `fd642066-7bfc-4b65-9463-6a08841c12f0` | Microsoft Purview Platform | Purview |
| `9ec59623-ce40-4dc8-a635-ed0275b5d58a` | Purview Ecosystem | Purview |
| `73c2949e-da2d-457a-9607-fcc665198967` | Azure Purview | Purview |
| `e158eb19-34ac-4d1b-a930-ec92172f7a97` | Audit Search API Service | Audit |
| `510a5356-1745-4855-93a5-113ea589fb26` | Microsoft 365 Ticketing | Governance |

---

## Copilot and AI

| Client ID | Application | Category |
|-----------|-------------|----------|
| `8e55a7b1-6766-4f0a-8610-ecacfe3d569a` | Microsoft Teams Copilot Bot | Copilot |
| `bb5ffd56-39eb-458c-a53a-775ba21277da` | Security Copilot | Copilot |
| `fb8d773d-7ef8-4ec0-a117-179f88add510` | Enterprise Copilot Platform | Copilot |
| `c0ab8ce9-e9a0-42e7-b064-33d422df41f1` | M365 Chat Client | Copilot |
| `cb2ff863-7f30-4ced-ab89-a00194bcf6d9` | Azure AI Studio App | AI |
| `d7304df8-741f-47d3-9bc2-df0e24e2071f` | Azure ML Workbench Web | AI |
| `be5f0473-6b57-40f8-b0a9-b3054b41b99e` | AI Builder Prod | AI |

---

## Virtual Desktop and Remote

| Client ID | Application | Category |
|-----------|-------------|----------|
| `9cdead84-a844-4324-93f2-b2e6bb768d07` | Azure Virtual Desktop | AVD |
| `a85cf173-4192-42f8-81fa-777a763e6e2c` | Azure Virtual Desktop Client | AVD |
| `fa4345a4-a730-4230-84a8-7d9651b86739` | Windows Virtual Desktop Client | WVD |
| `3b511579-5e00-46e1-a89e-a6f0870e2f5a` | Windows 365 Portal | W365 |
| `0af06dc6-e4b5-4f28-818e-e78e62d137a5` | Windows 365 | W365 |

---

## MSP and Partner

| Client ID | Application | Category |
|-----------|-------------|----------|
| `2832473f-ec63-45fb-976f-5d45a7d4bb91` | Partner Customer Delegated Admin | GDAP |
| `b39d63e7-7fa3-4b2b-94ea-ee256fdb8c2f` | Partner Customer Delegated Admin Migration | GDAP |
| `34cabb34-90ae-4aca-b8c3-c457dbedf145` | Partner Center Customer Service | Partner |
| `4eaa7769-3cf1-458c-a693-e9827e39cc95` | M365 Lighthouse API | MSP |
| `d9d5c99e-b0b4-4bad-92cc-5a6eb5421985` | M365 Lighthouse Service | MSP |

---

## Productivity Apps

| Client ID | Application | Category |
|-----------|-------------|----------|
| `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office (Word, Excel, PPT) | Office |
| `66375f6b-983f-4c2c-9701-d680650f588f` | Microsoft Planner | Planning |
| `75f31797-37c9-498e-8dc9-53c16a36afca` | Microsoft Planner Client | Planning |
| `22098786-6e16-43cc-a27d-191a01a1e3b5` | Microsoft To-Do Client | Tasks |
| `57336123-6e14-4acc-8dcf-287b6088aa28` | Microsoft Whiteboard Client | Collaboration |
| `5f00fd34-f302-417f-81ef-1adda179d8fd` | Microsoft Forms Web | Forms |
| `0922ef46-e1b9-4f7e-9134-9ad00547eb41` | Loop | Notes |
| `4354e225-50c9-4423-9ece-2d5afd904870` | Augmentation Loop | Notes |
| `3ff8e6ba-7dc3-4e9e-ba40-ee12b60d6d48` | Microsoft Todo Web App | Tasks |
| `7fc21101-d09b-4343-8eb3-21187e0431a4` | Microsoft Virtual Events Services | Events |
| `392c0cd5-b73d-42f5-9e94-49904793f11c` | Microsoft Virtual Events Portal | Events |

---

## Known Malicious / Abused Applications

Apps commonly used in BEC, consent phishing, and data exfiltration.
Source: ByteIntoCyber, Mitiga ConsentFix, Push Security

| Client ID | Application | Abuse Type |
|-----------|-------------|------------|
| `ff8d92dc-3d82-41d6-bcbd-b9174d163620` | PERFECTDATA SOFTWARE | Mailbox export/backup exfil |
| `e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd` | eM Client | Email sync/exfil |
| `62db40a4-2c7e-4373-a609-eda138798962` | Edison Mail | Full mailbox sync |
| `4761b959-9780-4c2d-87a3-512b4638f767` | Rclone | M365 file management/exfil |

---

## Implicit Grant Risk — m.grdz.org

The OpenID config for m.grdz.org shows these response_types_supported:

| Response Type | Flow | Risk |
|---------------|------|------|
| `code` | Authorization Code | Safe — standard |
| `id_token` | Implicit (ID token) | Medium — token in URL fragment |
| `code id_token` | Hybrid | Medium |
| `token id_token` | Implicit (access + ID) | HIGH — access token in URL |
| `token` | Implicit (bare token) | HIGH — token in referrer/logs |

Any app with a misconfigured redirect_uri can steal tokens via implicit grant.
To check: enumerate registered apps in the tenant, look for `http://` or wildcard redirect URIs.

---

## External References

| Resource | URL |
|----------|-----|
| Secureworks FOCI CSV | https://github.com/secureworks/family-of-client-ids-research |
| merill/microsoft-info (200+ apps) | https://github.com/merill/microsoft-info |
| GraphPreConsentExplorer (378 apps) | https://github.com/zh54321/GraphPreConsentExplorer |
| entrascopes.com (interactive browser) | https://entrascopes.com/ |
| Microsoft Learn first-party verification | https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in |
| Microsoft service principal reference | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-service-principal-table |
| SpecterOps BroCI/NAA research | https://specterops.io/blog/2025/10/15/naa-or-broci-let-me-explain/ |
| Mitiga ConsentFix | https://www.mitiga.io/blog/consentfix-oauth-phishing-explained |
| Push Security ConsentFix | https://pushsecurity.com/blog/consentfix |
| Storm-2372 device code phishing | https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/ |
| Volexity Russian device code phishing | https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/ |
| Red Canary first-party SP abuse | https://redcanary.com/blog/threat-detection/entra-id-service-principals/ |
| Red Canary ROPC analysis | https://redcanary.com/blog/threat-detection/ropc-legacy-authentication/ |
| ByteIntoCyber BEC app IDs | https://byteintocyber.com/microsoft-365-application-ids-bec-investigation-resources/ |
| Beercow Azure App IDs | https://github.com/Beercow/Azure-App-IDs |
| ROADtools Token eXchange | https://github.com/dirkjanm/ROADtools |
| FOCI formal research paper (2022) | https://www.scitepress.org/PublishedPapers/2022/110612/110612.pdf |
| Dirk-jan CA Bypass research | https://dirkjanm.io/assets/raw/Finding%20Entra%20ID%20CA%20Bypasses%20-%20the%20structured%20way.pdf |
