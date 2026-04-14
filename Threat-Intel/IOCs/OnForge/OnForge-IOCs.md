# on-forge.com Tech Support Scam Campaign - IOC Blocklist
# Generated: 2026-04-14
# Source: SentinelOne DV 
# Total: 96+ domains, 18+ phones, 4 IPs, 2 Tawk.to accounts

Important Note: All domains are under the on-forge.com, but include a specific Variant.

# ============================================================
# DOMAINS - Wildcard Block (Recommended)
# ============================================================

*.on-forge.com

# ============================================================
# DOMAINS - Confirmed Scam Subdomains 
# ============================================================

ikdnknskfjnsnflsjnfljsdlsjd-uynmyovf.on-forge.com
kjhgfdfghjklkjfj.on-forge.com

# ============================================================
# DOMAINS - Confirmed Scam Subdomains (Variant A: ph0ne=)
# ============================================================

kasdjfkasjd8uawkjnmzmnvmdsfhj27jajak03.on-forge.com
gbukukkaksdjfkasj32amsfn004.on-forge.com
2500007askdjfakieuri.on-forge.com

# ============================================================
# DOMAINS - Confirmed Scam Subdomains (Variant B: Anph=)
# ============================================================

nbvcxcghjmmn.on-forge.com
ruyinity65.on-forge.com
gityuiuyt66.on-forge.com

# ============================================================
# DOMAINS - Confirmed Scam Subdomains (Variant C: bcda=)
# ============================================================

usa-monday-admin-4wq5elwf.on-forge.com
usa-monday-admin-yph9gxfv.on-forge.com
usa-monday-admin-pkycwfol.on-forge.com

# ============================================================
# DOMAINS - Confirmed Scam Subdomains (Variant D: Kuph=)
# ============================================================
exorepusvir-osgfaw8g.on-forge.com

# ============================================================
# DOMAINS - Dead/Torn Down (522, former scam pages)
# ============================================================

nvcvbnnvghvbj.on-forge.com
alkjkdkkdkdk.on-forge.com
sdfghhgfjhgg.on-forge.com

# ============================================================
# DOMAINS - Keyboard Mash + Forge Hash (Type B)
# ============================================================

blajdlajndlakjdlajdla-gpw2vpji.on-forge.com
alkjfnsdnladjlakdl-csftsnyu.on-forge.com
nope-gsf1crvr.on-forge.com

# ============================================================
# DOMAINS - Other Scam Campaigns on Same Infrastructure
# ============================================================

nequi-allianze-tramites.on-forge.com
nequi.on-forge.com
kiuuutiiiiiii.on-forge.com

# ============================================================
# DOMAINS - Redirect Entry Points
# ============================================================

segurosn.lat
dhjanask.online - https://www.virustotal.com/gui/domain/dhjanask.online/details

# ============================================================
# IPs
# ============================================================

104.18.10.251
104.18.11.251
15.204.43.250
104.45.153.136

# ============================================================
# PHONE NUMBERS - UK Freephone
# ============================================================

08085310436
08081752331
08085012937
08000884533
08009124035
08000884932

# ============================================================
# PHONE NUMBERS - US Toll Free
# ============================================================

18339261805
18339261999
18339262479
18339262512
18339262514
8668094446
8668094664
5743695969

# ============================================================
# TAWK.TO SCAMMER ACCOUNTS
# ============================================================

69cd421fb8aa781c3b30ed16
68d549cbc6b9a0194dd28338

# ============================================================
# FILE HASHES - SHA256 (Scam Page)
# ============================================================

  SHA256: 298deae4484ebe1f2cf64669197a880d08f1c25852317d16e0feb9880a7b83fb
  File: custom.js
  Type: JavaScript
  Purpose: Scam engine: fullscreen hijack, keyboard lock, audio trap
  ────────────────────────────────────────
  SHA256: e5a7faad39c23549b61051a5e50dc7d1a8bc63411b825619d1301334529687c2
  File: index.html
  Type: HTML
  Purpose: Main scam page: fake Microsoft Security alert, phone injection
  ────────────────────────────────────────
  SHA256: 915cbddff7dab2554948e6cd382450219f0e71c7a9facb1f4f362d37a1cf880d
  File: bg.png
  Type: PNG
  Purpose: Explicit adult content (scareware shock image)
  ────────────────────────────────────────
  SHA256: 948b1331677d0f9991d50376bfba436033c5a9cc5919cf9f74c03424b6f3e342
  File: back.jpg
  Type: JPEG
  Purpose: Fake Microsoft Support page screenshot
  ────────────────────────────────────────
  SHA256: 7497f3d08e577650f4a8f8e835c9cb8369f84693385530733c4269e2636bd997
  File: custom.css
  Type: CSS
  Purpose: Hidden cursor, pulsing animation, fullscreen overlay styling
  ────────────────────────────────────────
  SHA256: 316e6a6737bd296ab30aca2ef7fa36f119d15786a2432d01e31fdc130272f15c
  File: defend.png
  Type: PNG
  Purpose: Windows Defender shield icon
  ────────────────────────────────────────
  SHA256: ee4bc5fe81fa7c1e8497d79c9c8a96485df217092d334e9b48fa8840fed11d03
  File: ms.png
  Type: PNG
  Purpose: Microsoft four square logo
  ────────────────────────────────────────
  SHA256: 3b531d403dc8ce7cbb0efb1a0c307cfb2bbaaf21feaff9f3546f13bebda71887
  File: v.jpg
  Type: JPEG
  Purpose: Two laptop icons with a shield (scan illustration)
  ────────────────────────────────────────
  SHA256: 3821ef20f5904fdb993e34d87ff8fb9c5786a382efb0eeee8b4f00c91428b701
  File: x.png
  Type: PNG
  Purpose: Warning/close icon
  ────────────────────────────────────────
  SHA256: 0589be7715d2320e559eae6bd26f3528e97450c70293da2e1e8ce45f77f99ab1
  File: beep1.mp3
  Type: MP3
  Purpose: Alarm beep sound (loops infinitely)

# ============================================================
# FILE HASHES - SHA1 (ScreenConnect Binaries from S1)
# ============================================================

Will be available soon

# ============================================================
# URL PATTERNS - Query Parameter Blocks
# ============================================================

ph0ne=
Anph=
bcda=
Kuph=

# ============================================================
# URL DETECTION REGEX
# ============================================================
# Broad: any on-forge.com with phone parameter
# https?://[a-z0-9\-]{5,60}\.on-forge\.com/.+\?(ph0ne|Anph|bcda|Kuph)=
#
# Type B subdomains (keyboard mash + Forge hash)
# [a-z]{15,30}-[a-z0-9]{8}\.on-forge\.com
#
# Type C subdomains (usa-monday-admin)
# usa-monday-admin-[a-z0-9]{8}\.on-forge\.com
