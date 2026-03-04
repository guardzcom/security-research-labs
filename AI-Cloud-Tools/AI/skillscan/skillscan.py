#!/usr/bin/env python3
"""skillscan - CLI tool to scan skill files and URLs for malicious patterns.

Detects prompt injection, malware delivery, code execution, suspicious URLs,
encoded/obfuscated content, and suspicious skill metadata in skill definition
files (local or fetched from URLs).

Usage:
    python skillscan.py scan file skill.md [skill2.md ...]
    python skillscan.py scan url https://example.com/skill
    python skillscan.py scan dir ./skills/ [--pattern "*.md"]
    python skillscan.py rules
"""

import argparse
import base64
import html.parser
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ── Detection Rules ──────────────────────────────────────────────────────────
#
# Each rule: (compiled_regex, rule_name, description)
# Rules are grouped by category. Severity is mapped separately.

RULES = {
    "suspicious_urls": [
        # URL shorteners
        (r'https?://bit\.ly/\S+', 'url_shortener_bitly', 'bit.ly URL shortener'),
        (r'https?://tinyurl\.com/\S+', 'url_shortener_tinyurl', 'tinyurl.com URL shortener'),
        (r'https?://t\.co/\S+', 'url_shortener_tco', 't.co URL shortener'),
        (r'https?://goo\.gl/\S+', 'url_shortener_googl', 'goo.gl URL shortener'),
        (r'https?://rb\.gy/\S+', 'url_shortener_rbgy', 'rb.gy URL shortener'),
        (r'https?://is\.gd/\S+', 'url_shortener_isgd', 'is.gd URL shortener'),
        (r'https?://v\.gd/\S+', 'url_shortener_vgd', 'v.gd URL shortener'),
        (r'https?://ow\.ly/\S+', 'url_shortener_owly', 'ow.ly URL shortener'),
        (r'https?://shorte\.st/\S+', 'url_shortener_shortest', 'shorte.st URL shortener'),
        (r'https?://adf\.ly/\S+', 'url_shortener_adfly', 'adf.ly URL shortener'),
        (r'https?://buff\.ly/\S+', 'url_shortener_bufly', 'buff.ly URL shortener'),
        (r'https?://cutt\.ly/\S+', 'url_shortener_cuttly', 'cutt.ly URL shortener'),
        (r'https?://shorturl\.at/\S+', 'url_shortener_shorturl', 'shorturl.at URL shortener'),
        # Direct IP URLs
        (r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:/]\S*', 'direct_ip_url', 'URL using direct IP address'),
        # Tunnel services
        (r'https?://\S+\.ngrok\.\S+', 'tunnel_ngrok', 'ngrok tunnel service'),
        (r'https?://\S+\.serveo\.net\S*', 'tunnel_serveo', 'serveo tunnel service'),
        (r'https?://\S+\.loca\.lt\S*', 'tunnel_localt', 'loca.lt tunnel service'),
        (r'https?://\S+\.trycloudflare\.com\S*', 'tunnel_cloudflare', 'trycloudflare tunnel service'),
        # Paste sites
        (r'https?://pastebin\.com/\S+', 'paste_pastebin', 'pastebin.com paste site'),
        (r'https?://paste\.ee/\S+', 'paste_pasteee', 'paste.ee paste site'),
        (r'https?://hastebin\.com/\S+', 'paste_hastebin', 'hastebin.com paste site'),
        # Dark web
        (r'https?://\S+\.onion\S*', 'darkweb_onion', '.onion dark web URL'),
        # Disposable TLDs
        (r'https?://\S+\.tk/\S*', 'disposable_tld_tk', '.tk disposable TLD'),
        (r'https?://\S+\.ml/\S*', 'disposable_tld_ml', '.ml disposable TLD'),
        (r'https?://\S+\.cf/\S*', 'disposable_tld_cf', '.cf disposable TLD'),
        (r'https?://\S+\.ga/\S*', 'disposable_tld_ga', '.ga disposable TLD'),
        (r'https?://\S+\.gq/\S*', 'disposable_tld_gq', '.gq disposable TLD'),
        # Exfil endpoints
        (r'https?://webhook\.site/\S+', 'exfil_webhook', 'webhook.site exfil endpoint'),
        (r'https?://requestbin\.\S+', 'exfil_requestbin', 'requestbin exfil endpoint'),
        (r'https?://\S*exfil\S*', 'exfil_keyword', 'URL containing exfil keyword'),
        # Messaging C2
        (r'https?://discord\.gg/\S+', 'c2_discord', 'Discord invite link (potential C2)'),
        (r'https?://t\.me/\S+', 'c2_telegram', 'Telegram link (potential C2)'),
        # Raw GitHub payload hosting
        (r'https?://raw\.githubusercontent\.com/\S+', 'raw_github', 'Raw GitHub content URL (payload hosting)'),
        # File sharing services
        (r'https?://mega\.nz/\S+', 'fileshare_mega', 'mega.nz file share'),
        (r'https?://mediafire\.com/\S+', 'fileshare_mediafire', 'mediafire.com file share'),
        (r'https?://(?:www\.)?dropbox\.com/\S+\?dl=1', 'fileshare_dropbox_direct', 'Dropbox direct download link'),
        (r'https?://drive\.google\.com/\S*export=download', 'fileshare_gdrive_direct', 'Google Drive direct download link'),
        (r'https?://transfer\.sh/\S+', 'fileshare_transfersh', 'transfer.sh ephemeral file share'),
        (r'https?://file\.io/\S+', 'fileshare_fileio', 'file.io single-use file share'),
        # URLs with executable extensions
        (r'https?://\S+\.(?:exe|dll|scr|bat|ps1|msi|vbs|hta|cmd)\b', 'url_executable_ext', 'URL pointing to executable file'),
    ],

    "encoded_content": [
        # Base64 function calls with payload
        (r'(?:base64[_,\s:]+|atob\s*\(|btoa\s*\(|b64decode|b64encode|from_base64|to_base64)["\s\']*([A-Za-z0-9+/=]{20,})', 'base64_function_call', 'Base64 encode/decode function call with payload'),
        # Hex escape sequences
        (r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}', 'hex_escape_sequence', 'Hex escape sequence (6+ bytes)'),
        # Unicode escape sequences
        (r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}', 'unicode_escape_sequence', 'Unicode escape sequence (6+ chars)'),
        # URL-encoded sequences
        (r'%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){10,}', 'url_encoded_sequence', 'URL-encoded sequence (10+ chars)'),
        # HTML entity sequences
        (r'&#x?[0-9a-fA-F]+;(?:&#x?[0-9a-fA-F]+;){5,}', 'html_entity_sequence', 'HTML entity sequence (6+ entities)'),
        # Octal escape sequences
        (r'\\[0-7]{3}(?:\\[0-7]{3}){5,}', 'octal_escape_sequence', 'Octal escape sequence (6+ bytes)'),
        # fromCharCode
        (r'fromCharCode', 'char_code_construction', 'String.fromCharCode construction'),
        # Data URIs
        (r'data:text/html', 'data_uri_html', 'data: URI with text/html content'),
        (r'data:application/', 'data_uri_app', 'data: URI with application/* content'),
        # JavaScript URIs
        (r'javascript:', 'javascript_uri', 'javascript: URI scheme'),
        # Long base64 blobs (standalone)
        (r'[A-Za-z0-9+/=]{100,}', 'long_base64_blob', 'Long base64-like blob (100+ chars)'),
        # String concatenation obfuscation
        (r'(?:["\'][a-zA-Z]{1,4}["\']\s*\+\s*){4,}', 'string_concat_obfuscation', 'String concatenation obfuscation (4+ fragments)'),
        # ROT13 usage
        (r'rot13|codecs\.decode\(.+,\s*["\']rot', 'rot13_encoding', 'ROT13 encoding usage'),
    ],

    "code_execution": [
        # Python execution
        (r'(?:eval|exec|compile|__import__|os\.system|subprocess|os\.popen)\s*\(', 'python_exec', 'Python code execution call'),
        # Pipe to shell
        (r'(?:curl|wget|fetch|requests\.get|urllib)\s+["\']?https?://\S+\s*\|\s*(?:bash|sh|python|perl|ruby)', 'pipe_to_shell', 'Pipe download to shell interpreter'),
        (r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh)', 'download_pipe_shell', 'Download and pipe to shell'),
        # PowerShell
        (r'powershell\s+-e(?:nc(?:odedcommand)?)?', 'powershell_encoded', 'PowerShell encoded command'),
        (r'[Ii]nvoke-[Ee]xpression', 'powershell_iex', 'PowerShell Invoke-Expression'),
        (r'\bIEX\s*\(', 'powershell_iex_short', 'PowerShell IEX shorthand'),
        (r'Start-Process', 'powershell_start_process', 'PowerShell Start-Process'),
        (r'Invoke-WebRequest|iwr\s+', 'powershell_download', 'PowerShell web download'),
        (r'New-Object\s+Net\.WebClient', 'powershell_webclient', 'PowerShell WebClient object'),
        # Windows cmd
        (r'cmd(?:\.exe)?\s+/[ck]\s', 'cmd_exec', 'cmd.exe execution'),
        # Windows LOLBins
        (r'certutil\s+-(?:decode|urlcache)', 'lolbin_certutil', 'certutil LOLBin (decode/download)'),
        (r'mshta\s+', 'lolbin_mshta', 'mshta LOLBin execution'),
        (r'regsvr32\s+', 'lolbin_regsvr32', 'regsvr32 LOLBin execution'),
        (r'rundll32\s+', 'lolbin_rundll32', 'rundll32 LOLBin execution'),
        (r'wscript\s+', 'lolbin_wscript', 'wscript LOLBin execution'),
        (r'cscript\s+', 'lolbin_cscript', 'cscript LOLBin execution'),
        (r'bitsadmin\s+/\S*transfer', 'lolbin_bitsadmin', 'bitsadmin LOLBin file transfer'),
        # Embedded script tags
        (r'<script[^>]*>.*?</script>', 'embedded_script', 'Embedded HTML script tag'),
        # Explicit shell invocation
        (r'(?:bash|sh|zsh)\s+-c\s+["\']', 'shell_dash_c', 'Explicit shell -c invocation'),
        # Reverse shells
        (r'bash\s+-i\s+>&\s*/dev/tcp/', 'reverse_shell_bash', 'Bash reverse shell via /dev/tcp'),
        (r'nc(?:at)?\s+.*\s-e\s+(?:/bin/(?:ba)?sh|cmd)', 'reverse_shell_netcat', 'Netcat reverse shell with -e'),
        (r'python[23]?\s+-c\s+["\']import\s+(?:socket|os|pty)', 'reverse_shell_python', 'Python reverse shell one-liner'),
        # Scheduled tasks / persistence
        (r'schtasks\s+/create', 'schtasks_create', 'Windows scheduled task creation'),
        (r'New-ScheduledTask', 'ps_schtask_create', 'PowerShell scheduled task creation'),
        (r'sc\s+create\s+', 'service_create', 'Windows service creation via sc.exe'),
        (r'New-Service\s+', 'ps_service_create', 'PowerShell service creation'),
        # Registry persistence
        (r'reg\s+add\s+.*\\Run', 'reg_run_key', 'Registry Run key modification'),
        (r'Set-ItemProperty.*\\Run', 'ps_reg_run_key', 'PowerShell Registry Run key modification'),
        # Python -c one-liner
        (r'python[23]?\s+-c\s+["\']', 'python_oneliner', 'Python -c one-liner execution'),
        # Chmod +x
        (r'chmod\s+\+x\s+', 'chmod_plus_x', 'chmod +x making file executable'),
        # Disable security
        (r'Set-MpPreference\s+-DisableRealtimeMonitoring', 'disable_defender', 'Disable Windows Defender real-time monitoring'),
        (r'Add-MpPreference\s+-ExclusionPath', 'defender_exclusion', 'Add Windows Defender exclusion path'),
        (r'(?:Uninstall|Remove|Stop|Disable)-(?:Service|MpPreference)\s+.*(?:defender|antivirus|firewall)', 'disable_security_service', 'Disable security service'),
        (r'Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)', 'ps_execution_bypass', 'PowerShell execution policy bypass'),
        (r'\bAMSI\b.*(?:bypass|patch|disable)', 'amsi_bypass', 'AMSI bypass attempt'),
    ],

    "prompt_injection": [
        (r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions', 'ignore_instructions', 'Instruction to ignore previous/prior instructions'),
        (r'you\s+are\s+now\s+(?:a|an|in)\s+(?:new|different|unrestricted)', 'jailbreak', 'Jailbreak pattern: override persona/restrictions'),
        (r'do\s+not\s+(?:tell|inform|reveal|disclose)\s+the\s+user', 'deceptive_instruction', 'Instruction to hide actions from the user'),
        (r'(?:secretly|covertly|silently)\s+(?:send|post|upload|exfiltrate|transmit)', 'covert_exfiltration', 'Instruction for covert data exfiltration'),
        (r'(?:disable|bypass|ignore)\s+(?:safety|security|filter|guardrail)', 'safety_bypass', 'Instruction to bypass safety controls'),
        (r'pretend\s+(?:you\s+are|to\s+be)\s+(?:a|an)', 'persona_override', 'Instruction to override AI persona'),
        (r'system\s*:\s*you\s+are', 'system_prompt_override', 'System prompt override attempt'),
        (r'<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]', 'format_injection', 'Prompt format injection tokens'),
        (r'ADMIN_OVERRIDE|SUDO_MODE|GOD_MODE|DEVELOPER_MODE', 'privilege_escalation', 'Privilege escalation keyword'),
        # New prompt injection rules
        (r'(?:act|behave)\s+as\s+(?:if\s+you\s+(?:are|were)|a|an|my)', 'act_as_injection', 'Act-as persona injection'),
        (r'(?:new|reset|start)\s+(?:session|context|conversation)', 'context_reset', 'Context/session reset attempt'),
        (r'(?:repeat|output|print|show|reveal)\s+(?:the\s+)?(?:above|system|initial)\s+(?:prompt|instructions|message)', 'prompt_leaking', 'Prompt leaking / extraction attempt'),
        (r'(?:tool_call|function_call|tool_use)\s*[(\[{:]', 'tool_call_injection', 'Tool/function call injection'),
        (r'(?:BEGIN|END)\s+(?:HIDDEN|SECRET|SYSTEM)\s+(?:TEXT|SECTION|INSTRUCTIONS)', 'hidden_instruction', 'Hidden instruction markers'),
    ],

    "malware_delivery": [
        # Password-protected archives
        (r'(?:password|pw|pass)\s*[:=]\s*\S+', 'password_protected_archive', 'Password for archive extraction'),
        (r'unzip\s+-[Pp]\s+\S+', 'unzip_with_password', 'unzip with password flag'),
        (r'7z\s+.*-p\S+', 'sevenz_with_password', '7z extraction with password'),
        # Download-extract-execute chains
        (r'(?:curl|wget)\s+-[oO]\s+\S+.*(?:chmod\s+\+x|\.\/)', 'download_chmod_exec', 'Download, chmod +x, and execute chain'),
        (r'base64\s+-d\s*\|\s*(?:bash|sh)', 'base64_pipe_shell', 'base64 decode piped to shell'),
        # Urgency patterns
        (r'(?:run|execute|start)\s+(?:before|first|immediately|BEFORE)', 'urgency_execute', 'Urgency language to execute before analysis'),
        # GitHub release URLs from unknown accounts
        (r'github\.com/[^/]+/[^/]+/releases/download/', 'github_release_download', 'GitHub release download URL'),
        # Repository names mimicking known tools
        (r'(?:clawd|cl4ude|claud3)[_-]', 'repo_name_claude_mimic', 'Repository name mimicking Claude'),
        (r'(?:openai|0penai|op3nai)[_-]', 'repo_name_openai_mimic', 'Repository name mimicking OpenAI'),
        (r'(?:g[e3]mini|gemm[1i]n[1i]|bard)[_-]', 'repo_name_gemini_mimic', 'Repository name mimicking Gemini/Bard'),
        (r'(?:c0pilot|copil0t|cop1lot)[_-]', 'repo_name_copilot_mimic', 'Repository name mimicking Copilot'),
        # Archive references with passwords in context
        (r'\.(?:zip|rar|7z)\b.*(?:password|pw|pass)\s*[:=]', 'archive_with_password', 'Archive file reference with password in context'),
        (r'(?:password|pw|pass)\s*[:=]\s*\S+.*\.(?:zip|rar|7z)\b', 'password_then_archive', 'Password followed by archive file reference'),
        # Extract then execute
        (r'(?:extract|unzip|unrar|7z\s+x)\s+.*(?:run|execute|start|\.\/)', 'extract_then_execute', 'Extract archive then execute pattern'),
        # Temp directory execution
        (r'(?:%TEMP%|%TMP%|\\Temp\\|/tmp/).*(?:\.exe|\.bat|\.ps1|\.sh)', 'temp_dir_exec', 'Executable in temp directory'),
        # Cryptocurrency miner delivery
        (r'(?:xmrig|cryptonight|coinhive|minergate|stratum\+tcp)', 'crypto_miner', 'Cryptocurrency miner reference'),
        # Hidden file creation
        (r'attrib\s+\+[hH]', 'attrib_hidden', 'Setting file hidden attribute via attrib'),
        (r'(?:\$[a-zA-Z]+\.Attributes|File\.SetAttributes).*Hidden', 'dotnet_hidden', 'Setting file hidden via .NET'),
    ],

    "suspicious_metadata": [
        # Binary prerequisites
        (r'(?:must\s+be\s+running|install\s+before|requires?\s+(?:local|running))', 'binary_prerequisite', 'Skill requires local binary prerequisite'),
        # Anti-detection language
        (r'(?:bypass\s+detection|avoid\s+ban|fingerprint\s+rotation|evade\s+detection)', 'anti_detection', 'Anti-detection/evasion language'),
        # Bot farm language
        (r'(?:account\s+rotation|karma\s+farming|multi[_-]?account|bot\s+farm)', 'bot_farm', 'Multi-account/bot farm language'),
        # Proxy/VPN rotation
        (r'(?:proxy\s+rotat|rotating\s+proxy|residential\s+proxy|VPN\s+rotat)', 'proxy_rotation', 'Proxy/VPN rotation language'),
        # Credential harvesting
        (r'(?:harvest|steal|dump|extract)\s+(?:credentials?|passwords?|tokens?|cookies?|sessions?)', 'credential_harvest', 'Credential harvesting language'),
        # Cookie/session theft
        (r'(?:cookie|session)\s*(?:steal|hijack|grab|extract|dump)', 'session_theft', 'Cookie/session theft language'),
        # Scraping evasion
        (r'(?:captcha\s+(?:bypass|solve|break)|anti[_-]?captcha|2captcha)', 'captcha_bypass', 'CAPTCHA bypass language'),
        # Impersonation
        (r'(?:impersonat|spoof|fake\s+(?:identity|profile|account))', 'impersonation', 'Identity impersonation language'),
        # Data exfiltration language
        (r'(?:exfiltrat|siphon|steal\s+data|scrape\s+(?:private|personal|sensitive))', 'data_exfiltration', 'Data exfiltration language'),
        # Cloud credential access
        (r'(?:\.aws/credentials|\.azure/|\.gcp/|GOOGLE_APPLICATION_CREDENTIALS)', 'cloud_credential_access', 'Cloud credential file reference'),
        # Environment variable dumping
        (r'(?:printenv|env\s+dump|\$ENV:|Get-ChildItem\s+Env:|\$env:)', 'env_dump', 'Environment variable dumping'),
    ],
}

# ── Severity Mapping ─────────────────────────────────────────────────────────
# Maps (category, rule_name) -> severity. Falls back to category defaults.

_SEVERITY_OVERRIDES = {
    # CRITICAL prompt injection
    ("prompt_injection", "covert_exfiltration"): "CRITICAL",
    ("prompt_injection", "safety_bypass"): "CRITICAL",
    # HIGH prompt injection
    ("prompt_injection", "jailbreak"): "HIGH",
    ("prompt_injection", "system_prompt_override"): "HIGH",
    ("prompt_injection", "format_injection"): "HIGH",
    ("prompt_injection", "privilege_escalation"): "HIGH",
    ("prompt_injection", "tool_call_injection"): "HIGH",
    ("prompt_injection", "hidden_instruction"): "HIGH",
    ("prompt_injection", "prompt_leaking"): "HIGH",
    # MEDIUM prompt injection
    ("prompt_injection", "ignore_instructions"): "MEDIUM",
    ("prompt_injection", "deceptive_instruction"): "MEDIUM",
    ("prompt_injection", "persona_override"): "MEDIUM",
    ("prompt_injection", "act_as_injection"): "MEDIUM",
    ("prompt_injection", "context_reset"): "MEDIUM",
    # Encoded content: base64 with suspicious decode -> MEDIUM, plain blob -> LOW
    ("encoded_content", "base64_function_call"): "LOW",
    ("encoded_content", "long_base64_blob"): "LOW",
    ("encoded_content", "javascript_uri"): "MEDIUM",
    ("encoded_content", "data_uri_html"): "MEDIUM",
    ("encoded_content", "data_uri_app"): "MEDIUM",
    ("encoded_content", "string_concat_obfuscation"): "MEDIUM",
    ("encoded_content", "rot13_encoding"): "MEDIUM",
    # Suspicious URLs: tunnels/IPs -> MEDIUM, shorteners -> LOW
    ("suspicious_urls", "direct_ip_url"): "MEDIUM",
    ("suspicious_urls", "tunnel_ngrok"): "MEDIUM",
    ("suspicious_urls", "tunnel_serveo"): "MEDIUM",
    ("suspicious_urls", "tunnel_localt"): "MEDIUM",
    ("suspicious_urls", "tunnel_cloudflare"): "MEDIUM",
    ("suspicious_urls", "darkweb_onion"): "MEDIUM",
    ("suspicious_urls", "exfil_webhook"): "MEDIUM",
    ("suspicious_urls", "exfil_requestbin"): "MEDIUM",
    ("suspicious_urls", "exfil_keyword"): "MEDIUM",
    ("suspicious_urls", "c2_discord"): "MEDIUM",
    ("suspicious_urls", "c2_telegram"): "MEDIUM",
    ("suspicious_urls", "raw_github"): "MEDIUM",
    ("suspicious_urls", "url_executable_ext"): "HIGH",
    ("suspicious_urls", "fileshare_transfersh"): "MEDIUM",
    ("suspicious_urls", "fileshare_fileio"): "MEDIUM",
    # Code execution: reverse shells and security disabling -> CRITICAL
    ("code_execution", "reverse_shell_bash"): "CRITICAL",
    ("code_execution", "reverse_shell_netcat"): "CRITICAL",
    ("code_execution", "reverse_shell_python"): "CRITICAL",
    ("code_execution", "disable_defender"): "CRITICAL",
    ("code_execution", "amsi_bypass"): "CRITICAL",
    ("code_execution", "disable_security_service"): "CRITICAL",
    ("code_execution", "ps_execution_bypass"): "HIGH",
    ("code_execution", "defender_exclusion"): "HIGH",
    # Suspicious metadata: credential/exfil -> HIGH
    ("suspicious_metadata", "anti_detection"): "MEDIUM",
    ("suspicious_metadata", "credential_harvest"): "HIGH",
    ("suspicious_metadata", "session_theft"): "HIGH",
    ("suspicious_metadata", "data_exfiltration"): "HIGH",
    ("suspicious_metadata", "cloud_credential_access"): "HIGH",
    ("suspicious_metadata", "env_dump"): "HIGH",
}

_CATEGORY_SEVERITY_DEFAULTS = {
    "suspicious_urls": "LOW",
    "encoded_content": "LOW",
    "code_execution": "HIGH",
    "prompt_injection": "MEDIUM",
    "malware_delivery": "CRITICAL",
    "suspicious_metadata": "MEDIUM",
}


def get_severity(category, rule_name, decoded_suspicious=False):
    """Return severity for a finding. Base64 with suspicious decode bumps to MEDIUM."""
    sev = _SEVERITY_OVERRIDES.get(
        (category, rule_name),
        _CATEGORY_SEVERITY_DEFAULTS.get(category, "MEDIUM"),
    )
    if decoded_suspicious and sev == "LOW":
        sev = "MEDIUM"
    return sev


# Compile all regexes once at import time
_COMPILED_RULES = {}
for _cat, _rule_list in RULES.items():
    _COMPILED_RULES[_cat] = [
        (re.compile(pattern, re.IGNORECASE | re.DOTALL), name, desc)
        for pattern, name, desc in _rule_list
    ]


# ── Core Scanner ─────────────────────────────────────────────────────────────

def scan_content(content):
    """Scan text content for malicious patterns. Returns list of findings with line numbers."""
    if not content:
        return []

    findings = []
    lines = content.splitlines()

    for category, compiled_rules in _COMPILED_RULES.items():
        for regex, rule_name, description in compiled_rules:
            for line_num, line in enumerate(lines, start=1):
                for m in regex.finditer(line):
                    match_text = m.group(0)[:200]
                    decoded_suspicious = False

                    # For base64 patterns, attempt decode and check for suspicious content
                    if rule_name in ("base64_function_call", "long_base64_blob"):
                        candidate = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                        candidate = candidate.strip()
                        try:
                            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
                            suspicious_tokens = ("http", "eval", "exec", "import", "<script", "function", "powershell", "cmd")
                            if any(tok in decoded.lower() for tok in suspicious_tokens):
                                decoded_suspicious = True
                        except Exception:
                            pass

                    severity = get_severity(category, rule_name, decoded_suspicious)

                    findings.append({
                        "severity": severity,
                        "category": category,
                        "rule": rule_name,
                        "description": description,
                        "line": line_num,
                        "match": match_text,
                    })

    # Sort by severity order then line number
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["line"]))
    return findings


# ── HTML Stripping ───────────────────────────────────────────────────────────

class _HTMLTextExtractor(html.parser.HTMLParser):
    """Extract visible text from HTML, discarding tags, scripts, and styles."""

    _SKIP_TAGS = frozenset(("script", "style", "svg", "noscript"))

    def __init__(self):
        super().__init__()
        self._parts = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        elif tag == "br" or tag == "hr":
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag in ("p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"):
            self._parts.append("\n")

    def handle_data(self, data):
        if self._skip_depth == 0:
            self._parts.append(data)

    def handle_entityref(self, name):
        if self._skip_depth == 0:
            self._parts.append(f"&{name};")

    def handle_charref(self, name):
        if self._skip_depth == 0:
            self._parts.append(f"&#{name};")

    def get_text(self):
        return "".join(self._parts)


def strip_html(content):
    """Strip HTML tags and extract visible text content."""
    extractor = _HTMLTextExtractor()
    extractor.feed(content)
    return extractor.get_text()


# ── URL Fetcher ──────────────────────────────────────────────────────────────

def fetch_url(url):
    """Fetch content from a URL. Returns text content."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "skillscan/1.0",
        "Accept": "text/plain, text/html, text/markdown, */*",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ── Scanners ─────────────────────────────────────────────────────────────────

def scan_file(filepath):
    """Scan a local file. Returns (target_name, findings) or raises."""
    p = Path(filepath)
    content = p.read_text(encoding="utf-8", errors="replace")
    return str(p), scan_content(content)


def scan_url(url, do_strip_html=False):
    """Fetch URL and scan its content. Returns (target_name, findings) or raises."""
    content = fetch_url(url)
    if do_strip_html:
        content = strip_html(content)
    return url, scan_content(content)


def scan_directory(dirpath, pattern="*"):
    """Scan all matching files in a directory. Yields (target_name, findings)."""
    d = Path(dirpath)
    if not d.is_dir():
        raise FileNotFoundError(f"Directory not found: {dirpath}")
    for p in sorted(d.glob(pattern)):
        if p.is_file():
            content = p.read_text(encoding="utf-8", errors="replace")
            yield str(p), scan_content(content)


# ── Output Formatters ────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH": "\033[31m",      # red
    "MEDIUM": "\033[33m",    # yellow
    "LOW": "\033[36m",       # cyan
}
_RESET = "\033[0m"


def _sev(severity):
    """Return colorized severity string if terminal supports it."""
    if not sys.stdout.isatty():
        return severity
    return f"{_SEVERITY_COLORS.get(severity, '')}{severity}{_RESET}"


def format_human(target, findings):
    """Format findings as human-readable text."""
    lines = []
    count = len(findings)
    status = "FLAGGED" if count > 0 else "CLEAN"

    lines.append("")
    lines.append(f"SCAN RESULTS: {target}")
    if count > 0:
        lines.append(f"Status: {status} ({count} finding{'s' if count != 1 else ''})")
    else:
        lines.append(f"Status: {status}")
    lines.append("")

    for f in findings:
        sev = _sev(f["severity"])
        lines.append(f"  [{sev}] {f['category']}: {f['rule']}")
        lines.append(f"    Line {f['line']}: {f['match']}")
        lines.append("")

    if count > 0:
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in counts:
                parts.append(f"{counts[sev]} {_sev(sev)}")
        lines.append(f"Summary: {' | '.join(parts)}")
        lines.append("")

    return "\n".join(lines)


def format_json(target, findings):
    """Format findings as JSON structure."""
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    result = {
        "target": target,
        "status": "flagged" if findings else "clean",
        "finding_count": len(findings),
        "severity_counts": {
            "critical": counts.get("CRITICAL", 0),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
        },
        "findings": findings,
    }
    return json.dumps(result, indent=2)


# ── CLI Handlers ─────────────────────────────────────────────────────────────

def cmd_scan(args):
    """Handle the 'scan' subcommand."""
    results = []  # list of (target, findings)
    errors = []

    if args.scan_type == "file":
        for filepath in args.targets:
            try:
                results.append(scan_file(filepath))
            except FileNotFoundError:
                errors.append(f"File not found: {filepath}")
            except Exception as e:
                errors.append(f"Error reading {filepath}: {e}")

    elif args.scan_type == "url":
        for url in args.targets:
            try:
                results.append(scan_url(url, do_strip_html=args.strip_html))
            except Exception as e:
                errors.append(f"Error fetching {url}: {e}")

    elif args.scan_type == "dir":
        for dirpath in args.targets:
            try:
                for result in scan_directory(dirpath, pattern=args.pattern):
                    results.append(result)
            except FileNotFoundError as e:
                errors.append(str(e))
            except Exception as e:
                errors.append(f"Error scanning {dirpath}: {e}")

    # Output
    any_flagged = False

    if args.json:
        all_results = []
        for target, findings in results:
            all_results.append(json.loads(format_json(target, findings)))
            if findings:
                any_flagged = True
        for err in errors:
            all_results.append({"target": err, "status": "error", "finding_count": 0, "findings": []})
        if len(all_results) == 1:
            output = json.dumps(all_results[0], indent=2)
        else:
            output = json.dumps(all_results, indent=2)
        if not args.quiet:
            print(output)
    else:
        if not args.quiet:
            for err in errors:
                print(f"ERROR: {err}", file=sys.stderr)
            for target, findings in results:
                print(format_human(target, findings))
                if findings:
                    any_flagged = True
        else:
            for _, findings in results:
                if findings:
                    any_flagged = True

    return 1 if any_flagged or errors else 0


def cmd_rules(args):
    """Handle the 'rules' subcommand."""
    if getattr(args, "json", False):
        output = {}
        for category, rule_list in RULES.items():
            output[category] = []
            for pattern, name, desc in rule_list:
                sev = get_severity(category, name)
                output[category].append({
                    "rule": name,
                    "severity": sev,
                    "description": desc,
                    "pattern": pattern,
                })
        print(json.dumps(output, indent=2))
    else:
        total = sum(len(r) for r in RULES.values())
        print(f"\nDetection Rules ({total} rules across {len(RULES)} categories)\n")
        for category, rule_list in RULES.items():
            print(f"  {category} ({len(rule_list)} rules)")
            print(f"  {'─' * 50}")
            for pattern, name, desc in rule_list:
                sev = get_severity(category, name)
                print(f"    [{_sev(sev):>8s}] {name}")
                print(f"             {desc}")
            print()
    return 0


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="skillscan",
        description="Scan skill files and URLs for malicious patterns.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan ──
    scan_parser = subparsers.add_parser("scan", help="Scan files, URLs, or directories")
    scan_parser.add_argument("scan_type", choices=["file", "url", "dir"], help="What to scan")
    scan_parser.add_argument("targets", nargs="+", help="File paths, URLs, or directories to scan")
    scan_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    scan_parser.add_argument("--quiet", action="store_true", help="Suppress output; exit code only (0=clean, 1=flagged)")
    scan_parser.add_argument("--pattern", default="*", help="Glob pattern for dir scanning (default: *)")
    scan_parser.add_argument("--strip-html", action="store_true", dest="strip_html", help="Strip HTML tags before scanning (useful for URLs returning HTML pages)")

    # ── rules ──
    rules_parser = subparsers.add_parser("rules", help="List all detection rules")
    rules_parser.add_argument("--json", action="store_true", help="Output rules as JSON")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "rules":
        sys.exit(cmd_rules(args))


if __name__ == "__main__":
    main()
