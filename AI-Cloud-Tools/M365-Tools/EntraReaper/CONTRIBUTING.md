# Contributing to EntraReaper

Thank you for your interest in improving EntraReaper. This guide covers how to add new tools, scenarios, kill chains, and general contribution guidelines.

---

## Table of Contents

- [Adding a New MCP Tool](#adding-a-new-mcp-tool)
- [Adding a New Scenario](#adding-a-new-scenario)
- [Adding a New Kill Chain](#adding-a-new-kill-chain)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)

---

## Adding a New MCP Tool

### 1. Define the tool in `server.py`

Add a new function decorated with `@mcp.tool()`:

```python
@mcp.tool()
async def recon_new_capability(
    domain: str,
    token_alias: str = "",
    save: bool = True,
) -> str:
    """
    One-line description of what the tool does.

    Detailed explanation including:
    - What AADInternals cmdlet(s) it wraps
    - What data it returns
    - OPSEC considerations
    """
    # 1. Budget check
    budget_ok = check_budget("recon_new_capability")
    if not budget_ok:
        return json.dumps({"error": "Budget exhausted"})

    # 2. Execute via bridge
    result = await bridge.run_cmdlet(
        "Get-AADIntSomething",
        params={"Domain": domain},
        token_alias=token_alias,
    )

    # 3. Auto-save to engagement folder
    if save and result.success:
        save_recon_result(domain, "new_capability", result.data)

    # 4. Spend budget
    spend_budget("recon_new_capability", cost=1)

    return _format_result(result, "recon_new_capability")
```

### 2. Add an OPSEC profile in `opsec.py`

Every tool must declare its noise level and detection risk:

```python
"recon_new_capability": {
    "noise": "low",          # silent | low | medium | high | loud
    "cost": 1,               # budget points consumed
    "detection": "unlikely",  # none | unlikely | possible | likely | certain
    "logs": "Entra ID sign-in logs only",
    "mitre": "T1087.004",
},
```

### 3. Add auto-save hooks in `engagement_store.py` (if needed)

If the tool produces a new type of artifact, add a save function:

```python
def save_new_artifact(domain: str, data: dict) -> Path:
    """Save artifact to the appropriate engagement folder."""
    path = RESULTS_DIR / f"{domain}_{date}_new_capability.md"
    path.write_text(format_markdown(data))
    return path
```

### 4. Update documentation

- Add the tool to the tool table in `README.md`
- Add the tool to `docs/architecture_v2.1.md`
- If it wraps a new cmdlet, verify it exists in `docs/cmdlet_reference.md`

---

## Adding a New Scenario

### 1. Write the scenario in `scenarios/scenarios_87.md`

Follow the existing format:

```markdown
### S88: Descriptive Name -- Subtitle
**Hat:** WHITE | GRAY | BLACK
**Perspective:** EXTERNAL | EXTERNAL+CRED | INTERNAL | PARTNER | PRIVILEGED
**OPSEC:** Silent | Low | Medium | HIGH | LOUD
**MITRE:** T1234, T1234.001
**Tools:** `tool_a`, `tool_b`, `tool_c`

\```
# Phase 1: Description
tool_a(param="value")

# Phase 2: Description
tool_b(param="value")
\```

**White hat use:** How this is used in authorized testing.
**Gray hat use:** How this applies to red team or bug bounty.
**Black hat use:** How an adversary would use this technique.
**Key insight:** The important takeaway.
```

### 2. Update the scenario index table

Add the scenario to the index table at the top of `scenarios_87.md` and update the category distribution table at the bottom.

### 3. Map to existing kill chains (or propose a new one)

If the scenario fits into an existing kill chain, note where it can be inserted. If it enables a new end-to-end attack path, propose a new kill chain.

---

## Adding a New Kill Chain

### 1. Define the chain

A kill chain is a sequence of scenarios (S-numbers) that form a complete attack path:

```markdown
### Chain N: Descriptive Name
\```
S01 > S03 > S88 > S09 > S34
\```
Brief description of each step and the overall attack narrative.
```

### 2. Requirements

- Must start from a realistic entry point (external recon or compromised credential)
- Must end at a meaningful objective (data exfil, persistence, admin access, impact)
- Each step must logically flow from the previous one
- Total OPSEC cost must be calculated and documented
- Must map to real-world threat actor TTPs where possible

---

## Code Style

### Python

- **Formatter:** Follow PEP 8 conventions
- **Type hints:** Required on all function signatures
- **Docstrings:** Required on all `@mcp.tool()` functions -- these become the tool descriptions visible to the AI agent
- **Error handling:** Always return structured JSON, never raise unhandled exceptions
- **Async:** All MCP tools must be `async def`
- **Naming:** Tool functions use `snake_case` matching the MITRE phase prefix (`recon_`, `cred_`, `persist_`, `privesc_`, `evade_`, `move_`, `collect_`, `impact_`, `access_`)

### PowerShell

- **Cmdlet names:** Always use the full `Verb-AADIntNoun` format
- **Parameters:** Pass as named parameters, never positional
- **Output:** All cmdlets should output objects that can be serialized to JSON
- **Error handling:** Use `try/catch` blocks, return structured error objects

### Scenarios

- **MITRE mapping:** Every scenario must have at least one ATT&CK technique ID
- **OPSEC rating:** Every scenario must have an accurate OPSEC level
- **Hat color:** Every scenario must declare WHITE, GRAY, or BLACK
- **Three perspectives:** Explain white hat, gray hat, and black hat use cases

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`
2. **Make your changes** following the code style guidelines above
3. **Test** your changes (see Testing Requirements below)
4. **Update documentation** -- README, architecture docs, scenario index as needed
5. **Submit a PR** with:
   - Clear title describing the change
   - Description of what was added/changed and why
   - MITRE ATT&CK technique IDs for any new attack tools
   - OPSEC assessment for any new tools

### PR Checklist

- [ ] New tools have OPSEC profiles in `opsec.py`
- [ ] New tools have auto-save hooks in `engagement_store.py`
- [ ] New scenarios have MITRE mappings, OPSEC ratings, and hat colors
- [ ] Documentation updated (README, architecture, scenario index)
- [ ] No hardcoded credentials, tokens, or tenant-specific data
- [ ] No secrets or real engagement data in committed files

---

## Testing Requirements

### For new MCP tools

1. **Environment check:** Verify the tool works with `pwsh scripts/setup.ps1`
2. **Standalone test:** Run the tool against a test tenant you control
3. **Budget integration:** Verify the OPSEC budget is checked and spent correctly
4. **Auto-save:** Verify artifacts are saved to the correct engagement folder
5. **Error handling:** Verify the tool returns structured JSON on failure (no unhandled exceptions)

### For new scenarios

1. **Tool availability:** All tools referenced in the scenario must exist in `server.py`
2. **Logical flow:** Each step must produce output that the next step can consume
3. **OPSEC accuracy:** The OPSEC rating must reflect the actual detection risk
4. **MITRE accuracy:** Technique IDs must match the [ATT&CK matrix](https://attack.mitre.org/)

### For new kill chains

1. **End-to-end:** The chain must be executable from start to finish
2. **Budget feasibility:** Total OPSEC cost must fit within the default budget (100 points)
3. **Decision points:** Document where the chain branches based on tenant configuration

---

## Questions?

Open a [discussion](../../discussions) or reach out to the maintainers.
