"""
OPSEC Governor — controls tool execution based on noise budget and cumulative footprint.

Features:
- Noise budget per engagement (configurable, default 100 points)
- Cumulative noise tracking (silent=0, low=1, medium=5, high=20, loud=50)
- Pre-execution check: "should this tool run given remaining budget?"
- Auto-block when budget exhausted (unless force=True)
- Budget report: what was spent, what's left, projected remaining actions
- Integrates with opsec.py profiles
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from entrareaper.opsec import OPSEC_PROFILES

logger = logging.getLogger("entrareaper.governor")

BASE_DIR = Path(__file__).parent.parent.parent.parent  # project root
NOISE_DIR = BASE_DIR / "engagement" / "operations" / "noise"

# Noise level -> point cost
NOISE_COSTS: dict[str, int] = {
    "silent": 0,
    "low": 1,
    "medium": 5,
    "high": 20,
    "loud": 50,
}

DEFAULT_BUDGET = 100


def _engagement_slug(engagement: str) -> str:
    """Convert engagement name to filesystem-safe slug."""
    return engagement.replace(".", "-").replace("@", "-").replace(" ", "-").lower()


def _budget_path(engagement: str) -> Path:
    """Return the path to the budget state file for an engagement."""
    eng_dir = NOISE_DIR / _engagement_slug(engagement)
    eng_dir.mkdir(parents=True, exist_ok=True)
    return eng_dir / "budget.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_budget(engagement: str) -> dict:
    """Load budget state from disk, or create default if missing."""
    bp = _budget_path(engagement)
    if bp.exists():
        try:
            return json.loads(bp.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Corrupt budget file for {engagement}, resetting: {e}")

    # Initialize default budget
    state = {
        "engagement": engagement,
        "total_budget": DEFAULT_BUDGET,
        "spent": 0,
        "remaining": DEFAULT_BUDGET,
        "created_at": _now_iso(),
        "last_updated": _now_iso(),
        "ledger": [],
    }
    _save_budget(engagement, state)
    return state


def _save_budget(engagement: str, state: dict) -> Path:
    """Persist budget state to disk."""
    bp = _budget_path(engagement)
    state["last_updated"] = _now_iso()
    bp.write_text(json.dumps(state, indent=2))
    return bp


def _get_tool_noise_level(tool_name: str) -> str:
    """Look up the predicted noise level for a tool from OPSEC_PROFILES."""
    profile = OPSEC_PROFILES.get(tool_name)
    if profile:
        return profile.noise_level.lower()
    return "medium"  # conservative default for unknown tools


def _noise_to_cost(noise_level: str) -> int:
    """Convert a noise level string to its point cost."""
    return NOISE_COSTS.get(noise_level.lower(), 5)  # default to medium cost


def check_budget(engagement: str, tool_name: str, force: bool = False) -> dict:
    """
    Pre-execution check: should this tool run given the remaining budget?

    Args:
        engagement: Target engagement/domain name
        tool_name: The MCP tool about to be executed
        force: If True, allow execution even when budget is exhausted

    Returns:
        dict with keys: allowed, remaining, cost, predicted_noise, reason, force_override
    """
    state = _load_budget(engagement)
    noise_level = _get_tool_noise_level(tool_name)
    cost = _noise_to_cost(noise_level)
    remaining = state["remaining"]

    result = {
        "tool": tool_name,
        "engagement": engagement,
        "predicted_noise": noise_level,
        "cost": cost,
        "remaining_before": remaining,
        "remaining_after": remaining - cost,
        "total_budget": state["total_budget"],
        "spent_so_far": state["spent"],
        "force_override": force,
    }

    if cost == 0:
        result["allowed"] = True
        result["reason"] = f"Silent operation — zero noise cost."
        return result

    if remaining >= cost:
        result["allowed"] = True
        result["reason"] = (
            f"Budget OK. {tool_name} costs {cost} points ({noise_level}), "
            f"{remaining} remaining -> {remaining - cost} after execution."
        )
        return result

    # Budget exhausted
    if force:
        result["allowed"] = True
        result["reason"] = (
            f"BUDGET EXCEEDED — forced override. {tool_name} costs {cost} points "
            f"but only {remaining} remaining. Proceeding anyway (force=True)."
        )
        logger.warning(
            f"Budget override for {engagement}: {tool_name} costs {cost}, only {remaining} left"
        )
        return result

    result["allowed"] = False
    result["reason"] = (
        f"BLOCKED — budget exhausted. {tool_name} costs {cost} points ({noise_level}) "
        f"but only {remaining} remaining. Use force=True to override, or reset budget."
    )
    logger.info(f"Blocked {tool_name} for {engagement}: cost={cost}, remaining={remaining}")
    return result


def spend_budget(engagement: str, tool_name: str, actual_noise: str = "") -> dict:
    """
    Deduct noise cost from the engagement budget after tool execution.

    Args:
        engagement: Target engagement/domain name
        tool_name: The MCP tool that was executed
        actual_noise: Observed noise level (if different from predicted).
                      If empty, uses predicted noise from OPSEC_PROFILES.

    Returns:
        dict with keys: spent, cost, remaining, predicted_noise, actual_noise, delta
    """
    state = _load_budget(engagement)
    predicted_noise = _get_tool_noise_level(tool_name)
    effective_noise = actual_noise.lower() if actual_noise else predicted_noise
    cost = _noise_to_cost(effective_noise)

    # Record the spend
    ledger_entry = {
        "timestamp": _now_iso(),
        "tool": tool_name,
        "predicted_noise": predicted_noise,
        "actual_noise": effective_noise,
        "cost": cost,
        "budget_before": state["remaining"],
        "budget_after": state["remaining"] - cost,
    }
    state["ledger"].append(ledger_entry)
    state["spent"] += cost
    state["remaining"] = state["total_budget"] - state["spent"]

    _save_budget(engagement, state)

    delta = "match" if predicted_noise == effective_noise else "mismatch"
    if predicted_noise != effective_noise:
        predicted_cost = _noise_to_cost(predicted_noise)
        if cost > predicted_cost:
            delta = f"LOUDER than expected ({predicted_noise}->{effective_noise}, +{cost - predicted_cost} pts)"
        else:
            delta = f"quieter than expected ({predicted_noise}->{effective_noise}, -{predicted_cost - cost} pts)"

    logger.info(
        f"Budget spend: {engagement} | {tool_name} | cost={cost} | remaining={state['remaining']}"
    )

    return {
        "tool": tool_name,
        "engagement": engagement,
        "predicted_noise": predicted_noise,
        "actual_noise": effective_noise,
        "cost": cost,
        "delta": delta,
        "total_spent": state["spent"],
        "remaining": state["remaining"],
        "total_budget": state["total_budget"],
    }


def get_budget_report(engagement: str) -> dict:
    """
    Full budget status report with spend breakdown and projections.

    Returns:
        dict with keys: summary, ledger, spend_by_category, projections
    """
    state = _load_budget(engagement)

    # Spend breakdown by noise level
    spend_by_level: dict[str, dict] = {}
    for entry in state["ledger"]:
        level = entry.get("actual_noise", "unknown")
        if level not in spend_by_level:
            spend_by_level[level] = {"count": 0, "total_cost": 0, "tools": []}
        spend_by_level[level]["count"] += 1
        spend_by_level[level]["total_cost"] += entry["cost"]
        spend_by_level[level]["tools"].append(entry["tool"])

    # Spend breakdown by tool
    spend_by_tool: dict[str, dict] = {}
    for entry in state["ledger"]:
        tool = entry["tool"]
        if tool not in spend_by_tool:
            spend_by_tool[tool] = {"count": 0, "total_cost": 0}
        spend_by_tool[tool]["count"] += 1
        spend_by_tool[tool]["total_cost"] += entry["cost"]

    # Projections: how many more of each noise level can we afford?
    remaining = state["remaining"]
    projections = {}
    for level, cost in NOISE_COSTS.items():
        if cost == 0:
            projections[level] = "unlimited"
        elif remaining >= cost:
            projections[level] = remaining // cost
        else:
            projections[level] = 0

    # Warning thresholds
    pct_remaining = (remaining / state["total_budget"] * 100) if state["total_budget"] > 0 else 0
    if pct_remaining <= 10:
        warning = "CRITICAL — less than 10% budget remaining. Switch to silent operations only."
    elif pct_remaining <= 25:
        warning = "WARNING — less than 25% budget remaining. Avoid high/loud operations."
    elif pct_remaining <= 50:
        warning = "CAUTION — less than 50% budget remaining. Plan remaining operations carefully."
    else:
        warning = None

    report = {
        "engagement": engagement,
        "summary": {
            "total_budget": state["total_budget"],
            "spent": state["spent"],
            "remaining": remaining,
            "percent_remaining": round(pct_remaining, 1),
            "operations_executed": len(state["ledger"]),
            "created_at": state["created_at"],
            "last_updated": state["last_updated"],
        },
        "spend_by_noise_level": spend_by_level,
        "spend_by_tool": spend_by_tool,
        "projections": {
            "remaining_actions_by_level": projections,
            "note": "How many more operations of each noise level the budget can absorb.",
        },
        "ledger": state["ledger"],
    }

    if warning:
        report["warning"] = warning

    return report


def set_budget(engagement: str, total: int) -> dict:
    """
    Configure (or reconfigure) the total noise budget for an engagement.

    Args:
        engagement: Target engagement/domain name
        total: New total budget in noise points

    Returns:
        dict confirming the new budget settings
    """
    if total < 0:
        return {"error": "Budget cannot be negative.", "engagement": engagement}

    state = _load_budget(engagement)
    old_total = state["total_budget"]
    state["total_budget"] = total
    state["remaining"] = total - state["spent"]

    # Add a ledger entry for the budget change
    state["ledger"].append({
        "timestamp": _now_iso(),
        "tool": "_budget_change",
        "predicted_noise": "silent",
        "actual_noise": "silent",
        "cost": 0,
        "budget_before": old_total,
        "budget_after": total,
        "note": f"Budget changed from {old_total} to {total}",
    })

    _save_budget(engagement, state)
    logger.info(f"Budget set for {engagement}: {old_total} -> {total}")

    return {
        "engagement": engagement,
        "old_budget": old_total,
        "new_budget": total,
        "spent": state["spent"],
        "remaining": state["remaining"],
    }


def reset_budget(engagement: str) -> dict:
    """
    Reset the noise budget to default, clearing all ledger history.

    Args:
        engagement: Target engagement/domain name

    Returns:
        dict confirming the reset
    """
    state = _load_budget(engagement)
    old_spent = state["spent"]
    old_ledger_count = len(state["ledger"])

    state = {
        "engagement": engagement,
        "total_budget": DEFAULT_BUDGET,
        "spent": 0,
        "remaining": DEFAULT_BUDGET,
        "created_at": state.get("created_at", _now_iso()),
        "last_updated": _now_iso(),
        "ledger": [{
            "timestamp": _now_iso(),
            "tool": "_budget_reset",
            "predicted_noise": "silent",
            "actual_noise": "silent",
            "cost": 0,
            "budget_before": old_spent,
            "budget_after": 0,
            "note": f"Budget reset. Cleared {old_spent} spent points and {old_ledger_count} ledger entries.",
        }],
    }

    _save_budget(engagement, state)
    logger.info(f"Budget reset for {engagement}: cleared {old_spent} spent, {old_ledger_count} entries")

    return {
        "engagement": engagement,
        "status": "reset",
        "budget": DEFAULT_BUDGET,
        "previous_spent": old_spent,
        "previous_operations": old_ledger_count,
    }
