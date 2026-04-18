"""
tests/test_path_aware_skills.py
================================
v3.7: Validates path-aware SKILL_MAP routing for all 4 Agents across 4 paths.

Test coverage:
  1. SKILL_MAP route correctness (all 4 agents × 4 paths = 16 routes)
  2. Skill file existence (16 .md files)
  3. Agent factory accepts input_type without exception
  4. run_*_pipeline signature compatibility (input_type kwarg)
  5. checkpoint.stage_enter records skill_file + input_type
"""

import os
import inspect
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ===========================================================================
# 1. SKILL_MAP route correctness
# ===========================================================================

EXPECTED_ROUTES = {
    "pkg":       {
        "scout":   "threat_intel.md",
        "analyst": "chain_analysis.md",
        "critic":  "debate_sop.md",
        "advisor": "action_report.md",
    },
    "code":      {
        "scout":   "source_code_audit.md",
        "analyst": "code_chain_analysis.md",
        "critic":  "code_debate_sop.md",
        "advisor": "code_action_report.md",
    },
    "injection": {
        "scout":   "ai_security_audit.md",
        "analyst": "ai_chain_analysis.md",
        "critic":  "ai_debate_sop.md",
        "advisor": "ai_action_report.md",
    },
    "config":    {
        "scout":   "config_audit.md",
        "analyst": "config_chain_analysis.md",
        "critic":  "config_debate_sop.md",
        "advisor": "config_action_report.md",
    },
}


@pytest.mark.parametrize("input_type,expected", [
    (ip, e) for ip, e in EXPECTED_ROUTES.items()
])
def test_skill_map_routes(input_type, expected):
    """All 4 agent SKILL_MAPs return correct file for each input_type."""
    from agents.scout   import SKILL_MAP as S_MAP
    from agents.analyst import SKILL_MAP as A_MAP
    from agents.critic  import SKILL_MAP as C_MAP
    from agents.advisor import SKILL_MAP as ADV_MAP

    assert S_MAP.get(input_type)   == expected["scout"],   f"Scout[{input_type}] mismatch"
    assert A_MAP.get(input_type)   == expected["analyst"], f"Analyst[{input_type}] mismatch"
    assert C_MAP.get(input_type)   == expected["critic"],  f"Critic[{input_type}] mismatch"
    assert ADV_MAP.get(input_type) == expected["advisor"], f"Advisor[{input_type}] mismatch"


# ===========================================================================
# 2. Skill file existence
# ===========================================================================

ALL_SKILL_FILES = sorted({
    skill
    for paths in EXPECTED_ROUTES.values()
    for skill in paths.values()
})


@pytest.mark.parametrize("skill_file", ALL_SKILL_FILES)
def test_skill_file_exists(skill_file):
    """Every referenced skill .md file must exist on disk."""
    path = os.path.join(PROJECT_ROOT, "skills", skill_file)
    assert os.path.isfile(path), f"Missing skill file: skills/{skill_file}"


@pytest.mark.parametrize("skill_file", ALL_SKILL_FILES)
def test_skill_file_not_empty(skill_file):
    """Every skill file must have substantial content (>= 200 bytes)."""
    path = os.path.join(PROJECT_ROOT, "skills", skill_file)
    size = os.path.getsize(path)
    assert size >= 200, f"Skill file too small ({size} bytes): skills/{skill_file}"


# ===========================================================================
# 3. Agent factory accepts input_type without exception
# ===========================================================================

@pytest.mark.parametrize("input_type", ["pkg", "code", "injection", "config"])
def test_scout_agent_accepts_input_type(input_type):
    """create_scout_agent accepts input_type kwarg without raising."""
    from agents.scout import create_scout_agent
    sig = inspect.signature(create_scout_agent)
    assert "input_type" in sig.parameters, "create_scout_agent missing input_type param"


@pytest.mark.parametrize("input_type", ["pkg", "code", "injection", "config"])
def test_analyst_agent_accepts_input_type(input_type):
    """create_analyst_agent accepts input_type kwarg."""
    from agents.analyst import create_analyst_agent
    sig = inspect.signature(create_analyst_agent)
    assert "input_type" in sig.parameters, "create_analyst_agent missing input_type param"


@pytest.mark.parametrize("input_type", ["pkg", "code", "injection", "config"])
def test_critic_agent_accepts_input_type(input_type):
    """create_critic_agent accepts input_type kwarg."""
    from agents.critic import create_critic_agent
    sig = inspect.signature(create_critic_agent)
    assert "input_type" in sig.parameters, "create_critic_agent missing input_type param"


@pytest.mark.parametrize("input_type", ["pkg", "code", "injection", "config"])
def test_advisor_agent_accepts_input_type(input_type):
    """create_advisor_agent accepts input_type kwarg."""
    from agents.advisor import create_advisor_agent
    sig = inspect.signature(create_advisor_agent)
    assert "input_type" in sig.parameters, "create_advisor_agent missing input_type param"


# ===========================================================================
# 4. run_*_pipeline signature compatibility
# ===========================================================================

def test_run_scout_pipeline_signature():
    """run_scout_pipeline accepts input_type kwarg."""
    from agents.scout import run_scout_pipeline
    sig = inspect.signature(run_scout_pipeline)
    assert "input_type" in sig.parameters


def test_run_analyst_pipeline_signature():
    """run_analyst_pipeline accepts input_type kwarg."""
    from agents.analyst import run_analyst_pipeline
    sig = inspect.signature(run_analyst_pipeline)
    assert "input_type" in sig.parameters


def test_run_critic_pipeline_signature():
    """run_critic_pipeline accepts input_type kwarg."""
    from agents.critic import run_critic_pipeline
    sig = inspect.signature(run_critic_pipeline)
    assert "input_type" in sig.parameters


def test_run_advisor_pipeline_signature():
    """run_advisor_pipeline accepts input_type kwarg."""
    from agents.advisor import run_advisor_pipeline
    sig = inspect.signature(run_advisor_pipeline)
    assert "input_type" in sig.parameters


# ===========================================================================
# 5. stage_* functions in main.py accept input_type
# ===========================================================================

def test_stage_functions_accept_input_type():
    """stage_analyst, stage_critic, stage_advisor all accept input_type."""
    from main import stage_analyst, stage_critic, stage_advisor
    for fn in [stage_analyst, stage_critic, stage_advisor]:
        sig = inspect.signature(fn)
        assert "input_type" in sig.parameters, f"{fn.__name__} missing input_type param"


# ===========================================================================
# 6. checkpoint.stage_enter records skill_file + input_type
# ===========================================================================

def test_checkpoint_stage_enter_records_skill_metadata(tmp_path):
    """stage_enter should record skill_file and input_type in checkpoint data."""
    import json
    from checkpoint import CheckpointRecorder

    log_dir = tmp_path / "logs"
    recorder = CheckpointRecorder(logs_dir=log_dir)
    recorder.start_scan("test-injection-001")

    # Call stage_enter with skill_file + input_type
    recorder.stage_enter(
        agent="scout",
        input_data={"test": True},
        skill_file="ai_security_audit.md",
        input_type="injection",
    )

    recorder.end_scan("test-injection-001", {})

    # Read back and verify
    cp_dir = log_dir / "checkpoints"
    jsonl_files = list(cp_dir.glob("*.jsonl"))
    assert len(jsonl_files) == 1, f"Expected 1 JSONL file, got {jsonl_files}"

    events = []
    with open(jsonl_files[0], "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    stage_enters = [e for e in events if e.get("event") == "STAGE_ENTER"]
    assert len(stage_enters) >= 1, f"Expected STAGE_ENTER events, got: {[e.get('event') for e in events]}"

    # Find the scout stage_enter
    scout_enter = next(
        (e for e in stage_enters if e.get("agent") == "scout"),
        None
    )
    assert scout_enter is not None, "No STAGE_ENTER for scout agent"

    data = scout_enter.get("data", {})
    assert data.get("skill_file") == "ai_security_audit.md", \
        f"skill_file not recorded correctly: {data}"
    assert data.get("input_type") == "injection", \
        f"input_type not recorded correctly: {data}"


# ===========================================================================
# 7. _load_skill fallback behavior
# ===========================================================================

def test_load_skill_fallback_on_missing_file():
    """_load_skill returns fallback string when file does not exist."""
    from agents.scout import _load_skill
    result = _load_skill("nonexistent_skill_file.md")
    assert len(result) > 0, "Fallback should not be empty"
    assert isinstance(result, str)


@pytest.mark.parametrize("agent_module,skill_file", [
    ("scout",   "threat_intel.md"),
    ("analyst", "chain_analysis.md"),
    ("critic",  "debate_sop.md"),
    ("advisor", "action_report.md"),
])
def test_load_skill_returns_correct_content(agent_module, skill_file):
    """_load_skill returns non-empty string for valid skill files."""
    import importlib
    mod = importlib.import_module(f"agents.{agent_module}")
    result = mod._load_skill(skill_file)
    assert len(result) >= 100, f"Skill content too short for {skill_file}"
    assert "##" in result or "#" in result, "Skill file should contain markdown headers"
