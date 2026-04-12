#!/usr/bin/env python
"""
v3.4 scout.py patcher - replaces create_scout_task with package-aware version
"""
import os

new_block = '''def create_scout_task(agent, tech_stack: str):
    """
    v3.4: Scout Task - package-aware mode.
    When tech_stack is a short comma-separated package list (from PackageExtractor),
    explicitly enumerate each package for the LLM to query via search_nvd.
    """
    from crewai import Task

    # Detect if input is a clean package list or raw code/long text
    is_package_list = (
        len(tech_stack) < 300
        and "\\n" not in tech_stack
        and "def " not in tech_stack
        and "import " not in tech_stack
    )

    if is_package_list:
        packages = [p.strip() for p in tech_stack.split(",") if p.strip()]
        packages_display = "\\n".join(f"   {i+1}. {pkg}" for i, pkg in enumerate(packages))
        nvd_calls = "\\n".join(f"   - search_nvd(\\'{pkg}\\')" for pkg in packages[:8])
        task_desc = (
            f"You are analyzing security vulnerabilities for packages extracted from source code.\\n\\n"
            f"Package list to scan:\\n{packages_display}\\n\\n"
            f"Steps to follow (MUST call tools in order):\\n\\n"
            f"Step 1: Call read_memory\\n"
            f"   Action: read_memory\\n"
            f"   Action Input: scout\\n\\n"
            f"Step 2: For EACH package, call search_nvd separately:\\n"
            f"{nvd_calls}\\n\\n"
            f"Step 3: For CVEs with CVSS >= 7.0, call search_otx for that package\\n\\n"
            f"Step 4: Assemble JSON report from REAL tool results only\\n"
            f"   - CVE IDs, CVSS scores must come from search_nvd output\\n"
            f"   - Compare with read_memory history, mark is_new\\n\\n"
            f"Step 5: Call write_memory to save results\\n"
            f"   Action: write_memory\\n"
            f"   Action Input: scout|{{JSON report}}\\n\\n"
            f"Step 6: Output JSON report as Final Answer\\n\\n"
            f"FORBIDDEN:\\n"
            f"- Do NOT skip tool calls\\n"
            f"- Do NOT fabricate CVE IDs\\n"
            f"- Do NOT use backstory examples (they are fake)\\n"
            f"- write_memory MUST be called before Final Answer"
        )
    else:
        task_desc = (
            f"You are analyzing security vulnerabilities in: {tech_stack[:800]}\\n\\n"
            f"Steps to follow (MUST call tools in order):\\n\\n"
            f"Step 1: Call read_memory\\n"
            f"   Action: read_memory\\n"
            f"   Action Input: scout\\n\\n"
            f"Step 2: Identify package names and call search_nvd for each one\\n\\n"
            f"Step 3: For CVEs with CVSS >= 7.0, call search_otx\\n\\n"
            f"Step 4: Assemble JSON report from REAL tool results only\\n\\n"
            f"Step 5: Call write_memory\\n"
            f"   Action: write_memory\\n"
            f"   Action Input: scout|{{JSON report}}\\n\\n"
            f"Step 6: Output JSON report as Final Answer\\n\\n"
            f"FORBIDDEN:\\n"
            f"- Do NOT skip tool calls\\n"
            f"- Do NOT fabricate CVE IDs\\n"
            f"- write_memory MUST be called before Final Answer"
        )

    return Task(
        description=task_desc,
        expected_output="Structured JSON threat intel report with CVEs from search_nvd tool.",
        agent=agent,
    )

'''

scout_path = os.path.join("agents", "scout.py")
with open(scout_path, 'r', encoding='utf-8') as f:
    content = f.read()

idx = content.find('def create_scout_task')
end_idx = content.find('def run_scout_pipeline', idx)

if idx < 0:
    print("ERROR: create_scout_task not found")
    exit(1)

if end_idx < 0:
    print("ERROR: create_scout_pipeline not found")
    exit(1)

old_section = content[idx:end_idx]
new_content = content[:idx] + new_block + "\n\n" + content[end_idx:]

with open(scout_path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"SUCCESS: Scout task updated.")
print(f"  Old section length: {len(old_section)}")
print(f"  New block length: {len(new_block)}")
print(f"  Total file length: {len(new_content)}")
