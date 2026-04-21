# ThreatHunter Skill Guide

## What Is a Skill?

A Skill is an SOP embedded into an Agent's backstory.
It tells the Agent how to reason, not how to call an API.

## Skill vs. Tool

| | Skill | Tool |
|---|---|---|
| Nature | Markdown guidance written in natural language | Python function exposed with `@tool` |
| Location | Injected into the Agent backstory | Attached to the Agent `tools` list |
| Purpose | Steers reasoning and decision flow | Executes concrete operations such as API calls |
| Example | "Compare with history before setting `is_new`." | `search_nvd("django 4.2")` |

## Skill Files in This Project

| Skill File | Owner | Agent |
|---|---|---|
| `threat_intel.md` | Member B | Scout Agent |
| `chain_analysis.md` | Member C | Analyst Agent |
| `action_report.md` | Team Lead | Advisor Agent |

## Quality Expectations

Skills are one of the most important deliverables in this project.
Agent reasoning quality depends directly on Skill quality.
AI can help write code, but Skill design still requires human judgment.
