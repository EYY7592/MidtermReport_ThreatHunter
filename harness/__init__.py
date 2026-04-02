"""
ThreatHunter Harness Engineering 基礎設施
========================================

三柱架構（OpenAI Harness Engineering 原版）：
  柱 1：情境工程 Context Engineering（L1）
  柱 2：架構約束 Architectural Constraints（L2）
  柱 3：熵防管理 Entropy Management（L3）

嚴格層次邊界：
  L1 → 不可引用 L2, L3
  L2 → 可引用 L1；不可引用 L3
  L3 → 可引用 L1, L2
"""
