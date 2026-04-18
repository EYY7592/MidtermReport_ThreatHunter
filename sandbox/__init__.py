# sandbox/__init__.py
# ThreatHunter Sandbox 模組
# 三層安全隔離架構（v3.9）：
#   Layer 1: AST 遮罩 + timeout（ast_guard.py）
#   Layer 2: Docker 容器隔離（docker_sandbox.py）
#   Layer 3: Memory 快取淨化（memory_sanitizer.py）
#
# 設計原則：Graceful Degradation
#   每一層都有降級路徑，不會因 Sandbox 不可用而中斷 Pipeline
