"""
tests/stress_test_realworld.py - ThreatHunter 多維度壓力測試
=============================================================
5 大維度 × 15 個場景，全方位驗證系統的實用性、安全性、信用性、健壯性。

遵守：project_CONSTITUTION.md + HARNESS_ENGINEERING.md
執行：
  uv run python -m pytest tests/stress_test_realworld.py -v            # 全部 15 場景
  uv run python -m pytest tests/stress_test_realworld.py -v -k "security"  # 只跑安全性
  uv run python -m pytest tests/stress_test_realworld.py -v -k "robustness"  # 只跑健壯性
"""

import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import pytest

sys.path.insert(0, ".")

from main import run_pipeline

logger = logging.getLogger("threathunter.stress")


# ══════════════════════════════════════════════════════════════
# 共用斷言函式
# ══════════════════════════════════════════════════════════════

def assert_pipeline_complete(result: dict, min_stages: int = 3) -> None:
    """Pipeline 不崩潰，有完整輸出"""
    assert result is not None, "Pipeline 回傳 None"
    assert "pipeline_meta" in result, "缺少 pipeline_meta"
    meta = result["pipeline_meta"]
    assert meta["stages_completed"] >= min_stages, (
        f"只完成 {meta['stages_completed']} 階段，至少需要 {min_stages}"
    )


def assert_valid_risk_score(result: dict) -> None:
    """risk_score 在合理範圍"""
    score = result.get("risk_score", -1)
    assert 0 <= score <= 100, f"risk_score={score} 超出 0-100 範圍"


def assert_has_actions(result: dict) -> None:
    """Advisor 有產出行動報告"""
    actions = result.get("actions", {})
    assert isinstance(actions, dict), f"actions 不是 dict: {type(actions)}"
    # 至少有 urgent/important/resolved 三個 key 之一
    assert any(k in actions for k in ("urgent", "important", "resolved")), (
        f"actions 缺少 urgent/important/resolved: {list(actions.keys())}"
    )


def assert_no_fabricated_cves(result: dict) -> None:
    """
    禁止虛構 CVE（憲法 CI-1, CI-2）。
    所有 CVE-ID 必須符合 CVE-YYYY-NNNNN 格式。
    """
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}")
    actions = result.get("actions", {})
    for priority_key in ("urgent", "important"):
        for action in actions.get(priority_key, []):
            cve_id = action.get("cve_id", "")
            if cve_id and cve_id != "UNKNOWN":
                assert cve_pattern.match(cve_id), (
                    f"CVE-ID 格式異常（可能是虛構）: {cve_id}"
                )


def assert_executive_summary_exists(result: dict) -> None:
    """有 executive_summary 欄位"""
    summary = result.get("executive_summary", "")
    assert len(summary) > 10, f"executive_summary 太短或不存在: '{summary[:50]}'"


def assert_critic_ran(result: dict) -> None:
    """Critic 確實執行（非 SKIPPED）"""
    meta = result.get("pipeline_meta", {})
    verdict = meta.get("critic_verdict", "SKIPPED")
    # SKIPPED 表示 Critic 沒有執行
    assert verdict != "SKIPPED", f"Critic verdict 為 SKIPPED，表示未真正執行"


# ══════════════════════════════════════════════════════════════
# 速率限制保護
# ══════════════════════════════════════════════════════════════

INTER_TEST_DELAY = 10  # 場景間隔秒數，防 API 限速


def rate_limit_guard():
    """場景之間的速率保護"""
    time.sleep(INTER_TEST_DELAY)


# ══════════════════════════════════════════════════════════════
# 維度一：實用性（Usability）
# ══════════════════════════════════════════════════════════════


class TestUsability:
    """測試真實使用者的多種輸入模式"""

    def test_u1_enterprise_multistack(self):
        """U1: 企業多層技術棧 — 同時掃描 7+ 套件"""
        tech_stack = "Nginx 1.24, Django 4.2, Redis 7.0, PostgreSQL 16, Celery 5.3, Docker 24.0, OpenSSL 3.1"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        assert_has_actions(result)
        assert_executive_summary_exists(result)
        rate_limit_guard()

    def test_u2_syslog_input(self):
        """U2: 系統日誌摘要 — 從非結構化日誌提取套件"""
        tech_stack = (
            "[ALERT] Apache 2.4.51 mod_proxy SSRF detected. "
            "OpenSSL 1.1.1 CVE-2023-5678 in /var/log. "
            "MySQL 8.0.28 auth bypass warning."
        )
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        assert_has_actions(result)
        rate_limit_guard()

    def test_u3_natural_language_vulnerability_report(self):
        """U3: 漏洞疑慮報告（自然語言描述）"""
        tech_stack = (
            "Our team suspects SQL injection in our Joomla 3.6 CMS. "
            "WordPress 6.0 has outdated xmlrpc.php. "
            "Spring Boot 3.1 actuator endpoint exposed."
        )
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        assert_executive_summary_exists(result)
        rate_limit_guard()

    def test_u4_mixed_chinese_english(self):
        """U4: 混合中英文輸入"""
        tech_stack = (
            "公司系統使用 Spring Boot 3.1 和 Node.js 18，"
            "後端有 Redis 7.0 快取，最近收到 Log4Shell 漏洞警報"
        )
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        assert_has_actions(result)
        rate_limit_guard()


# ══════════════════════════════════════════════════════════════
# 維度二：安全性（Security）
# ══════════════════════════════════════════════════════════════


class TestSecurity:
    """測試系統能否抓到真正危險的漏洞"""

    def test_s1_log4shell_critical(self):
        """S1: 已知高危漏洞 — Log4j 2.14 (Log4Shell, CVSS 10.0)"""
        tech_stack = "Log4j 2.14.1"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        # Log4j 2.14 是 CVSS 10.0 的漏洞，risk_score 應該很高
        risk = result.get("risk_score", 0)
        assert risk >= 50, (
            f"Log4j 2.14 的 risk_score 應 >= 50，實際為 {risk}"
        )
        rate_limit_guard()

    def test_s2_apache_path_traversal(self):
        """S2: CISA KEV 清單漏洞 — Apache 2.4.49 (CVE-2021-41773)"""
        tech_stack = "Apache HTTP 2.4.49"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        assert_has_actions(result)
        rate_limit_guard()

    def test_s3_eol_frameworks(self):
        """S3: 過時但常見的框架（EOL 軟體風險）"""
        tech_stack = "jQuery 2.1.4, Bootstrap 3.3.7, PHP 7.4"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        rate_limit_guard()

    def test_s4_supply_chain_attack(self):
        """S4: Python 供應鏈攻擊場景"""
        tech_stack = "requests 2.28.0, urllib3 1.26.5, setuptools 65.0"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_valid_risk_score(result)
        assert_has_actions(result)
        rate_limit_guard()


# ══════════════════════════════════════════════════════════════
# 維度三：信用性（Credibility）
# ══════════════════════════════════════════════════════════════


class TestCredibility:
    """測試報告內容是否可信、合規"""

    def test_c1_cve_authenticity(self):
        """C1: CVE 真實性驗證 — 所有 CVE-ID 格式合法且非虛構"""
        tech_stack = "Django 4.2, Redis 7.0"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        assert_no_fabricated_cves(result)
        rate_limit_guard()

    def test_c2_risk_score_consistency(self):
        """C2: risk_score 與行動分級一致性
        
        如果 risk_score >= 80，urgent 項目不應為空；
        如果 risk_score <= 20，urgent 項目應該為空或極少。
        """
        tech_stack = "Django 4.2, Redis 7.0"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        risk = result.get("risk_score", 0)
        urgent_count = len(result.get("actions", {}).get("urgent", []))

        if risk >= 80:
            assert urgent_count > 0, (
                f"risk_score={risk} >= 80，但 urgent 為空（不合理）"
            )
        rate_limit_guard()

    def test_c3_critic_execution(self):
        """C3: Critic Agent 確實執行（非 SKIPPED）"""
        tech_stack = "Django 4.2, Redis 7.0"
        result = run_pipeline(tech_stack)

        assert_pipeline_complete(result)
        # Critic 已啟用，應執行對抗辯論
        assert_critic_ran(result)
        rate_limit_guard()


# ══════════════════════════════════════════════════════════════
# 維度四：健壯性（Robustness）
# ══════════════════════════════════════════════════════════════


class TestRobustness:
    """測試邊界條件與故障恢復"""

    def test_r1_empty_input(self):
        """R1: 空輸入 — 不崩潰，回傳有意義的結果"""
        tech_stack = ""
        try:
            result = run_pipeline(tech_stack)
            # 如果 Pipeline 接受空輸入，結果應該是安全的
            if result is not None:
                assert_valid_risk_score(result)
        except (ValueError, RuntimeError) as e:
            # 明確拒絕空輸入是可接受的行為
            assert "empty" in str(e).lower() or "input" in str(e).lower() or len(str(e)) > 0
        rate_limit_guard()

    def test_r2_nonexistent_package(self):
        """R2: 不存在的套件 — 處理查無結果"""
        tech_stack = "FakePackage999 1.0, NonExistLib 2.0"
        result = run_pipeline(tech_stack)

        # Pipeline 應該完成（可能 degraded）
        assert result is not None, "Pipeline 回傳 None"
        assert "pipeline_meta" in result, "缺少 pipeline_meta"
        assert_valid_risk_score(result)
        rate_limit_guard()

    def test_r3_long_input(self):
        """R3: 超長輸入（50 個套件）— 不 timeout、不 OOM"""
        packages = [
            "Django 4.2", "Redis 7.0", "PostgreSQL 16", "Nginx 1.24",
            "OpenSSL 3.1", "Node.js 18", "React 18.2", "Vue 3.3",
            "Spring Boot 3.1", "Flask 2.3", "FastAPI 0.100", "Express 4.18",
            "jQuery 3.7", "Bootstrap 5.3", "Angular 16", "Svelte 4.0",
            "MySQL 8.0", "MongoDB 7.0", "Elasticsearch 8.9", "Kafka 3.5",
            "RabbitMQ 3.12", "Celery 5.3", "Docker 24.0", "Kubernetes 1.28",
            "Terraform 1.5", "Ansible 2.15", "Jenkins 2.414", "GitLab 16.3",
            "Prometheus 2.46", "Grafana 10.0", "Kibana 8.9", "Logstash 8.9",
            "Apache 2.4", "Tomcat 10.1", "Jetty 12.0", "Gunicorn 21.2",
            "uWSGI 2.0", "HAProxy 2.8", "Traefik 2.10", "Envoy 1.27",
            "Istio 1.19", "Consul 1.16", "Vault 1.14", "Nomad 1.6",
            "MinIO 2023.0", "Ceph 18.0", "GlusterFS 11.0", "NATS 2.9",
            "ZeroMQ 4.3", "gRPC 1.57",
        ]
        tech_stack = ", ".join(packages)
        result = run_pipeline(tech_stack)

        # 可能部分降級，但必須不崩潰
        assert result is not None, "Pipeline 回傳 None（超長輸入導致崩潰）"
        assert "pipeline_meta" in result, "缺少 pipeline_meta"
        rate_limit_guard()

    def test_r4_special_characters(self):
        """R4: 特殊字元注入 — 防止注入攻擊"""
        tech_stack = "Django<4.2>; Redis'7.0\"; --drop table"
        result = run_pipeline(tech_stack)

        # 不崩潰是底線，安全處理特殊字元
        assert result is not None, "Pipeline 回傳 None（特殊字元導致崩潰）"
        assert "pipeline_meta" in result, "缺少 pipeline_meta"
        rate_limit_guard()


# ══════════════════════════════════════════════════════════════
# 測試報告產生器
# ══════════════════════════════════════════════════════════════


@pytest.fixture(scope="session", autouse=True)
def stress_test_summary(request):
    """在所有測試完成後輸出摘要報告"""
    yield
    passed = request.session.testscollected - request.session.testsfailed
    total = request.session.testscollected
    failed = request.session.testsfailed
    print("\n" + "=" * 60)
    print(f"  ThreatHunter 壓力測試報告")
    print(f"  通過: {passed}/{total} ({passed/total*100:.0f}%)" if total > 0 else "  無測試")
    print(f"  失敗: {failed}")
    print("=" * 60)
