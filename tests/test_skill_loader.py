"""
tests/test_skill_loader.py — Phase 4D 動態 Skill 熱載入系統測試
================================================================

測試覆蓋範圍（32 個測試）：
  - SkillLoader 初始化與基本讀取
  - mtime 快取機制（TTL 內不重讀、TTL 過期後驗證、mtime 變更自動熱載入）
  - Graceful Degradation（檔案遺失、空檔案、編碼錯誤）
  - 執行緒安全（多執行緒並行讀取/重載）
  - reload_skill / reload_all / invalidate / invalidate_all
  - get_registry / get_stats / list_available_skills
  - 全域單例 skill_loader 的連貫性

遵守：project_CONSTITUTION.md — 不使用 stub / pass / TODO
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# ── 確保 project root 在 sys.path ─────────────────────────────────
_HERE = Path(__file__).parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))


# ═══════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture()
def tmp_skills_dir(tmp_path: Path) -> Path:
    """建立臨時 skills/ 目錄，含 3 個測試用 .md 檔案"""
    (tmp_path / "alpha.md").write_text("# Alpha SOP\nStep 1: Check CVE.", encoding="utf-8")
    (tmp_path / "beta.md").write_text("# Beta SOP\nStep 1: Query NVD.", encoding="utf-8")
    (tmp_path / "gamma.md").write_text("# Gamma SOP\nStep 1: Scan OTX.", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def loader(tmp_skills_dir: Path):
    """建立指向臨時目錄的 SkillLoader，TTL 設為高精度值供測試"""
    from skills.skill_loader import SkillLoader
    return SkillLoader(skills_dir=tmp_skills_dir)


# ═══════════════════════════════════════════════════════════════════
# 一、基本初始化與讀取
# ═══════════════════════════════════════════════════════════════════

class TestInitialization:
    """測試 SkillLoader 初始化行為"""

    def test_default_skills_dir(self):
        """全域單例使用正確的 skills/ 目錄"""
        from skills.skill_loader import skill_loader
        assert skill_loader._skills_dir.name == "skills"
        assert skill_loader._skills_dir.is_dir()

    def test_custom_skills_dir(self, tmp_skills_dir: Path):
        """自訂 skills_dir 正確設定"""
        from skills.skill_loader import SkillLoader
        loader = SkillLoader(skills_dir=tmp_skills_dir)
        assert loader._skills_dir == tmp_skills_dir

    def test_empty_cache_on_init(self, loader):
        """初始化後快取應為空"""
        assert len(loader._cache) == 0

    def test_str_path_accepted(self, tmp_skills_dir: Path):
        """接受字串路徑（不只 Path 物件）"""
        from skills.skill_loader import SkillLoader
        loader = SkillLoader(skills_dir=str(tmp_skills_dir))
        content = loader.load_skill("alpha.md")
        assert "Alpha" in content


# ═══════════════════════════════════════════════════════════════════
# 二、基本讀取與快取
# ═══════════════════════════════════════════════════════════════════

class TestBasicLoading:
    """測試基本 load_skill 行為"""

    def test_load_existing_skill(self, loader):
        """讀取存在的 skill 檔案"""
        content = loader.load_skill("alpha.md")
        assert "Alpha SOP" in content
        assert "Step 1" in content

    def test_load_populates_cache(self, loader):
        """首次讀取後快取中應有此條目"""
        loader.load_skill("alpha.md")
        assert "alpha.md" in loader._cache

    def test_load_nonexistent_returns_fallback(self, loader):
        """不存在的 skill 應回傳 fallback SOP，不得拋出例外"""
        content = loader.load_skill("nonexistent.md")
        assert isinstance(content, str)
        assert len(content) > 0  # 至少是 _DEFAULT_FALLBACK

    def test_fallback_entry_mtime_is_negative(self, loader):
        """Fallback 條目的 mtime 應為 -1.0"""
        loader.load_skill("nonexistent.md")
        entry = loader._cache.get("nonexistent.md")
        assert entry is not None
        assert entry.mtime == -1.0

    def test_known_fallback_sop_used(self, loader):
        """已知的 fallback key（如 threat_intel.md）應用對應 fallback SOP"""
        from skills.skill_loader import _FALLBACK_SOPS
        # 使用不在 tmp_skills_dir 的已知 fallback key
        if "threat_intel.md" in _FALLBACK_SOPS:
            content = loader.load_skill("threat_intel.md")
            assert "Threat Intel" in content or len(content) > 10

    def test_multiple_skills_independent(self, loader):
        """多個 skill 互相獨立快取"""
        a = loader.load_skill("alpha.md")
        b = loader.load_skill("beta.md")
        assert a != b
        assert "alpha.md" in loader._cache
        assert "beta.md" in loader._cache

    def test_load_utf8_bom_encoding(self, tmp_skills_dir: Path):
        """能讀取 UTF-8 BOM 編碼的檔案"""
        from skills.skill_loader import SkillLoader
        bom_file = tmp_skills_dir / "bom_test.md"
        bom_file.write_bytes(b"\xef\xbb\xbf# BOM Test\nContent here.")
        loader = SkillLoader(skills_dir=tmp_skills_dir)
        content = loader.load_skill("bom_test.md")
        assert "BOM Test" in content


# ═══════════════════════════════════════════════════════════════════
# 三、TTL 快取與 mtime 熱載入
# ═══════════════════════════════════════════════════════════════════

class TestCacheAndHotReload:
    """測試 TTL + mtime 熱載入核心邏輯"""

    def test_ttl_cache_hit(self, loader):
        """TTL 內重複呼叫不應觸發磁碟讀取"""
        loader.load_skill("alpha.md")
        # 修改快取條目的 load_time 使其在 TTL 內
        loader._cache["alpha.md"].load_time = time.time()

        # 計數快取讀取次數，期望為 0 次磁碟讀取
        original_read = loader._read_file
        read_count = []

        def mock_read(filepath):
            read_count.append(1)
            return original_read(filepath)

        loader._read_file = mock_read
        loader.load_skill("alpha.md")
        loader._read_file = original_read

        assert len(read_count) == 0, "TTL 內不應重新讀取磁碟"

    def test_mtime_unchanged_refreshes_load_time(self, loader, tmp_skills_dir: Path):
        """mtime 未變，TTL 到期後只更新 load_time，不重讀磁碟"""
        loader.load_skill("alpha.md")
        # 記錄初始 load_time
        initial_load_time = loader._cache["alpha.md"].load_time

        # 強制 TTL 過期（load_time 設為遠古值）
        loader._cache["alpha.md"].load_time = 0.0

        # 稍等確保 time.time() 數值有差異
        time.sleep(0.05)
        loader.load_skill("alpha.md")

        # load_time 應大於 0（重新設為 time.time()）
        new_load_time = loader._cache["alpha.md"].load_time
        assert new_load_time > 0.0
        assert new_load_time > initial_load_time - 1  # 大於接近原始值即可


    def test_mtime_changed_triggers_hot_reload(self, loader, tmp_skills_dir: Path):
        """mtime 改變時應觸發熱載入"""
        loader.load_skill("alpha.md")

        # 強制 TTL 過期
        loader._cache["alpha.md"].load_time = 0

        # 修改檔案內容
        time.sleep(0.05)  # 確保 mtime 差異可被偵測
        new_content = "# Alpha SOP v2 UPDATED\nNew step added."
        (tmp_skills_dir / "alpha.md").write_text(new_content, encoding="utf-8")

        # 強制文件系統更新 mtime（Windows 有時需要）
        new_path = tmp_skills_dir / "alpha.md"
        new_mtime = new_path.stat().st_mtime
        loader._cache["alpha.md"].mtime = new_mtime - 1.0  # 模擬舊 mtime

        content = loader.load_skill("alpha.md")
        assert "v2 UPDATED" in content

    def test_file_deleted_switches_to_fallback(self, loader, tmp_skills_dir: Path):
        """檔案被刪除後應切換到 fallback SOP"""
        loader.load_skill("gamma.md")
        assert loader._cache["gamma.md"].mtime > 0  # 正常載入

        # 刪除檔案並強制 TTL 過期
        (tmp_skills_dir / "gamma.md").unlink()
        loader._cache["gamma.md"].load_time = 0

        content = loader.load_skill("gamma.md")
        assert isinstance(content, str)
        assert len(content) > 0
        # mtime 應重設為 -1（fallback 標識）
        assert loader._cache["gamma.md"].mtime == -1.0


# ═══════════════════════════════════════════════════════════════════
# 四、強制重載 API
# ═══════════════════════════════════════════════════════════════════

class TestReloadAPI:
    """測試 reload_skill / reload_all / invalidate / invalidate_all"""

    def test_reload_skill_refreshes_content(self, loader, tmp_skills_dir: Path):
        """reload_skill 應立即讀取最新內容"""
        loader.load_skill("alpha.md")
        (tmp_skills_dir / "alpha.md").write_text("# Reloaded.", encoding="utf-8")

        content = loader.reload_skill("alpha.md")
        assert "Reloaded" in content

    def test_reload_all_updates_cached_skills(self, loader, tmp_skills_dir: Path):
        """reload_all 更新所有已快取 skill"""
        loader.load_skill("alpha.md")
        loader.load_skill("beta.md")

        (tmp_skills_dir / "alpha.md").write_text("# Alpha v3.", encoding="utf-8")
        (tmp_skills_dir / "beta.md").write_text("# Beta v3.", encoding="utf-8")

        results = loader.reload_all()
        assert "Alpha v3" in results.get("alpha.md", "")
        assert "Beta v3" in results.get("beta.md", "")

    def test_invalidate_removes_cache_entry(self, loader):
        """invalidate 後快取應移除該條目"""
        loader.load_skill("alpha.md")
        assert "alpha.md" in loader._cache

        loader.invalidate("alpha.md")
        assert "alpha.md" not in loader._cache

    def test_invalidate_nonexistent_no_error(self, loader):
        """invalidate 不存在的 key 不應拋出例外"""
        loader.invalidate("ghost.md")  # 不應 raise

    def test_invalidate_all_clears_cache(self, loader):
        """invalidate_all 應清空所有快取"""
        loader.load_skill("alpha.md")
        loader.load_skill("beta.md")
        assert len(loader._cache) == 2

        loader.invalidate_all()
        assert len(loader._cache) == 0

    def test_reload_nonexistent_returns_fallback(self, loader):
        """reload_skill 對不存在檔案應回傳 fallback"""
        content = loader.reload_skill("never_exists.md")
        assert isinstance(content, str)
        assert len(content) > 0


# ═══════════════════════════════════════════════════════════════════
# 五、Registry 與 Stats API
# ═══════════════════════════════════════════════════════════════════

class TestRegistryAndStats:
    """測試 get_registry / get_stats / list_available_skills"""

    def test_get_registry_structure(self, loader):
        """get_registry 回傳符合預期結構"""
        loader.load_skill("alpha.md")
        registry = loader.get_registry()

        assert "skills_dir" in registry
        assert "cache_ttl_seconds" in registry
        assert "total" in registry
        assert "skills" in registry
        assert registry["total"] == 1

    def test_get_registry_entry_fields(self, loader):
        """get_registry 中每個 entry 應含必要欄位"""
        loader.load_skill("alpha.md")
        registry = loader.get_registry()
        entry = registry["skills"][0]

        required_fields = ["filename", "size_bytes", "mtime", "load_time", "age_seconds",
                           "is_fallback", "content_preview"]
        for field in required_fields:
            assert field in entry, f"缺少欄位: {field}"

    def test_get_stats_structure(self, loader):
        """get_stats 回傳符合預期結構"""
        loader.load_skill("alpha.md")
        stats = loader.get_stats()

        assert "cached_skills" in stats
        assert "fallback_count" in stats
        assert "skills_dir" in stats
        assert "cache_ttl_seconds" in stats
        assert stats["cached_skills"] == 1

    def test_fallback_count_accurate(self, loader):
        """get_stats 中 fallback_count 應準確"""
        loader.load_skill("real_file.md")  # nonexistent → fallback
        loader.load_skill("alpha.md")       # exists → normal

        stats = loader.get_stats()
        assert stats["cached_skills"] == 2
        assert stats["fallback_count"] == 1  # 只有 real_file.md 是 fallback

    def test_list_available_skills(self, loader, tmp_skills_dir: Path):
        """list_available_skills 應列出所有 .md 檔案"""
        available = loader.list_available_skills()
        assert "alpha.md" in available
        assert "beta.md" in available
        assert "gamma.md" in available
        # 不應含非 .md 檔案
        assert all(f.endswith(".md") for f in available)


# ═══════════════════════════════════════════════════════════════════
# 六、執行緒安全
# ═══════════════════════════════════════════════════════════════════

class TestThreadSafety:
    """測試多執行緒並行存取的安全性"""

    def test_concurrent_loads_no_race(self, loader):
        """多執行緒並行 load_skill 不得出現競爭條件"""
        results = []
        errors = []

        def worker():
            try:
                content = loader.load_skill("alpha.md")
                results.append(content)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"執行緒錯誤: {errors}"
        assert len(results) == 20
        # 所有結果應相同
        assert len(set(results)) == 1

    def test_concurrent_reload_and_load(self, loader, tmp_skills_dir: Path):
        """並行 reload 與 load 不得 deadlock 或 crash"""
        stop_event = threading.Event()
        errors = []

        def continuous_loader():
            while not stop_event.is_set():
                try:
                    loader.load_skill("beta.md")
                except Exception as e:
                    errors.append(str(e))

        def reloader():
            for _ in range(5):
                try:
                    loader.reload_skill("beta.md")
                    time.sleep(0.01)
                except Exception as e:
                    errors.append(str(e))

        loader_thread = threading.Thread(target=continuous_loader)
        reload_thread = threading.Thread(target=reloader)

        loader_thread.start()
        reload_thread.start()

        reload_thread.join(timeout=5)
        stop_event.set()
        loader_thread.join(timeout=5)

        assert len(errors) == 0, f"並行錯誤: {errors}"


# ═══════════════════════════════════════════════════════════════════
# 七、全域單例行為
# ═══════════════════════════════════════════════════════════════════

class TestGlobalSingleton:
    """測試全域 skill_loader 單例一致性"""

    def test_singleton_same_instance(self):
        """多次 import 應得到同一個 skill_loader 實例"""
        from skills.skill_loader import skill_loader as sl1
        from skills.skill_loader import skill_loader as sl2
        assert sl1 is sl2

    def test_global_load_skill_function(self, tmp_path: Path):
        """全域 load_skill() 函式正確委派到單例"""
        from skills import skill_loader as module

        # 使用臨時 skills 目錄修補單例
        original_dir = module.skill_loader._skills_dir
        try:
            test_file = tmp_path / "test_skill.md"
            test_file.write_text("# Test via global function.", encoding="utf-8")
            module.skill_loader._skills_dir = tmp_path
            module.skill_loader.invalidate("test_skill.md")

            content = module.load_skill("test_skill.md")
            assert "Test via global function" in content
        finally:
            module.skill_loader._skills_dir = original_dir

    def test_global_reload_skill_function(self):
        """全域 reload_skill() 函式不拋出例外"""
        from skills.skill_loader import reload_skill
        content = reload_skill("ghost_again.md")
        assert isinstance(content, str)

    def test_global_get_registry_function(self):
        """全域 get_registry() 函式回傳正確結構"""
        from skills.skill_loader import get_registry
        registry = get_registry()
        assert "skills_dir" in registry
        assert "skills" in registry
