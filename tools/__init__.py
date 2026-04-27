# ThreatHunter tools package
# 保留 package-level export 契約，但以 proxy 方式延後真正 import，
# 避免單純 `import tools` / `hasattr(tools, "...")` 就觸發 CrewAI 副作用。

from importlib import import_module
from typing import Any


class _LazyToolProxy:
    def __init__(self, module_name: str, attr_name: str) -> None:
        self._module_name = module_name
        self._attr_name = attr_name
        self._loaded: Any | None = None

    def _load(self) -> Any:
        if self._loaded is None:
            module = import_module(self._module_name)
            self._loaded = getattr(module, self._attr_name)
        return self._loaded

    def __call__(self, *args, **kwargs):
        return self._load()(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._load(), name)

    def __repr__(self) -> str:
        return f"<LazyToolProxy {self._module_name}:{self._attr_name}>"


_EXPORTS = {
    "search_nvd": ("tools.nvd_tool", "search_nvd"),
    "search_osv": ("tools.osv_tool", "search_osv"),
    "search_osv_batch": ("tools.osv_tool", "search_osv_batch"),
    "search_otx": ("tools.otx_tool", "search_otx"),
    "check_cisa_kev": ("tools.kev_tool", "check_cisa_kev"),
    "search_exploits": ("tools.exploit_tool", "search_exploits"),
    "fetch_epss_score": ("tools.epss_tool", "fetch_epss_score"),
    "get_epss_score": ("tools.epss_tool", "get_epss_score"),
    "lookup_attck_by_cwe": ("tools.attck_tool", "lookup_attck_by_cwe"),
    "lookup_attck_by_description": ("tools.attck_tool", "lookup_attck_by_description"),
    "get_attck_for_cve": ("tools.attck_tool", "get_attck_for_cve"),
    "read_memory": ("tools.memory_tool", "read_memory"),
    "write_memory": ("tools.memory_tool", "write_memory"),
    "history_search": ("tools.memory_tool", "history_search"),
}

__all__ = list(_EXPORTS)

for _name, (_module_name, _attr_name) in _EXPORTS.items():
    globals()[_name] = _LazyToolProxy(_module_name, _attr_name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
