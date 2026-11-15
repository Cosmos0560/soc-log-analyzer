"""Shared fixtures: loaders for the non-package scripts (gate, hook)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load_script(name: str, relative: str) -> ModuleType:
    """Import a script that is not part of the package (gate, hook) by file path."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def gate() -> ModuleType:
    return load_script("soc_gate", "scripts/gate.py")


@pytest.fixture(scope="session")
def hook() -> ModuleType:
    return load_script("soc_pre_tool_use", ".claude/hooks/pre_tool_use.py")
