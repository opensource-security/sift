#!/usr/bin/env python3
"""The `sift[provenance]` extra must stay optional.

`sift.provenance` takes runtime dependencies (httpx, tldextract, idna, dateutil,
dnspython) that the core commit-triage pipeline does not. The whole point of
putting them behind an extra is that a base install still works, and the easiest
way to break that is for a later refactor to add a module-scope
`from sift.provenance import ...` somewhere under `sift/runtime/`.

This fixture is deterministic, offline, and free. It needs no dependencies at
all -- it reads source text and runs a subprocess with the extra's modules
blocked, rather than importing anything itself.

Run:
    python tests/test_provenance_extra_isolation.py
    pytest tests/test_provenance_extra_isolation.py
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Modules only the extra provides. A base install has none of them.
EXTRA_MODULES = ("httpx", "tldextract", "idna", "dateutil", "dns", "certifi", "httpcore")

CORE_PACKAGES = ("runtime", "render", "cli", "profiles")


def _module_scope_imports(path: Path) -> set[str]:
    """Top-level imports only; imports inside functions are the sanctioned form."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                found.add(node.module)
            elif node.module:
                found.add("." * node.level + node.module)
    return found


def test_core_packages_do_not_import_provenance_at_module_scope() -> None:
    offenders: list[str] = []
    checked = 0
    for package in CORE_PACKAGES:
        for path in sorted((ROOT / "sift" / package).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            checked += 1
            for name in _module_scope_imports(path):
                bare = name.lstrip(".")
                if bare.startswith("sift.provenance") or bare.startswith("provenance"):
                    offenders.append(f"{path.relative_to(ROOT)} imports {name}")
                if bare.split(".")[0] in EXTRA_MODULES:
                    offenders.append(f"{path.relative_to(ROOT)} imports {name}")
    assert not offenders, (
        "core packages must not depend on the provenance extra at module scope:\n  "
        + "\n  ".join(offenders)
    )
    print(f"  ok  {checked} core modules, none import the extra at module scope")


def test_pipeline_imports_with_extra_blocked() -> None:
    """Simulate a base install by making the extra's modules unimportable."""
    script = """
import sys

BLOCKED = %r

class Blocker:
    def find_module(self, name, path=None):
        if name.split('.')[0] in BLOCKED:
            return self
        return None
    def load_module(self, name):
        raise ImportError(f"blocked for test: {name}")
    def find_spec(self, name, path=None, target=None):
        if name.split('.')[0] in BLOCKED:
            raise ImportError(f"blocked for test: {name}")
        return None

for mod in list(sys.modules):
    if mod.split('.')[0] in BLOCKED:
        del sys.modules[mod]
sys.meta_path.insert(0, Blocker())

from sift.runtime import analysis, case_builder, primary, verifier  # noqa: F401
from sift.render import github_check, github_summary  # noqa: F401
from sift.cli import analyze_commit, analyze_pr  # noqa: F401

# The provenance evidence hook must degrade, not raise.
result = case_builder.build_domain_provenance_evidence(
    __import__('pathlib').Path('.'),
    commit_payload={'author_email': 'someone@example-corp.net'},
    author_identity_history={},
)
assert result is None, f"expected None when disabled, got {result!r}"

import os
os.environ['SIFT_DOMAIN_PROVENANCE'] = '1'
result = case_builder.build_domain_provenance_evidence(
    __import__('pathlib').Path('.'),
    commit_payload={'author_email': 'someone@example-corp.net'},
    author_identity_history={},
)
assert isinstance(result, dict), f"expected a dict, got {result!r}"
assert result.get('status') == 'extra_not_installed', result
assert result.get('role') == 'unavailable', result
print('base-install pipeline imports and degrades correctly')
""" % (EXTRA_MODULES,)

    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (
        "pipeline must import with the provenance extra unavailable:\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr[-2000:]}"
    )
    print(f"  ok  {proc.stdout.strip()}")


def test_cli_entrypoint_guards_its_import() -> None:
    """`sift-domain` is installed unconditionally, so it must not raise raw."""
    path = ROOT / "sift" / "cli" / "domain_provenance.py"
    assert path.is_file(), "sift/cli/domain_provenance.py is missing"
    for name in _module_scope_imports(path):
        bare = name.lstrip(".").split(".")[0]
        assert bare not in EXTRA_MODULES, (
            f"{path.name} imports {name} at module scope; a base-install user "
            f"running `sift-domain` would get a raw ModuleNotFoundError"
        )
        assert not name.lstrip(".").startswith("sift.provenance"), (
            f"{path.name} imports {name} at module scope; import it inside main() "
            f"and catch ImportError instead"
        )
    print("  ok  sift-domain defers its provenance imports into main()")


def main() -> int:
    tests = [
        test_core_packages_do_not_import_provenance_at_module_scope,
        test_pipeline_imports_with_extra_blocked,
        test_cli_entrypoint_guards_its_import,
    ]
    failed = 0
    print("provenance extra isolation: does a base install still work?\n")
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}\n        {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print()
    print("FAILED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
