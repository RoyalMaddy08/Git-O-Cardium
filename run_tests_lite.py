"""Dependency-free runner (pytest-compatible tests use plain asserts). Prefer `pytest`."""
import importlib, pathlib, sys, traceback
sys.path.insert(0, ".")
fails = n = 0
for f in sorted(pathlib.Path("tests").glob("test_*.py")):
    mod = importlib.import_module(f"tests.{f.stem}")
    for name in dir(mod):
        if name.startswith("test_"):
            n += 1
            try:
                getattr(mod, name)(); print("PASS", f.stem, name)
            except Exception:
                fails += 1; print("FAIL", f.stem, name); traceback.print_exc()
print(f"\n{n - fails}/{n} passed"); sys.exit(1 if fails else 0)
