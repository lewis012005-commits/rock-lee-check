"""Concrete checks — the catalogue tier.

Each is a known bug class with a CWE reference and its own self-tests. These are
DETECTION checks for defensive hardening: they flag defects in your own code so
they can be fixed. None generate, deliver, or weaponise anything.

To add a class: write the detector, write self-tests that PROVE it (a positive
it must fire on, a negative it must not), append it to ALL_CHECKS, and the
harness refuses to trust it until it passes. This is where the catalogue
(CWE/CVE) gets turned into checks — each ingested pattern earns its place by
becoming falsifiable, exactly as a relay finding does.
"""
import ast
from .check import Check, Finding, SelfTest


def _parse(source):
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


# --- CWE-95: eval/exec on data --------------------------------------------
def _detect_eval(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ("eval", "exec"):
            out.append(Finding("eval-exec", "CWE-95",
                f"`{node.func.id}()` runs its argument as code; never on attacker-influenced input",
                getattr(node, "lineno", None)))
    return out

eval_exec = Check(
    id="eval-exec", cwe="CWE-95",
    description="eval()/exec() call — arbitrary code execution if the argument is attacker-influenced",
    detect=_detect_eval,
    self_test=SelfTest(
        positives=("x = eval(user_input)\n", "exec(payload)\n"),
        negatives=("import ast\nx = ast.literal_eval(s)\n", "import json\nx = json.loads(s)\n"),
    ),
)


# --- CWE-1188: mutable default argument (execution-grounded) ---------------
def _detect_mutable_default(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.args.defaults:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    kind = type(d).__name__.lower()
                    out.append(Finding("mutable-default", "CWE-1188",
                        f"mutable default ({kind}) in `{node.name}` is one object shared by every call",
                        getattr(node, "lineno", None)))
    return out

def _confirm_mutable_default(source):
    """Execution-grounded: define the function and call it twice; if the second
    call sees the first call's mutation, the bug is REAL — reproduced, not
    guessed. Length is snapshotted as an int before the second call, because the
    leaked object is aliased across both returns."""
    tree = _parse(source)
    if tree is None:
        return (False, "")
    ns = {}
    try:
        exec(compile(tree, "<corpus>", "exec"), ns)
    except Exception as e:
        return (False, f"could not execute: {e}")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if not any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in node.args.defaults):
                continue
            fn = ns.get(node.name)
            if not callable(fn):
                continue
            try:
                r1 = fn("a") if len(node.args.args) >= 1 else fn()
                n1 = len(r1)                       # snapshot as int BEFORE the aliased second call
                r2 = fn("b") if len(node.args.args) >= 1 else fn()
                n2 = len(r2)
                if n2 > n1:
                    return (True, f"call 1 -> length {n1}; call 2 -> length {n2} "
                                  f"(the default object persisted and accumulated across calls)")
            except Exception:
                continue
    return (False, "detected statically; execution did not reproduce")

mutable_default = Check(
    id="mutable-default", cwe="CWE-1188",
    description="Mutable default argument — one object shared by every call; a classic silent state-leak",
    detect=_detect_mutable_default, confirm=_confirm_mutable_default,
    self_test=SelfTest(
        positives=("def add(x, items=[]):\n    items.append(x)\n    return items\n",),
        negatives=("def add(x, items=None):\n    if items is None:\n        items = []\n    items.append(x)\n    return items\n",),
    ),
)


# --- CWE-396: bare except --------------------------------------------------
def _detect_bare_except(source):
    tree = _parse(source)
    if tree is None:
        return []
    return [Finding("bare-except", "CWE-396",
            "bare `except:` swallows everything, including KeyboardInterrupt and SystemExit",
            getattr(n, "lineno", None))
            for n in ast.walk(tree)
            if isinstance(n, ast.ExceptHandler) and n.type is None]

bare_except = Check(
    id="bare-except", cwe="CWE-396",
    description="Bare except — catches and hides all exceptions, including ones that must propagate",
    detect=_detect_bare_except,
    self_test=SelfTest(
        positives=("try:\n    f()\nexcept:\n    pass\n",),
        negatives=("try:\n    f()\nexcept ValueError:\n    handle()\n",),
    ),
)


# --- CWE-617: assert used as a runtime/security check ----------------------
def _detect_assert(source):
    tree = _parse(source)
    if tree is None:
        return []
    return [Finding("assert-validation", "CWE-617",
            "`assert` is stripped under `python -O`; never use it to enforce a runtime or security check",
            getattr(n, "lineno", None))
            for n in ast.walk(tree) if isinstance(n, ast.Assert)]

assert_validation = Check(
    id="assert-validation", cwe="CWE-617",
    description="assert as a runtime check — vanishes under python -O, so the check silently disappears in prod",
    detect=_detect_assert,
    self_test=SelfTest(
        positives=("def process(user):\n    assert user.is_admin\n    do_admin()\n",),
        negatives=("def process(user):\n    if not user.is_admin:\n        raise PermissionError\n    do_admin()\n",),
    ),
)


# --- CWE-89: SQL built by string interpolation -----------------------------
_SQL_KW = ("select ", "insert ", "update ", "delete ", "drop ", " from ", " where ", " values")
def _looks_like_sql(s):
    low = " " + s.lower() + " "
    return sum(kw in low for kw in _SQL_KW) >= 2

def _detect_sql(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []
    for node in ast.walk(tree):
        ln = getattr(node, "lineno", None)
        if isinstance(node, ast.JoinedStr):  # f-string
            lit = "".join(v.value for v in node.values
                          if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if any(isinstance(v, ast.FormattedValue) for v in node.values) and _looks_like_sql(lit):
                out.append(Finding("sql-injection", "CWE-89",
                    "SQL built with an f-string — use a parameterised query", ln))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)) \
                and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) \
                and _looks_like_sql(node.left.value):
            out.append(Finding("sql-injection", "CWE-89",
                "SQL built with string %/+ concatenation — use a parameterised query", ln))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "format" and isinstance(node.func.value, ast.Constant) \
                and isinstance(node.func.value.value, str) and _looks_like_sql(node.func.value.value):
            out.append(Finding("sql-injection", "CWE-89",
                "SQL built with str.format() — use a parameterised query", ln))
    return out

sql_injection = Check(
    id="sql-injection", cwe="CWE-89",
    description="SQL assembled by string interpolation/concatenation — the classic injection vector",
    detect=_detect_sql,
    self_test=SelfTest(
        positives=('q = f"SELECT * FROM users WHERE id = {uid}"\n',
                   'q = "SELECT * FROM t WHERE x = %s" % val\n'),
        negatives=('cur.execute("SELECT * FROM users WHERE id = ?", (uid,))\n',),
    ),
)


# --- CWE-798: hardcoded secret ---------------------------------------------
_SECRET_NAMES = ("password", "passwd", "secret", "api_key", "apikey", "token", "private_key")
def _detect_secret(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.lower() in _SECRET_NAMES \
                        and isinstance(node.value, ast.Constant) \
                        and isinstance(node.value.value, str) and len(node.value.value) >= 6:
                    out.append(Finding("hardcoded-secret", "CWE-798",
                        f"`{t.id}` holds a hardcoded literal; load from env or a secrets manager",
                        getattr(node, "lineno", None)))
    return out

hardcoded_secret = Check(
    id="hardcoded-secret", cwe="CWE-798",
    description="Hardcoded credential — a secret literal in source; load from environment/secrets manager",
    detect=_detect_secret,
    self_test=SelfTest(
        positives=('API_KEY = "sk-live-9f8a7b6c5d4e"\n',),
        negatives=('import os\nAPI_KEY = os.environ["API_KEY"]\n',),
    ),
)


ALL_CHECKS = [eval_exec, mutable_default, bare_except, assert_validation, sql_injection, hardcoded_secret]
