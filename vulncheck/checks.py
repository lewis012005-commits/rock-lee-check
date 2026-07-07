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
import re
from .check import Check, Finding, SelfTest


def _parse(source):
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _ident_words(name):
    """Split an identifier into lowercased whole words (snake_case + camelCase),
    plus adjacent pairs joined so `api_key`/`apiKey` also yield `apikey`. Used by
    the name-context checks below so a keyword must be a WHOLE word, not a
    substring — `author_email` is not `auth`, `tokens` is not `token`. Substring
    matching was the single biggest false-positive source the adversary corpus
    surfaced."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    segs = [s.lower() for s in re.split(r"[^A-Za-z0-9]+", spaced) if s]
    return set(segs) | {a + b for a, b in zip(segs, segs[1:])}


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
# Scope-narrowed after the corpus meta-test exposed a false positive on
# `test_with_assert`: asserts are the LEGITIMATE idiom inside tests, so the
# detector skips test scopes (functions named test*, classes named Test*) and
# the scan runner skips test files entirely via `skip_path`.
def _detect_assert(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []

    def visit(node, in_test):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            in_test = in_test or node.name.startswith("test")
        elif isinstance(node, ast.ClassDef):
            in_test = in_test or node.name.startswith("Test")
        if isinstance(node, ast.Assert) and not in_test:
            out.append(Finding("assert-validation", "CWE-617",
                "`assert` is stripped under `python -O`; never use it to enforce a runtime or security check",
                getattr(node, "lineno", None)))
        for child in ast.iter_child_nodes(node):
            visit(child, in_test)

    visit(tree, False)
    return out

def _is_test_path(path):
    parts = path.replace("\\", "/").split("/")
    base = parts[-1]
    return "tests" in parts or "test" in parts \
        or base.startswith("test_") or base.endswith("_test.py")

assert_validation = Check(
    id="assert-validation", cwe="CWE-617",
    description="assert as a runtime check — vanishes under python -O, so the check silently disappears in prod",
    detect=_detect_assert, skip_path=_is_test_path,
    self_test=SelfTest(
        positives=("def process(user):\n    assert user.is_admin\n    do_admin()\n",
                   "assert config.is_valid\n"),
        negatives=("def process(user):\n    if not user.is_admin:\n        raise PermissionError\n    do_admin()\n",
                   "def test_add():\n    assert add(2, 2) == 4\n",
                   "class TestMath:\n    def helper(self):\n        assert self.ready\n"),
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


# ===========================================================================
# CATALOGUE TIER, BATCH 2 — ten classes authored in parallel, then each
# NARROWED against an adversary that reproduced (by execution) a realistic
# clean snippet the first cut fired on. Every such snippet is baked in below
# as a self-test NEGATIVE: the check does not run until it stays silent on the
# idiom that fooled it. Where a clean idiom is syntactically indistinguishable
# from the bug without data-flow (a bare variable command, a stored-password
# ==), recall is surrendered honestly and recorded as an accepted miss — never
# faked. Precision over recall, because a checker that cries wolf gets muted.
# ===========================================================================


# --- CWE-78: OS command built from data and run through a shell -------------
# NARROWED: the first cut fired on any bare-variable command (indistinguishable
# from a constant command in a named variable without data-flow), on
# shlex.quote()-sanitised f-strings, and on numeric `% int(n)` formatting. Now
# a command counts as "built from data" only when it interpolates an operand
# that is NOT wrapped in a shell-neutralising call (shlex.quote/shlex.join/int).
# A bare-variable command is an accepted miss, locked in as a negative.
def _ss_is_sanitized(node):
    """int() coerces away shell metacharacters; shlex.quote()/shlex.join()
    escape for the shell — an interpolation wrapped in one of these is safe."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name):
        return f.id in ("int", "quote")
    if isinstance(f, ast.Attribute):
        return f.attr in ("quote", "join")
    return False

def _ss_dynamic_cmd(node):
    if isinstance(node, ast.JoinedStr):  # f-string: any UNSANITISED interpolation
        return any(isinstance(v, ast.FormattedValue) and not _ss_is_sanitized(v.value)
                   for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        def unsafe(x):
            if isinstance(x, ast.BinOp) and isinstance(x.op, ast.Add):
                return unsafe(x.left) or unsafe(x.right)
            if isinstance(x, ast.Constant) and isinstance(x.value, str):
                return False
            return not _ss_is_sanitized(x)
        return unsafe(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        rhs = node.right
        parts = rhs.elts if isinstance(rhs, ast.Tuple) else [rhs]
        return any(not isinstance(p, ast.Constant) and not _ss_is_sanitized(p) for p in parts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        args = list(node.args) + [kw.value for kw in node.keywords]
        return any(not _ss_is_sanitized(a) for a in args)
    return False

def _detect_subprocess_shell(source):
    tree = _parse(source)
    if tree is None:
        return []
    run_fns = ("run", "call", "check_call", "check_output", "Popen")
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else None)
        ln = getattr(node, "lineno", None)
        if name in run_fns:
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                             and kw.value.value is True for kw in node.keywords)
            cmd = node.args[0] if node.args else next(
                (kw.value for kw in node.keywords if kw.arg == "args"), None)
            if shell_true and cmd is not None and _ss_dynamic_cmd(cmd):
                out.append(Finding("subprocess-shell", "CWE-78",
                    f"`{name}(..., shell=True)` with a command built from unescaped data — use a list argv without a shell",
                    ln))
        elif name in ("system", "popen") and isinstance(fn, ast.Attribute) \
                and isinstance(fn.value, ast.Name) and fn.value.id == "os":
            if node.args and _ss_dynamic_cmd(node.args[0]):
                out.append(Finding("subprocess-shell", "CWE-78",
                    f"`os.{name}()` with a command built from unescaped data — use subprocess with a list argv",
                    ln))
    return out

subprocess_shell = Check(
    id="subprocess-shell", cwe="CWE-78",
    description="OS command built from unescaped data and run through a shell — the classic command injection vector",
    detect=_detect_subprocess_shell,
    self_test=SelfTest(
        positives=('import subprocess\nsubprocess.run(f"ping -c 1 {host}", shell=True)\n',
                   'import os\nos.system("tar czf backup.tgz " + path)\n',
                   'import subprocess\nsubprocess.run("rm -rf " + target, shell=True)\n',
                   'import os\nos.popen("grep %s app.log" % pattern)\n'),
        negatives=('import subprocess\nsubprocess.run("ls -la", shell=True)\n',
                   'import subprocess\nsubprocess.run(["ping", "-c", "1", host], check=True)\n',
                   'import os\nos.system("make clean")\n',
                   'import platform\nname = platform.system()\n',
                   # adversary FPs, now locked in:
                   'import subprocess\nsubprocess.run(CLEANUP_CMD, shell=True)\n',          # constant in a named var
                   'import subprocess\nsubprocess.check_output(cmd, shell=True)\n',         # bare variable (accepted miss)
                   'import shlex, subprocess\nsubprocess.check_output(f"grep {shlex.quote(p)} log", shell=True)\n',
                   'import os\nos.system("shutdown -r +%d" % int(minutes))\n'),
    ),
)


# --- CWE-502: deserialization of untrusted data -----------------------------
# NARROWED: `yaml.load` is attributed to PyYAML only when the file actually
# `import yaml` — ruamel.yaml's documented `yaml = YAML(); yaml.load(fh)` (a safe
# round-trip loader) no longer trips it. A `**kwargs` forward is treated as an
# unknown-but-possibly-safe Loader and left silent.
_UNSAFE_YAML_LOADERS = ("Loader", "UnsafeLoader", "FullLoader",
                        "CLoader", "CUnsafeLoader", "CFullLoader")

def _ud_unsafe_yaml_loader(call):
    if any(kw.arg is None for kw in call.keywords):
        return False  # **kwargs may inject a safe Loader we cannot see -> don't assume unsafe
    loader = None
    if len(call.args) >= 2:
        loader = call.args[1]
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader = kw.value
    if loader is None:
        return True
    if isinstance(loader, ast.Attribute):
        return loader.attr in _UNSAFE_YAML_LOADERS
    if isinstance(loader, ast.Name):
        return loader.id in _UNSAFE_YAML_LOADERS
    return False

def _detect_deserialization(source):
    tree = _parse(source)
    if tree is None:
        return []
    has_yaml_import = any(isinstance(n, ast.Import) and any(a.name == "yaml" for a in n.names)
                          for n in ast.walk(tree))
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)):
            continue
        mod, attr = node.func.value.id, node.func.attr
        ln = getattr(node, "lineno", None)
        if mod in ("pickle", "cPickle", "_pickle") and attr in ("load", "loads"):
            out.append(Finding("unsafe-deserialization", "CWE-502",
                f"`{mod}.{attr}()` executes arbitrary code while deserialising; never feed it untrusted bytes",
                ln))
        elif mod == "marshal" and attr in ("load", "loads"):
            out.append(Finding("unsafe-deserialization", "CWE-502",
                f"`marshal.{attr}()` is not hardened against malicious data; use json for untrusted input",
                ln))
        elif mod == "yaml" and has_yaml_import and attr in ("load", "load_all") \
                and _ud_unsafe_yaml_loader(node):
            out.append(Finding("unsafe-deserialization", "CWE-502",
                f"`yaml.{attr}()` without a safe Loader can construct arbitrary objects; use yaml.safe_load",
                ln))
    return out

unsafe_deserialization = Check(
    id="unsafe-deserialization", cwe="CWE-502",
    description="pickle/marshal/unsafe yaml.load — deserialising untrusted data can execute arbitrary code",
    detect=_detect_deserialization,
    self_test=SelfTest(
        positives=("import pickle\nobj = pickle.loads(blob)\n",
                   "import yaml\ncfg = yaml.load(stream)\n",
                   "import yaml\ncfg = yaml.load(stream, Loader=yaml.FullLoader)\n",
                   "import marshal\ncode = marshal.loads(raw)\n"),
        negatives=("import json\nobj = json.loads(blob)\n",
                   "import yaml\ncfg = yaml.safe_load(stream)\n",
                   "import yaml\ncfg = yaml.load(stream, Loader=yaml.SafeLoader)\n",
                   "import pickle\nblob = pickle.dumps(obj)\n",
                   # adversary FPs, now locked in:
                   "from ruamel.yaml import YAML\nyaml = YAML()\ncfg = yaml.load(fh)\n",   # ruamel round-trip loader
                   "import yaml\ndef load(text, **kw):\n    kw.setdefault('Loader', yaml.SafeLoader)\n    return yaml.load(text, **kw)\n"),
    ),
)


# --- CWE-916: password/secret hashed with a broken or fast hash ------------
# NARROWED: the name-context gate now matches WHOLE words (via _ident_words),
# not substrings. The first cut's `auth` matched author/authorized/oauth and
# `pwd` collided with print-working-directory; both are dropped/whole-worded so
# Gravatar's md5-of-author_email, cache-dir md5-of-pwd, and md5 public-key
# fingerprints stay silent. md5/sha1 for content addressing was always spared.
_WEAK_HASH_KW = ("password", "passwd", "secret", "token", "credential", "auth")

def _weak_hash_algo(call):
    """'md5'/'sha1' for hashlib.md5/sha1(...) or hashlib.new('md5'|'sha1', ...), else None."""
    f = call.func
    if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
            and f.value.id == "hashlib"):
        return None
    if f.attr in ("md5", "sha1"):
        return f.attr
    if f.attr == "new" and call.args and isinstance(call.args[0], ast.Constant) \
            and isinstance(call.args[0].value, str) \
            and call.args[0].value.lower() in ("md5", "sha1"):
        return call.args[0].value.lower()
    return None

def _weak_hash_secretish(names):
    return any(kw in _ident_words(n) for n in names for kw in _WEAK_HASH_KW)

def _detect_weak_hash(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []

    def arg_names(call):
        names = []
        for a in list(call.args) + [kw.value for kw in call.keywords]:
            for n in ast.walk(a):
                if isinstance(n, ast.Name):
                    names.append(n.id)
                elif isinstance(n, ast.Attribute):
                    names.append(n.attr)
        return names

    def usedforsecurity(call):
        for kw in call.keywords:
            if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant):
                return kw.value.value
        return None

    def visit(node, funcs, targets):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs = funcs + (node.name,)
        if isinstance(node, ast.Assign):
            targets = tuple(t.id if isinstance(t, ast.Name) else t.attr
                            for t in node.targets if isinstance(t, (ast.Name, ast.Attribute)))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, (ast.Name, ast.Attribute)):
            t = node.target
            targets = (t.id if isinstance(t, ast.Name) else t.attr,)
        elif isinstance(node, ast.stmt):
            targets = ()
        if isinstance(node, ast.Call):
            algo = _weak_hash_algo(node)
            if algo is not None:
                ufs = usedforsecurity(node)
                if ufs is not False and (ufs is True or _weak_hash_secretish(
                        arg_names(node) + list(funcs) + list(targets))):
                    out.append(Finding("weak-hash-for-secret", "CWE-916",
                        f"{algo} is broken/fast — hash secrets with a slow KDF (bcrypt/scrypt/argon2)",
                        getattr(node, "lineno", None)))
        for child in ast.iter_child_nodes(node):
            visit(child, funcs, targets)

    visit(tree, (), ())
    return out

weak_hash_secret = Check(
    id="weak-hash-for-secret", cwe="CWE-916",
    description="Password/secret hashed with md5/sha1 — broken and fast; use bcrypt/scrypt/argon2",
    detect=_detect_weak_hash,
    self_test=SelfTest(
        positives=(
            'import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()\n',
            'import hashlib\ndef fingerprint_token(token):\n    return hashlib.sha1(token.encode()).hexdigest()\n',
            'import hashlib\ndigest = hashlib.new("md5", secret_bytes)\n',
            'import hashlib\nsig = hashlib.sha1(data, usedforsecurity=True).digest()\n',
        ),
        negatives=(
            'import hashlib\nchecksum = hashlib.md5(file_bytes).hexdigest()\n',
            'import hashlib\netag = hashlib.sha1(response_body).hexdigest()\n',
            'import hashlib\ntrace_id = hashlib.md5(auth_header, usedforsecurity=False).hexdigest()\n',
            'import hashlib\ndigest = hashlib.sha256(password.encode()).hexdigest()\n',
            'import hashlib\nmac = hashlib.new("sha256", token_bytes)\n',
            # adversary FPs, now locked in (whole-word gate spares them):
            'import hashlib\ndef gravatar_url(author_email):\n    return hashlib.md5(author_email.strip().encode()).hexdigest()\n',
            'import hashlib, os\npwd = os.getcwd()\ncache_dir = hashlib.md5(pwd.encode()).hexdigest()[:12]\n',
            'import hashlib\ndef fingerprint_authorized_key(key_blob):\n    return hashlib.md5(key_blob).hexdigest()\n',
        ),
    ),
)


# --- CWE-330: security token from the non-crypto `random` module ------------
# NARROWED: the first cut fired on EVERY PRNG call inside any secret-named
# function (retry-jitter in refresh_access_token), and on bare `key`/plural
# `tokens`. Now: (a) the function-name path fires only on PRNG inside a RETURN
# value, so jitter passed to time.sleep() is spared; (b) names match on whole
# words, dropping bare `key` (dict keys) and `session` (session_length), while
# `session_id` still matches via the joined-word form.
_RNG_FUNCS = ("random", "randint", "randrange", "choice", "choices",
              "sample", "getrandbits", "uniform", "randbytes")
_RNG_SECRET_KW = ("token", "secret", "password", "passwd", "nonce", "otp",
                  "salt", "apikey", "sessionid", "sessiontoken", "sessionkey")

def _rt_secretish(name):
    return any(kw in _ident_words(name) for kw in _RNG_SECRET_KW)

def _detect_insecure_random(source):
    tree = _parse(source)
    if tree is None:
        return []
    aliases = {}  # `from random import getrandbits as grb` -> {"grb": "getrandbits"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "random":
            for a in node.names:
                if a.name in _RNG_FUNCS:
                    aliases[a.asname or a.name] = a.name

    def rng_call(node):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                    and f.value.id == "random" and f.attr in _RNG_FUNCS:
                return f.attr
            if isinstance(f, ast.Name) and f.id in aliases:
                return aliases[f.id]
        return None

    out, seen = [], set()

    def flag(call, fname):
        if id(call) not in seen:
            seen.add(id(call))
            out.append(Finding("insecure-random-token", "CWE-330",
                f"`random.{fname}()` is not cryptographically secure; use the `secrets` module for tokens and keys",
                getattr(call, "lineno", None)))

    def scan(value):
        for sub in ast.walk(value):
            fn = rng_call(sub)
            if fn:
                flag(sub, fn)

    def visit(node, fn_name, in_test):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            in_test = in_test or node.name.startswith("test")  # random test data is legitimate
            fn_name = node.name
        elif isinstance(node, ast.ClassDef):
            in_test = in_test or node.name.startswith("Test")
        if not in_test:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [t.id if isinstance(t, ast.Name) else t.attr
                         for t in targets if isinstance(t, (ast.Name, ast.Attribute))]
                if any(_rt_secretish(n) for n in names):
                    scan(node.value)
            elif isinstance(node, ast.Return) and node.value is not None \
                    and fn_name and _rt_secretish(fn_name):
                scan(node.value)
        for child in ast.iter_child_nodes(node):
            visit(child, fn_name, in_test)

    visit(tree, None, False)
    return out

insecure_random_token = Check(
    id="insecure-random-token", cwe="CWE-330",
    description="Security token from the `random` module — Mersenne Twister output is predictable; use `secrets`",
    detect=_detect_insecure_random,
    self_test=SelfTest(
        positives=(
            "import random\ntoken = random.randint(0, 999999)\n",
            'import random\nsession_id = "".join(random.choices(ALPHABET, k=32))\n',
            'import random\ndef generate_api_key():\n    return "".join(random.choice(CHARS) for _ in range(20))\n',
            "from random import getrandbits\nnonce = getrandbits(64)\n",
        ),
        negatives=(
            "import random\nsample = random.sample(population, 10)\n",
            "import secrets\ntoken = secrets.token_hex(32)\n",
            "users = sorted(users, key=lambda u: u.name)\n",
            "import random\nwinner = random.choice(sorted(entries, key=score))\n",
            "import random\nmonkey = random.choice(animals)\n",
            'import random\ntoken = "".join(random.SystemRandom().choice(CHARS) for _ in range(32))\n',
            "import random\ndef test_token_expiry():\n    delay = random.uniform(0, 1)\n    check(delay)\n",
            # adversary FPs, now locked in:
            "import random, time\ndef refresh_access_token(client):\n    time.sleep(min(2, 30) + random.uniform(0, 1))\n    return client.post('/token')\n",
            "import random\ndef evict_one(cache):\n    key = random.choice(list(cache))\n    del cache[key]\n",
            "import random\ndef make_sentence(vocab, length):\n    tokens = random.choices(vocab, k=length)\n    return ' '.join(tokens)\n",
        ),
    ),
)


# --- CWE-295: TLS certificate verification disabled -------------------------
# NARROWED: the `verify_mode = ssl.CERT_NONE` assignment rule was dropped — on a
# server context CERT_NONE means "don't request CLIENT certs" (the documented
# default, not a MITM hole), and the two are indistinguishable statically. That
# is an accepted miss. The unambiguous signals stay: verify=False on HTTP verbs
# and ssl._create_unverified_context(). skip_path drops test files (negative
# regression tests routinely assert verify=False is rejected).
_HTTP_VERBS = ("get", "post", "put", "delete", "patch", "head", "request")

def _detect_tls_verify(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        ln = getattr(node, "lineno", None)
        is_http = (isinstance(fn, ast.Attribute) and fn.attr in _HTTP_VERBS) \
            or (isinstance(fn, ast.Name) and fn.id == "request")
        if is_http and any(kw.arg == "verify" and isinstance(kw.value, ast.Constant)
                           and kw.value.value is False for kw in node.keywords):
            out.append(Finding("tls-verify-disabled", "CWE-295",
                "HTTP call with verify=False skips TLS certificate verification — MITM-able", ln))
        elif (isinstance(fn, ast.Attribute) and fn.attr == "_create_unverified_context") \
                or (isinstance(fn, ast.Name) and fn.id == "_create_unverified_context"):
            out.append(Finding("tls-verify-disabled", "CWE-295",
                "ssl._create_unverified_context() builds a context that never checks certificates", ln))
    return out

tls_verify_disabled = Check(
    id="tls-verify-disabled", cwe="CWE-295",
    description="TLS certificate verification disabled — verify=False or an unverified SSL context invites MITM",
    detect=_detect_tls_verify, skip_path=_is_test_path,
    self_test=SelfTest(
        positives=("import requests\nr = requests.get(url, verify=False)\n",
                   'resp = session.post("https://api.internal", data=body, verify=False)\n',
                   "import ssl\nctx = ssl._create_unverified_context()\n"),
        negatives=("import requests\nr = requests.get(url, verify=True)\n",
                   'r = requests.get(url, verify="/etc/ssl/certs/ca.pem")\n',
                   "r = client.get(url, verify=ca_bundle)\n",
                   "schema.validate(doc, verify=False)\n",
                   "import ssl\nctx.verify_mode = ssl.CERT_REQUIRED\n",
                   # adversary FPs, now accepted misses locked in as negatives:
                   "import ssl\nctx.verify_mode = ssl.CERT_NONE\n",                  # ambiguous client/server
                   "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.verify_mode = ssl.CERT_NONE\n"),
    ),
)


# --- CWE-377: insecure temporary file ---------------------------------------
# NARROWED: exclusive-create mode "x" (O_CREAT|O_EXCL) is the CWE-377 MITIGATION
# — atomic, refuses a pre-existing/symlinked path — so it is dropped from the
# unsafe write-mode set; only "w"/"a" now fire. skip_path drops test files
# (pyfakefs patches open() to an in-memory fs, so hardcoded /tmp is safe there).
def _detect_insecure_tempfile(source):
    tree = _parse(source)
    if tree is None:
        return []
    module_names = set()   # names the tempfile module is bound to
    mktemp_names = set()   # names tempfile.mktemp itself is bound to
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "tempfile":
                    module_names.add(a.asname or a.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "tempfile":
            for a in node.names:
                if a.name == "mktemp":
                    mktemp_names.add(a.asname or a.name)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        ln = getattr(node, "lineno", None)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "mktemp" \
                and isinstance(func.value, ast.Name) and func.value.id in module_names:
            out.append(Finding("insecure-tempfile", "CWE-377",
                "`tempfile.mktemp()` returns only a name — another process can claim it first; use mkstemp/NamedTemporaryFile", ln))
        elif isinstance(func, ast.Name) and func.id in mktemp_names:
            out.append(Finding("insecure-tempfile", "CWE-377",
                "`mktemp()` returns only a name — another process can claim it first; use mkstemp/NamedTemporaryFile", ln))
        elif isinstance(func, ast.Name) and func.id == "open" and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) \
                and (node.args[0].value.startswith("/tmp/")
                     or node.args[0].value.startswith("/var/tmp/")):
            mode = None  # default mode is 'r' (a read), so no mode -> no finding
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                    and isinstance(node.args[1].value, str):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str):
                    mode = kw.value.value
            # "x" (exclusive create) is the safe idiom, not a race -> only "w"/"a" fire
            if mode is not None and set(mode) & {"w", "a"}:
                out.append(Finding("insecure-tempfile", "CWE-377",
                    "writing to a hardcoded shared-/tmp path — predictable name invites a symlink/pre-creation race; use tempfile.mkstemp", ln))
    return out

insecure_tempfile = Check(
    id="insecure-tempfile", cwe="CWE-377",
    description="Insecure temp file — mktemp() name race, or a hardcoded /tmp path opened for writing",
    detect=_detect_insecure_tempfile, skip_path=_is_test_path,
    self_test=SelfTest(
        positives=('import tempfile\npath = tempfile.mktemp(suffix=".csv")\n',
                   'from tempfile import mktemp\ncache = mktemp()\n',
                   'log = open("/tmp/app.log", "a")\n',
                   'with open("/var/tmp/report.csv", mode="w") as f:\n    f.write(row)\n'),
        negatives=('import tempfile\nfd, path = tempfile.mkstemp(suffix=".csv")\n',
                   'import tempfile\nwith tempfile.NamedTemporaryFile("w", delete=False) as f:\n    f.write(data)\n',
                   'data = open("/tmp/state.json").read()\n',
                   'import os, tempfile\npath = os.path.join(tempfile.gettempdir(), name)\nwith open(path, "w") as f:\n    f.write(data)\n',
                   'd = tmp_path_factory.mktemp("data")\n',
                   # adversary FP, now locked in: "x" is the atomic-create mitigation
                   'lock = open("/tmp/reportd.lock", "x")\n'),
    ),
)


# --- CWE-732: file permissions opened to world-writable ---------------------
# NARROWED: (a) the mode is arg[1] for os.chmod/lchmod/fchmod and arg[0] for
# Path(...).chmod — the first cut checked EVERY positional int, so os.fchmod(3,
# 0o600) flagged the file DESCRIPTOR 3 as a "mode"; (b) umask(0) is spared when
# the same function restores the mask (mask = os.umask(0); os.umask(mask) is the
# only way to READ the umask, shipped verbatim in pip).
def _ww_is_umask(call):
    f = call.func
    fname = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
    return fname == "umask"

def _detect_world_writable_chmod(source):
    tree = _parse(source)
    if tree is None:
        return []
    # umask calls inside a function that calls umask >=2 times are the
    # query/save-restore idiom, not a permanent widening -> spare them
    guarded = set()
    for fdef in ast.walk(tree):
        if isinstance(fdef, (ast.FunctionDef, ast.AsyncFunctionDef)):
            umasks = [c for c in ast.walk(fdef) if isinstance(c, ast.Call) and _ww_is_umask(c)]
            if len(umasks) >= 2:
                guarded.update(id(c) for c in umasks)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            fname = node.func.attr
        elif isinstance(node.func, ast.Name):
            fname = node.func.id
        else:
            continue
        ln = getattr(node, "lineno", None)
        if fname in ("chmod", "fchmod", "lchmod"):
            # os.chmod(path, mode) / chmod(path, mode) -> arg[1];
            # Path(...).chmod(mode) -> arg[0]. The path/fd first arg is never a mode.
            is_os_form = isinstance(node.func, ast.Name) or (
                isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os")
            mode_args = []
            if is_os_form:
                if len(node.args) >= 2:
                    mode_args.append(node.args[1])
            elif node.args:
                mode_args.append(node.args[0])
            mode_args += [kw.value for kw in node.keywords if kw.arg == "mode"]
            for a in mode_args:
                if isinstance(a, ast.Constant) and type(a.value) is int and a.value & 0o002:
                    out.append(Finding("world-writable-chmod", "CWE-732",
                        f"chmod mode {oct(a.value)} sets the world-writable bit; any local user can modify the file",
                        ln))
        elif fname == "umask" and id(node) not in guarded and len(node.args) == 1 \
                and isinstance(node.args[0], ast.Constant) \
                and type(node.args[0].value) is int and node.args[0].value == 0:
            out.append(Finding("world-writable-chmod", "CWE-732",
                "umask(0) removes all default permission masking; files created afterwards can be world-writable",
                ln))
    return out

world_writable_chmod = Check(
    id="world-writable-chmod", cwe="CWE-732",
    description="chmod to a world-writable mode (or umask(0)) — any local user can modify the file",
    detect=_detect_world_writable_chmod,
    self_test=SelfTest(
        positives=('import os\nos.chmod("app.sock", 0o777)\n',
                   "from pathlib import Path\nPath(p).chmod(0o666)\n",
                   "import os\nos.umask(0)\n"),
        negatives=("import os\nos.chmod(path, 0o644)\n",
                   "import os, stat\nos.chmod(path, stat.S_IRUSR | stat.S_IWUSR)\n",
                   "import os\nos.umask(0o077)\n",
                   "from pathlib import Path\nPath(p).chmod(0o600)\n",
                   # adversary FPs, now locked in:
                   "import os\nos.fchmod(3, 0o600)\n",                                      # arg[0]=3 is an fd, not a mode
                   "import os\ndef current_umask():\n    mask = os.umask(0)\n    os.umask(mask)\n    return mask\n"),
    ),
)


# --- CWE-208: secret compared with == (timing-unsafe) ----------------------
# NARROWED: (a) a comparison against ANY literal constant is skipped — magic
# bytes (`sig != b"PK\\x03\\x04"`), lexer tokens (`token == "("`), and status
# codes are not attacker-timed secret compares; only two non-constant operands
# count; (b) `password`/`digest` dropped from the keyword set — password-equality
# is almost always the same-request confirm-password idiom (not a stored-secret
# oracle) and `digest` is overwhelmingly a content-address, not a MAC.
_TIMING_KW = ("token", "secret", "signature", "hmac", "apikey", "csrf")

def _timing_secret_name(node):
    if isinstance(node, ast.Name):
        name = node.id
    elif isinstance(node, ast.Attribute):
        name = node.attr
    else:
        return False  # a Call operand (len(token), .hexdigest()) is not the secret's bytes
    return any(kw in _ident_words(name) for kw in _TIMING_KW)

def _detect_timing_compare(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left] + list(node.comparators)
        for op, left, right in zip(node.ops, operands, operands[1:]):
            if not isinstance(op, (ast.Eq, ast.NotEq)):
                continue  # is/in are identity/membership, not byte-by-byte compares
            if any(isinstance(s, ast.Constant) for s in (left, right)):
                continue  # comparing against a literal: not an attacker-timed secret compare
            if _timing_secret_name(left) or _timing_secret_name(right):
                out.append(Finding("timing-unsafe-compare", "CWE-208",
                    "secret compared with == leaks match progress via timing; use hmac.compare_digest",
                    getattr(node, "lineno", None)))
                break  # one finding per comparison
    return out

timing_unsafe_compare = Check(
    id="timing-unsafe-compare", cwe="CWE-208",
    description="Secret compared with == — short-circuit equality leaks match progress via timing; use hmac.compare_digest",
    detect=_detect_timing_compare,
    self_test=SelfTest(
        positives=("if token == provided:\n    grant()\n",
                   "if request.api_token != given:\n    reject()\n",
                   "if mac.hexdigest() == signature:\n    accept()\n"),
        negatives=("if response.status == 200:\n    ok()\n",
                   "if len(token) != 32:\n    reject()\n",
                   "if token == None:\n    challenge()\n",
                   "if token is None:\n    challenge()\n",
                   "import hmac\nif hmac.compare_digest(token, expected):\n    grant()\n",
                   "if tokenizer == default_tokenizer:\n    reuse()\n",
                   # adversary FPs, now locked in:
                   "if password1 != password2:\n    raise ValidationError\n",              # same-request confirm-password
                   'if signature != b"PK\\x03\\x04":\n    return False\n',                  # public magic bytes (literal)
                   'if token == "(":\n    depth += 1\n'),                                    # lexer token vs literal
    ),
)


# --- CWE-489: web app started with debug mode on ----------------------------
# NARROWED: both rules now require the file to import Flask — the first cut was
# receiver-blind and fired on the stdlib `asyncio.run(main(), debug=True)` dev-mode
# idiom (no web-debug console, no RCE). skip_path drops test files (fixtures set
# DEBUG=True to exercise debug-only branches). Env/flag-guarded debug remains an
# accepted miss (config decides at runtime).
def _fd_imports_flask(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Import) and any(a.name == "flask" or a.name.startswith("flask.")
                                             for a in n.names):
            return True
        if isinstance(n, ast.ImportFrom) and n.module \
                and (n.module == "flask" or n.module.startswith("flask.")):
            return True
    return False

def _detect_flask_debug(source):
    tree = _parse(source)
    if tree is None or not _fd_imports_flask(tree):
        return []
    out = []
    for node in ast.walk(tree):
        ln = getattr(node, "lineno", None)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is True:
                    out.append(Finding("flask-debug", "CWE-489",
                        "`.run(debug=True)` ships the Werkzeug debugger — an interactive RCE console in prod",
                        ln))
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and node.value.value is True:
            for t in node.targets:
                if isinstance(t, ast.Subscript) \
                        and ((isinstance(t.value, ast.Attribute) and t.value.attr == "config")
                             or (isinstance(t.value, ast.Name) and t.value.id == "config")) \
                        and isinstance(t.slice, ast.Constant) and t.slice.value == "DEBUG":
                    out.append(Finding("flask-debug", "CWE-489",
                        "`config['DEBUG'] = True` left in code enables debug mode in production",
                        ln))
    return out

flask_debug = Check(
    id="flask-debug", cwe="CWE-489",
    description="Web app started with debug mode on — Werkzeug's debug console is RCE if reachable",
    detect=_detect_flask_debug, skip_path=_is_test_path,
    self_test=SelfTest(
        positives=("from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n",
                   'import flask\napp = flask.Flask(__name__)\napp.run(host="0.0.0.0", debug=True)\n',
                   "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = True\n"),
        negatives=("from flask import Flask\napp = Flask(__name__)\napp.run()\n",
                   "from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)\n",
                   'import os\nfrom flask import Flask\napp = Flask(__name__)\napp.run(debug=os.environ.get("FLASK_DEBUG") == "1")\n',
                   "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = False\n",
                   "from flask import Flask\napp = Flask(__name__)\napp.config['TESTING'] = True\n",
                   # adversary FPs, now locked in (no Flask import -> not a web-debug console):
                   "import asyncio\nasyncio.run(main(), debug=True)\n",
                   "import curio\ncurio.run(main, debug=True)\n"),
    ),
)


# --- CWE-390: typed exception caught and silently discarded ----------------
# Bare `except:` + pass is bare-except's class (CWE-396), so type-None handlers
# are left to that check. NARROWED: a pass/... handler on a Try that has an
# `else:` clause is spared — the else clause is where the success path is
# handled, so the except is a structured "expected miss" (queue.get(timeout)
# poll), not a swallow. Bare `return`/`continue` swallows remain accepted misses
# (too often legitimate control flow to flag without context).
def _is_silent_stmt(stmt):
    if isinstance(stmt, ast.Pass):
        return True
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) \
        and stmt.value.value is ...

def _detect_silent_exception(source):
    tree = _parse(source)
    if tree is None:
        return []
    out = []
    try_types = (ast.Try, getattr(ast, "TryStar", ()))
    for node in ast.walk(tree):
        if not isinstance(node, try_types):
            continue
        if node.orelse:
            continue  # an else: clause handles the success path — structured, not a silent swallow
        for h in node.handlers:
            if h.type is not None and h.body and all(_is_silent_stmt(s) for s in h.body):
                try:
                    caught = ast.unparse(h.type)
                except Exception:
                    caught = "exception"
                out.append(Finding("silent-exception", "CWE-390",
                    f"`except {caught}` discards the error without handling it; if "
                    "suppression is intended, say so with `contextlib.suppress(...)`",
                    getattr(h, "lineno", None)))
    return out

silent_exception = Check(
    id="silent-exception", cwe="CWE-390",
    description="Typed exception caught and silently discarded — the error vanishes; use contextlib.suppress to make intent explicit",
    detect=_detect_silent_exception,
    self_test=SelfTest(
        positives=("try:\n    f()\nexcept ValueError:\n    pass\n",
                   "try:\n    f()\nexcept (OSError, KeyError):\n    ...\n"),
        negatives=("try:\n    f()\nexcept:\n    pass\n",  # bare handler -> bare-except's class
                   "try:\n    f()\nexcept ValueError as e:\n    log(e)\n",
                   "try:\n    f()\nexcept ValueError:\n    raise\n",
                   "try:\n    x = parse(s)\nexcept ValueError:\n    x = None\n",
                   "import contextlib\nwith contextlib.suppress(ValueError):\n    f()\n",
                   # adversary FP, now locked in: an else: clause is the handling
                   "try:\n    item = q.get(timeout=1)\nexcept Empty:\n    pass\nelse:\n    work(item)\n"),
    ),
)


ALL_CHECKS = [
    # catalogue tier, batch 1
    eval_exec, mutable_default, bare_except, assert_validation, sql_injection, hardcoded_secret,
    # catalogue tier, batch 2 (each narrowed against a reproduced adversary FP)
    subprocess_shell, unsafe_deserialization, weak_hash_secret, insecure_random_token,
    tls_verify_disabled, insecure_tempfile, world_writable_chmod, timing_unsafe_compare,
    flask_debug, silent_exception,
]
