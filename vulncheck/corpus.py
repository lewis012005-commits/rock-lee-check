"""Labelled ground-truth corpus — the tool's meta-test.

Run every check against code whose answers are already known, and measure the
tool's own false positives (fired on clean) and false negatives (missed a real
bug). This is the floor the 'who checks the checker' regress bottoms out on:
the samples either trip a check or they don't, and the answer is a fact.

These are INERT defect fixtures — code that CONTAINS a defect, not code that
does harm. A string-concatenated SQL query is the injection ANTI-PATTERN; it
connects to nothing and attacks nothing. Same category as a linter's fixtures.

HONEST LIMIT baked into the corpus: `test_with_assert` is a legitimate assert
in a test, labelled clean. The assert check will fire on it — a real false
positive — so the meta-test reports the tool's own imprecision instead of a
rigged 100%. That is the tool catching a weakness in one of its own checks.
"""

VULNERABLE = [
    {"name": "eval_input",      "cwe": "CWE-95",   "source": "user_input = get()\nresult = eval(user_input)\n"},
    {"name": "mutable_default", "cwe": "CWE-1188", "source": "def collect(x, acc=[]):\n    acc.append(x)\n    return acc\n"},
    {"name": "bare_except",     "cwe": "CWE-396",  "source": "try:\n    risky()\nexcept:\n    pass\n"},
    {"name": "assert_auth",     "cwe": "CWE-617",  "source": "def admin_action(user):\n    assert user.is_admin\n    wipe()\n"},
    {"name": "sql_fstring",     "cwe": "CWE-89",   "source": 'def find(uid):\n    q = f"SELECT * FROM users WHERE id = {uid}"\n    return q\n'},
    {"name": "hardcoded_key",   "cwe": "CWE-798",  "source": 'SECRET = "hunter2-prod-key-abc123"\n'},
]

CLEAN = [
    {"name": "safe_eval",        "source": "import ast\nresult = ast.literal_eval(user_input)\n"},
    {"name": "safe_default",     "source": "def collect(x, acc=None):\n    if acc is None:\n        acc = []\n    acc.append(x)\n    return acc\n"},
    {"name": "typed_except",     "source": "try:\n    risky()\nexcept (ValueError, KeyError) as e:\n    log(e)\n"},
    {"name": "explicit_check",   "source": "def admin_action(user):\n    if not user.is_admin:\n        raise PermissionError\n    wipe()\n"},
    {"name": "param_sql",        "source": 'def find(uid):\n    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))\n'},
    {"name": "env_secret",       "source": 'import os\nSECRET = os.environ["SECRET"]\n'},
    {"name": "test_with_assert", "source": "def test_add():\n    assert add(2, 2) == 4\n"},  # legit assert -> exposes assert-check FP
]
