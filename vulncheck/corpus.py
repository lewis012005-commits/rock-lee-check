"""Labelled ground-truth corpus — the tool's meta-test.

Run every check against code whose answers are already known, and measure the
tool's own false positives (fired on clean) and false negatives (missed a real
bug). This is the floor the 'who checks the checker' regress bottoms out on:
the samples either trip a check or they don't, and the answer is a fact.

These are INERT defect fixtures — code that CONTAINS a defect, not code that
does harm. A string-concatenated SQL query is the injection ANTI-PATTERN; it
connects to nothing and attacks nothing. Same category as a linter's fixtures.

HONEST LIMIT, and what it bought: `test_with_assert` is a legitimate assert in
a test, labelled clean. The assert check originally fired on it — a real false
positive that the meta-test reported instead of a rigged 100%. That exposure is
what drove the scope-narrowing of `assert-validation` (test scopes are the
legitimate home of asserts, so they are skipped). The sample stays here as a
permanent regression negative: if the check ever widens back, this corpus entry
catches it. That is the loop working: the tool caught a weakness in one of its
own checks, the check was narrowed, and the evidence became a regression test.
"""

VULNERABLE = [
    {"name": "eval_input",      "cwe": "CWE-95",   "source": "user_input = get()\nresult = eval(user_input)\n"},
    {"name": "mutable_default", "cwe": "CWE-1188", "source": "def collect(x, acc=[]):\n    acc.append(x)\n    return acc\n"},
    {"name": "bare_except",     "cwe": "CWE-396",  "source": "try:\n    risky()\nexcept:\n    pass\n"},
    {"name": "assert_auth",     "cwe": "CWE-617",  "source": "def admin_action(user):\n    assert user.is_admin\n    wipe()\n"},
    {"name": "sql_fstring",     "cwe": "CWE-89",   "source": 'def find(uid):\n    q = f"SELECT * FROM users WHERE id = {uid}"\n    return q\n'},
    {"name": "hardcoded_key",   "cwe": "CWE-798",  "source": 'SECRET = "hunter2-prod-key-abc123"\n'},
    # catalogue tier, batch 2
    {"name": "shell_fstring",   "cwe": "CWE-78",   "source": 'import subprocess\ndef ping(host):\n    return subprocess.run(f"ping -c 1 {host}", shell=True)\n'},
    {"name": "pickle_cookie",   "cwe": "CWE-502",  "source": "import pickle\ndef restore_session(cookie):\n    return pickle.loads(cookie)\n"},
    {"name": "md5_password",    "cwe": "CWE-916",  "source": "import hashlib\ndef register(username, password):\n    hashed = hashlib.md5(password.encode()).hexdigest()\n    db.save(username, hashed)\n"},
    {"name": "random_token",    "cwe": "CWE-330",  "source": 'import random\ndef issue_reset_token():\n    token = "".join(random.choices("abcdef0123456789", k=32))\n    return token\n'},
    {"name": "verify_false",    "cwe": "CWE-295",  "source": "import requests\ndef fetch_status(url):\n    return requests.get(url, timeout=5, verify=False).status_code\n"},
    {"name": "mktemp_race",     "cwe": "CWE-377",  "source": 'import tempfile\ndef export(rows):\n    path = tempfile.mktemp(suffix=".csv")\n    with open(path, "w") as f:\n        f.write(rows)\n    return path\n'},
    {"name": "chmod_777",       "cwe": "CWE-732",  "source": "import os\ndef share(path):\n    os.chmod(path, 0o777)\n    return path\n"},
    {"name": "token_eq",        "cwe": "CWE-208",  "source": "def verify(request, expected_token):\n    if request.token == expected_token:\n        return grant()\n    return deny()\n"},
    {"name": "flask_debug",     "cwe": "CWE-489",  "source": 'from flask import Flask\napp = Flask(__name__)\nif __name__ == "__main__":\n    app.run(debug=True)\n'},
    {"name": "silent_oserror",  "cwe": "CWE-390",  "source": "def load_settings(path):\n    try:\n        return read(path)\n    except OSError:\n        pass\n"},
    # batch 2 breadth probes — NEW syntactic shapes per class, not clones of the
    # samples above: exec (not eval), Popen+concat (not run+f-string), sha1 (not
    # md5), yaml.load (not pickle), a bare == on two signature names.
    {"name": "exec_config",     "cwe": "CWE-95",   "source": 'code = open("cfg.py").read()\nexec(code)\n'},
    {"name": "popen_concat",    "cwe": "CWE-78",   "source": 'import subprocess\ndef cat(fname):\n    return subprocess.Popen("cat " + fname, shell=True)\n'},
    {"name": "sha1_token",      "cwe": "CWE-916",  "source": "import hashlib\ndef store(session_token):\n    return hashlib.sha1(session_token.encode()).hexdigest()\n"},
    {"name": "yaml_load",       "cwe": "CWE-502",  "source": 'import yaml\ndef load_cfg(path):\n    return yaml.load(open(path))\n'},
    {"name": "sig_compare",     "cwe": "CWE-208",  "source": "def check(provided_signature, expected_signature):\n    return provided_signature == expected_signature\n"},
]

CLEAN = [
    {"name": "safe_eval",        "source": "import ast\nresult = ast.literal_eval(user_input)\n"},
    {"name": "safe_default",     "source": "def collect(x, acc=None):\n    if acc is None:\n        acc = []\n    acc.append(x)\n    return acc\n"},
    {"name": "typed_except",     "source": "try:\n    risky()\nexcept (ValueError, KeyError) as e:\n    log(e)\n"},
    {"name": "explicit_check",   "source": "def admin_action(user):\n    if not user.is_admin:\n        raise PermissionError\n    wipe()\n"},
    {"name": "param_sql",        "source": 'def find(uid):\n    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))\n'},
    {"name": "env_secret",       "source": 'import os\nSECRET = os.environ["SECRET"]\n'},
    {"name": "test_with_assert", "source": "def test_add():\n    assert add(2, 2) == 4\n"},  # legit assert -> exposes assert-check FP
    # catalogue tier, batch 2 — the clean twin of each new vulnerable sample
    {"name": "shell_argv",       "source": 'import subprocess\ndef ping(host):\n    return subprocess.run(["ping", "-c", "1", host], check=True)\n'},
    {"name": "json_cookie",      "source": "import json\ndef restore_session(cookie):\n    return json.loads(cookie)\n"},
    {"name": "md5_cache_key",    "source": "import hashlib\ndef cache_key(url, params):\n    raw = url + repr(params)\n    return hashlib.md5(raw.encode()).hexdigest()\n"},
    {"name": "secrets_token",    "source": "import secrets\ndef issue_reset_token():\n    return secrets.token_urlsafe(32)\n"},
    {"name": "verify_bundle",    "source": "import requests\ndef fetch_status(url, ca_bundle):\n    return requests.get(url, timeout=5, verify=ca_bundle).status_code\n"},
    {"name": "mkstemp_safe",     "source": 'import os, tempfile\ndef export(rows):\n    fd, path = tempfile.mkstemp(suffix=".csv")\n    with os.fdopen(fd, "w") as f:\n        f.write(rows)\n    return path\n'},
    {"name": "chmod_644",        "source": "import os\ndef share(path):\n    os.chmod(path, 0o644)\n    return path\n"},
    {"name": "compare_digest",   "source": "import hmac\ndef verify(request, expected_token):\n    if hmac.compare_digest(request.token, expected_token):\n        return grant()\n    return deny()\n"},
    {"name": "flask_env_debug",  "source": 'import os\nfrom flask import Flask\napp = Flask(__name__)\nif __name__ == "__main__":\n    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")\n'},
    {"name": "suppress_oserror", "source": "import contextlib\ndef remove_temp(path):\n    with contextlib.suppress(FileNotFoundError):\n        unlink(path)\n"},
    # batch 2 breadth probes — the RIGHT idiom for each new vulnerable shape,
    # exercising the near-miss boundary each narrowing draws.
    {"name": "argv_shell_false", "source": "import subprocess\ndef cat(fname):\n    return subprocess.run([\"cat\", fname], shell=False)\n"},
    {"name": "ssl_default_ctx",  "source": "import ssl\nctx = ssl.create_default_context()\n"},
    {"name": "secrets_choice",   "source": 'import secrets\ntoken = "".join(secrets.choice(CHARS) for _ in range(32))\n'},
    {"name": "safe_load_all",    "source": "import yaml\ndef load_all(stream):\n    return list(yaml.safe_load_all(stream))\n"},
    {"name": "chmod_700",        "source": "import os\ndef lock_down(path):\n    os.chmod(path, 0o700)\n"},
]
