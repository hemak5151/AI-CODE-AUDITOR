from analysis_engine.project import Project
from analysis_engine.security.deprecated import find_deprecated_apis
from analysis_engine.security.secrets import find_hardcoded_secrets


def secrets(sources):
    return find_hardcoded_secrets(Project.from_sources(sources))


def deprecated(sources):
    return find_deprecated_apis(Project.from_sources(sources))


# ---------------------------------------------------------------- secrets
def test_python_secrets_by_name_and_masking():
    src = ('import os\nDB_PASSWORD = "hunter2-prod"\napi_key = os.environ["KEY"]\n'
           'token = ""\nsecret = "changeme"\nconnect(password="s3cr3t!x")\nconfig = {"client_secret": "abcd1234efgh"}\n')
    fl = secrets({"a.py": src})
    assert [f.line_number for f in fl] == [2, 6, 7]
    assert all(f.cwe_id == "CWE-798" for f in fl)
    assert all("hunter2" not in (f.evidence or "") and "s3cr3t" not in (f.evidence or "") for f in fl)


def test_javascript_secrets_and_template_literals():
    src = ("const apiKey = 'sk-live-abcdef123456';\nconst token = `${process.env.T}`;\n"
           "const cfg = { password: 'letmein99' };\nlet pwd = process.env.PWD;\n")
    assert [f.line_number for f in secrets({"a.js": src})] == [1, 3]


def test_known_token_formats_are_high_severity_even_without_a_name():
    src = 'x = "AKIAIOSFODNN7EXAMPLE"\ny = "ghp_' + "a" * 36 + '"\nz = "-----BEGIN RSA PRIVATE KEY-----"\n'
    fl = secrets({"a.py": src})
    assert [(f.line_number, f.severity.value) for f in fl] == [(1, "high"), (2, "high"), (3, "high")]
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.evidence for f in fl)


def test_no_false_positives_on_ordinary_code():
    src = ('password_field = "id_password"\n'.replace("id_password", "pw") + "def f(password):\n    return password\n"
           "token_count = 5\nmax_tokens = 10\nname = 'bob'\n")
    assert secrets({"a.py": src}) == []


# ---------------------------------------------------------------- deprecated
def test_python_deprecated_calls_modules_and_attributes():
    src = ("import imp\nimport datetime\nimport collections\nimport time\nfrom datetime import datetime as dt\n\n"
           "def f():\n    a = datetime.datetime.utcnow()\n    b = dt.utcnow()\n    c = time.clock()\n"
           "    return isinstance(a, collections.Mapping)\n\n"
           "class T:\n    def t(self):\n        self.assertEquals(1, 1)\n")
    got = sorted((f.line_number, f.message) for f in deprecated({"a.py": src}))
    assert got == [(1, "Deprecated API: imp"), (8, "Deprecated API: datetime.datetime.utcnow"),
                   (9, "Deprecated API: datetime.datetime.utcnow"), (10, "Deprecated API: time.clock"),
                   (11, "Deprecated API: collections.Mapping"), (15, "Deprecated API: assertEquals")]


def test_removed_apis_are_high_severity_and_deprecated_are_low():
    fl = deprecated({"a.py": "import imp\nimport os\nos.popen('ls')\n"})
    assert {f.message: f.severity.value for f in fl} == {"Deprecated API: imp": "high", "Deprecated API: os.popen": "low"}


def test_javascript_deprecated_apis():
    src = ("const fs = require('fs');\nconst url = require('url');\n"
           "fs.exists('x', () => {});\nconst u = url.parse(s);\nconst b = new Buffer(10);\nconst z = s.substr(1, 2);\n")
    assert [f.line_number for f in deprecated({"a.js": src})] == [3, 4, 5, 6]


def test_modern_code_has_no_deprecated_findings():
    src = ("import datetime\nfrom importlib import import_module\n\n"
           "def f():\n    return datetime.datetime.now(datetime.timezone.utc)\n")
    assert deprecated({"a.py": src}) == []


def test_error_messages_named_after_passwords_are_not_secrets():
    src = "invalidPasswordErrorMessage = 'Invalid password'\npassword_hint = 'at least eight characters'\nDB_PASSWORD = 'hunter2-prod'\n"
    assert [f.line_number for f in secrets({"a.py": src})] == [3]


def test_credentials_in_tests_are_skipped_by_default_but_known_token_formats_are_not():
    src = "PASSWORD = 'hunter2-prod'\nKEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    assert [f.cwe_id for f in secrets({"src/app.py": src})] == ["CWE-798", "CWE-798"]
    only_tokens = secrets({"tests/test_app.py": src})
    assert [(f.line_number, f.severity.value) for f in only_tokens] == [(2, "medium")]  # the AWS key; the password is skipped


def test_include_tests_reports_test_credentials_at_lower_severity():
    src = "PASSWORD = 'hunter2-prod'\n"
    prod = secrets({"src/app.py": src})[0]
    test = find_hardcoded_secrets(Project.from_sources({"tests/test_app.py": src}), include_tests=True)[0]
    assert (prod.severity.value, prod.confidence) == ("medium", 0.7)
    assert (test.severity.value, test.confidence) == ("low", 0.4)


def test_labels_templates_and_urls_named_like_credentials_are_not_secrets():
    src = ('INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"\nreset_url_token = "set-password"\n'
           'SECRET_KEY_INSECURE_PREFIX = "django-insecure-"\nREASON_CSRF_TOKEN_MISSING = "CSRF token missing"\n'
           'token_source = "POST"\nset_password = "ALTER USER %(user)s IDENTIFIED BY %(password)s"\n')
    assert secrets({"a.py": src}) == []


def test_weakly_named_tokens_need_a_secret_looking_value():
    src = 'API_TOKEN = "ghx_A1b2C3d4E5f6G7h8I9j0"\nsession_token = "abc"\nauth_token = "plain-words-only"\n'
    assert [f.line_number for f in secrets({"a.py": src})] == [1, 3]  # auth_token is a strong name, token alone is weak


def test_weak_real_passwords_are_reported_but_fill_in_markers_are_not():
    src = ('password = "secret"\nDB_PASSWORD = "test"\nadmin_password = "admin"\n'
           'password_a = "changeme"\npassword_b = "todo"\npassword_c = "<password>"\npassword_d = "your_api_key"\n')
    assert [f.line_number for f in secrets({"a.py": src})] == [1, 2, 3]


def test_the_sample_used_by_the_backend_tests_is_fully_detected():
    from analysis_engine.pipeline import analyze_sources
    r = analyze_sources({"app/vuln.py": 'password = "secret"\nvalue = eval(user_input)\n'})
    assert sorted((f.cwe_id, f.line_number) for f in r.findings) == sorted([("CWE-798", 1), ("CWE-95", 2)])
