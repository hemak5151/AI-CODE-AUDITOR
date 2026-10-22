# UI Wireframes (v1)

## 1. Upload page

```
+--------------------------------------------------+
| AI Code Auditor                         [Results]|
+--------------------------------------------------+
|  Analyze a project                               |
|  ( ) Upload .zip   ( ) Git URL                   |
|  +--------------------------------------------+  |
|  |  Drop zip here   or   https://github.com/..|  |
|  +--------------------------------------------+  |
|  [ ] Add guideline files (PDF / Markdown)        |
|                                [ Start analysis ]|
|  Progress: [########----] 65%  Parsing files...  |
+--------------------------------------------------+
```

## 2. Findings list

```
+--------------------------------------------------+
| Findings (3)   Severity: [All v]  CWE: [All v]   |
+--------------------------------------------------+
| CRITICAL | CWE-78  | Command injection | utils.py:30 |
| HIGH     | CWE-89  | SQL injection     | db.py:12    |
| MEDIUM   | CWE-798 | Hardcoded secret  | config.py:4 |
+--------------------------------------------------+
| Severity chart:  crit ##  high ###  med #        |
+--------------------------------------------------+
```

## 3. Finding detail

```
+----------------------------+---------------------+
| Code viewer (Monaco)       | MOCK-1 | HIGH       |
|  10  def get_user(uid):    | CWE-89 | conf 0.91  |
|  11    cur = db.cursor()   | Explanation: ...    |
| >12    cur.execute(...)    | Evidence: ...       |
|  13    return cur.fetch()  | Guideline: OWASP .. |
|                            | [ View patch ]      |
+----------------------------+---------------------+
```

## 4. Diff viewer

```
+--------------------------------------------------+
| Patch for MOCK-1                                 |
+-------------------------+------------------------+
| Original                | Patched                |
| - cur.execute("..."+uid)| + cur.execute("..?",   |
|                         |         (uid,))        |
+-------------------------+------------------------+
| [ Reject ]  [ Accept ]  [ Download patch ]       |
+--------------------------------------------------+
```
