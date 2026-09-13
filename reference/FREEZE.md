# Reference Freeze — Python Oracle

This directory holds the Python oracle whose behavior `asc-rs` must reproduce.

## Pinned commit

| Field      | Value                                      |
|------------|--------------------------------------------|
| Repository | https://github.com/MG1937/asc (upstream)  |
| Path       | `reference/asc/`                           |
| SHA-1      | `ccc6bae7704f5c5ef1a7271e27314837079621fb` |
| Frozen on  | 2026-09-13 (Windows 11, git 2.55.0.windows.3) |
| Working branch / state | detached HEAD, clean working tree      |

## How to reproduce the clone

```bash
git clone https://github.com/MG1937/asc.git reference/asc
git -C reference/asc checkout ccc6bae7704f5c5ef1a7271e27314837079621fb
```

Verify with:

```bash
git -C reference/asc rev-parse HEAD
# expected: ccc6bae7704f5c5ef1a7271e27314837079621fb
git -C reference/asc status --short
# expected: (no output)
git -C reference/asc log -1 --format='%H %ad %s' --date=short
# expected: ccc6bae7704f5c5ef1a7271e27314837079621fb <date> Merge pull request #19 from MG1937/dev-0.1.0
```

## Python and dependency environment

| Tool          | Version                                             |
|---------------|-----------------------------------------------------|
| OS            | Windows 11 Enterprise 10.0.26200 (git-bash shell)   |
| Python        | 3.14.6 (`python --version`)                        |
| androguard    | 4.1.3 (matches `requirements.txt` pin)              |
| pip           | 25.x bundled with Python 3.14.6                     |

Create / refresh the local environment (offline-safe after the first run):

```bash
python -m venv reference/venv
reference/venv/Scripts/python.exe -m pip install --upgrade pip
reference/venv/Scripts/python.exe -m pip install androguard==4.1.3
reference/venv/Scripts/python.exe -m pip freeze > reference/requirements-freeze.txt
```

`reference/requirements-freeze.txt` is the recorded lock (48 packages, generated
2026-09-13). Pinning only `androguard==4.1.3` is enough; the rest is the
transitive closure produced by pip against the Windows 3.14 ABI wheels.

## How to invoke the oracle

```bash
cd reference/asc
../reference/venv/Scripts/python.exe main.py --help
../reference/venv/Scripts/python.exe main.py findrefs path/to/app.apk string onCreate
../reference/venv/Scripts/python.exe main.py getclass path/to/app.apk Lcom/example/Foo;
```

Two relevant notes:

1. `main.py` always imports `from src.asc_client...` and `from src.asc_core...`
   and must be invoked with `reference/asc/` as the cwd (the repo layout
   relies on the implicit `src.` package root being on `sys.path`).
2. androguard pulls in optional native wheels (`frida`, `greenlet`,
   `cryptography`). They are not used by the oracle at runtime, but they are
   present in `requirements-freeze.txt` because `pip install androguard==4.1.3`
   resolves them as recommended extras on Windows / Python 3.14.

## Forbidden writes

The directory `reference/asc/` is read-only for every ASC-RS worker, including
this one. Do not edit, `git checkout --`, or otherwise mutate files inside
`reference/asc/`. If the freeze needs to move, advance it here first and re-run
golden capture.
