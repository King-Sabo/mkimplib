# mkimplib

Build a COFF import library (`.lib`) directly from a DLL's export table.
No `.def` file, no `lib.exe`, `dumpbin`, `dlltool` or MSVC install required.

```
python mkimplib.py foo.dll          # -> foo.lib next to foo.dll
```

The output is the same short-import-format archive that `lib.exe` / `llvm-lib`
produce, and links with `link.exe`, `lld-link` and GNU `ld`.

## Requirements

- Python 3 (standard library only)
- Optional: `pip install capstone` — used on x86 only, to detect exact
  `__stdcall` argument sizes (see below)

Single-file executable without Python on the target machine:

```
pip install pyinstaller capstone
pyinstaller -F mkimplib.py          # -> dist\mkimplib.exe
```

## Supported targets

| Machine | Notes |
|---------|-------|
| x64     | |
| x86     | stdcall / fastcall decoration handled |
| ARM64   | ARM64EC / ARM64X hybrids are treated as plain ARM64 |
| ARM (Thumb-2) | |

The machine is taken from the DLL; override with `--machine`.

## What it handles

| Case | Behaviour |
|------|-----------|
| Code exports | `Foo` + `__imp_Foo` (linker-generated thunk) |
| **Data exports** | Detected from the section the export RVA lives in (non-executable ⇒ data). Emitted as `IMPORT_DATA`: `__imp_Foo` only, no thunk. Use `__declspec(dllimport)` in the consumer. |
| **NONAME (ordinal-only) exports** | Imported by ordinal. Symbol name defaults to `<dllstem>_ord<N>`; set your own with `--ordname N=Name`. |
| **Forwarded exports** | Imported by name. The target DLL is looked up so data-ness and x86 argument size come from the real implementation. |
| **C++ exports** | Mangled names passed through verbatim. |
| **x86 `__stdcall`** | Undecorated export `Foo` gets `_Foo` (cdecl) **and** `_Foo@N`. See below. |
| x86 already-decorated names | `Foo@8`, `_Foo@8`, `?cpp@@...`, `@Foo@8` map exactly to the export. |
| x86 `__fastcall` | Optional `@Foo@N` variants with `--fastcall`. |
| Hints | Real name-table hints are recorded for faster loader binding. |

### x86 stdcall

Win32 DLLs usually export stdcall functions undecorated (`Foo`), while the
compiler references `_Foo@N`. The tool resolves `N` like this:

1. **`--x86 auto`** (default): disassemble the function with capstone and read
   the first `ret N`. Emits exactly `_Foo` and `_Foo@N`.
2. If capstone is missing, or the function can't be analysed (thunk, jump
   table, unresolved forwarder): emit `_Foo@0`, `_Foo@4`, … `_Foo@<x86-max>`.
   Unused members are never pulled in by the linker; the only cost is file size.

`--x86 range` always uses the range; `--x86 none` emits cdecl names only.

**Why only x86 needs this:** on x86, `__stdcall` callees pop their own
arguments (`ret N`), so the compiler encodes the argument size into the symbol
name to catch mismatches at link time. x64, ARM and ARM64 have a single
calling convention where the caller cleans up, so C symbols carry no
decoration and the symbol name is simply the export name. Nothing needs to be
recovered, and capstone is never loaded.

### Forwarder resolution

For an export like `fwd = kernel32.lstrlenA` the target DLL is searched in:

1. the input DLL's directory
2. each `--fwd-path DIR`
3. `%SystemRoot%\SysWOW64` (x86) or `%SystemRoot%\System32`

Chains are followed (`a.X -> b.Y -> c.Z`), including `dll.#ordinal` targets.
API-set forwarders (`api-ms-win-*`) are not resolved; they fall back to the
defaults above.

## Options

```
mkimplib [-o OUT] [--dll-name NAME] [--machine {x86,x64,arm,arm64}]
         [--ordname ORD=NAME ...] [--x86 {auto,range,none}] [--x86-max BYTES]
         [--fastcall] [--fwd-path DIR ...] [--list] [-q] dll
```

| Option | Description |
|--------|-------------|
| `-o, --out` | Output `.lib` (default: `<dllstem>.lib` next to the DLL) |
| `--dll-name` | DLL name recorded in the import lib (default: input file name) |
| `--machine` | Override detected machine |
| `--ordname ORD=NAME` | Symbol name for a NONAME export; repeatable |
| `--x86` | stdcall decoration mode: `auto` (default), `range`, `none` |
| `--x86-max` | Upper bound in bytes for the range fallback (default 64) |
| `--fastcall` | x86: also emit `@Foo@N` variants |
| `--fwd-path DIR` | Extra search directory for forwarded-to DLLs; repeatable |
| `--list` | Print the planned symbols and exit without writing |
| `-q, --quiet` | Suppress summary and warnings |

## Examples

```
# Output to a specific path
python mkimplib.py C:\thirdparty\foo.dll -o lib\x64\foo.lib

# DLL will be deployed under a different name than the file you have
python mkimplib.py foo_v2.dll --dll-name foo.dll

# Give ordinal-only exports real names
python mkimplib.py shell32.dll --ordname 61=RunFileDlg

# Inspect decisions before writing
python mkimplib.py foo.dll --list
```

`--list` columns: symbol, `code`/`data`, import name type
(`name`, `noprefix`, `undecorate`, `ordinal`), hint/ordinal, source export,
note (`data`, `fwd->...`, `stdcall`, `stdcall (range)`).

## Limitations

- Without capstone, stdcall functions with more than `--x86-max` bytes of
  arguments won't resolve; raise the bound (e.g. `--x86-max 128`).
- The stdcall size heuristic uses a linear sweep up to the first `ret`;
  functions that tail-jump elsewhere fall back to the range.
- ARM64EC / ARM64X export views are not generated.
- A DATA export living in an executable section would be treated as code
  (rare; no known toolchain does this by default).

## Output format notes

- First and second linker members plus a longnames member, as written by
  `lib.exe`.
- Import descriptor, null import descriptor and null thunk objects are
  byte-identical to those produced by `llvm-dlltool`.
- Timestamps are zero; output is deterministic for a given input.
