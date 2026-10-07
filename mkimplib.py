#!/usr/bin/env python3
"""
mkimplib - build a COFF import library (.lib) directly from a DLL.

No .def file, no lib.exe/dlltool. Handles the usual pain points:

  * DATA exports      - detected from the section the export RVA lives in
                        (non-executable -> IMPORT_DATA, no thunk, __imp_ only)
  * NONAME exports    - imported by ordinal; symbol name <dllstem>_ord<N>
                        unless overridden with --ordname N=Name
  * forwarded exports - imported by name; the target DLL is looked up (input
                        dir, --fwd-path, System32/SysWOW64) so data-ness and
                        x86 arg size come from the real implementation
  * C++ exports       - mangled names passed through verbatim
  * x86 __stdcall     - undecorated exports get _Foo (cdecl) plus _Foo@N;
                        N is read from the function's `ret N` when capstone
                        is installed, otherwise a range of candidates is
                        emitted (unused members are never pulled in by the
                        linker, so extras only cost file size)
  * x86 __fastcall    - optional @Foo@N variants (--fastcall)

Output is the same short-import-format archive that lib.exe / llvm-lib
produce and is accepted by link.exe, lld-link and GNU ld.

Usage:
  mkimplib.py foo.dll                    -> foo.lib next to the DLL
  mkimplib.py foo.dll -o out\\foo.lib
  mkimplib.py foo.dll --list             -> show what would be emitted
"""

import argparse
import os
import struct
import sys

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

M_I386 = 0x014C
M_AMD64 = 0x8664
M_ARMNT = 0x01C4
M_ARM64 = 0xAA64

MACHINES = {"x86": M_I386, "x64": M_AMD64, "arm": M_ARMNT, "arm64": M_ARM64}
MACHINE_NAMES = {v: k for k, v in MACHINES.items()}

ADDR32NB = {M_I386: 7, M_AMD64: 3, M_ARMNT: 2, M_ARM64: 2}

SCN_CNT_CODE = 0x00000020
SCN_CNT_INIT = 0x00000040
SCN_ALIGN_2 = 0x00200000
SCN_ALIGN_4 = 0x00300000
SCN_ALIGN_8 = 0x00400000
SCN_EXEC = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

SYM_CLASS_EXTERNAL = 2
SYM_CLASS_STATIC = 3
SYM_CLASS_SECTION = 0x68

IMPORT_CODE = 0
IMPORT_DATA = 1

NT_ORDINAL = 0
NT_NAME = 1
NT_NOPREFIX = 2
NT_UNDECORATE = 3


def die(msg):
    sys.stderr.write("mkimplib: error: %s\n" % msg)
    sys.exit(1)


def warn(msg):
    sys.stderr.write("mkimplib: warning: %s\n" % msg)


# --------------------------------------------------------------------------
# PE parsing
# --------------------------------------------------------------------------

class Section(object):
    __slots__ = ("name", "va", "vsize", "raw_ptr", "raw_size", "chars")


class PE(object):
    def __init__(self, data, soft=False):
        self.data = data
        self.ok = False
        fail = (lambda m: None) if soft else die
        if data[:2] != b"MZ":
            return fail("not a PE file (no MZ header)")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return fail("not a PE file (no PE signature)")
        coff = e_lfanew + 4
        (self.machine, nsec, _, _, _, opt_size, self.characteristics) = \
            struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == 0x10B:
            dd_off, ndd_off = opt + 96, opt + 92
        elif magic == 0x20B:
            dd_off, ndd_off = opt + 112, opt + 108
        else:
            return fail("unknown optional header magic 0x%x" % magic)
        ndd = struct.unpack_from("<I", data, ndd_off)[0]
        self.dirs = []
        for i in range(min(ndd, 16)):
            self.dirs.append(struct.unpack_from("<II", data, dd_off + 8 * i))
        self.sections = []
        sh = opt + opt_size
        for i in range(nsec):
            s = Section()
            off = sh + 40 * i
            s.name = data[off:off + 8].rstrip(b"\0").decode("latin-1")
            (s.vsize, s.va, s.raw_size, s.raw_ptr) = struct.unpack_from("<IIII", data, off + 8)
            s.chars = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append(s)
        self.ok = True

    def section_of(self, rva):
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s
        return None

    def off(self, rva):
        s = self.section_of(rva)
        if s is None:
            return None
        o = rva - s.va
        if o >= s.raw_size:
            return None
        return s.raw_ptr + o

    def cstr(self, rva):
        o = self.off(rva)
        if o is None:
            return None
        end = self.data.index(b"\0", o)
        return self.data[o:end].decode("latin-1")

    def u32(self, rva):
        return struct.unpack_from("<I", self.data, self.off(rva))[0]

    def u16(self, rva):
        return struct.unpack_from("<H", self.data, self.off(rva))[0]


class Export(object):
    __slots__ = ("name", "ordinal", "hint", "rva", "forward", "is_data")

    def __init__(self):
        self.name = None
        self.forward = None
        self.is_data = False
        self.hint = 0


def read_exports(pe):
    if not pe.dirs or pe.dirs[0][0] == 0:
        return [], None
    exp_rva, exp_size = pe.dirs[0]
    o = pe.off(exp_rva)
    (_, _, _, _, name_rva, base, nfuncs, nnames, funcs_rva, names_rva, ords_rva) = \
        struct.unpack_from("<IIHHIIIIIII", pe.data, o)
    dll_internal = pe.cstr(name_rva) if name_rva else None

    rvas = [pe.u32(funcs_rva + 4 * i) for i in range(nfuncs)]
    names_for = {}
    for i in range(nnames):
        nm = pe.cstr(pe.u32(names_rva + 4 * i))
        idx = pe.u16(ords_rva + 2 * i)
        names_for.setdefault(idx, []).append((nm, i))

    out = []
    for idx, rva in enumerate(rvas):
        if rva == 0:
            continue
        forward = None
        is_data = False
        if exp_rva <= rva < exp_rva + exp_size:
            forward = pe.cstr(rva)
        else:
            code_rva = rva & ~1 if pe.machine == M_ARMNT else rva
            s = pe.section_of(code_rva)
            if s is not None and not (s.chars & (SCN_EXEC | SCN_CNT_CODE)):
                is_data = True
        named = names_for.get(idx)
        if named:
            for nm, hint in named:
                e = Export()
                e.name, e.hint, e.ordinal, e.rva = nm, hint, base + idx, rva
                e.forward, e.is_data = forward, is_data
                out.append(e)
        else:
            e = Export()
            e.ordinal, e.rva, e.forward, e.is_data = base + idx, rva, forward, is_data
            out.append(e)
    return out, dll_internal


class FwdResolver(object):
    """Follows forwarded exports (kernel32.Foo, ntdll.#12) into the target DLL
    so data-ness and x86 argument size come from the real implementation."""

    def __init__(self, dirs):
        self.dirs = [d for d in dirs if d and os.path.isdir(d)]
        self.cache = {}

    def _load(self, mod):
        key = mod.lower()
        if key in self.cache:
            return self.cache[key]
        res = None
        fname = mod if "." in os.path.basename(mod) else mod + ".dll"
        for d in self.dirs:
            p = os.path.join(d, fname)
            if os.path.isfile(p):
                try:
                    with open(p, "rb") as f:
                        tpe = PE(f.read(), soft=True)
                    if tpe.ok:
                        exps, _ = read_exports(tpe)
                        by_name = dict((e.name, e) for e in exps if e.name is not None)
                        by_ord = dict((e.ordinal, e) for e in exps)
                        res = (tpe, by_name, by_ord)
                        break
                except Exception:
                    pass
        self.cache[key] = res
        return res

    def resolve(self, fwd, depth=0):
        """-> (pe, Export) of the final implementation, or None."""
        if depth > 8 or "." not in fwd:
            return None
        mod, sym = fwd.rsplit(".", 1)
        t = self._load(mod)
        if t is None:
            return None
        tpe, by_name, by_ord = t
        if sym.startswith("#"):
            try:
                e = by_ord.get(int(sym[1:]))
            except ValueError:
                return None
        else:
            e = by_name.get(sym)
        if e is None:
            return None
        if e.forward:
            return self.resolve(e.forward, depth + 1)
        return tpe, e


# --------------------------------------------------------------------------
# x86 stdcall argument size detection
# --------------------------------------------------------------------------

_cs = None


def _capstone():
    global _cs
    if _cs is None:
        try:
            import capstone
            _cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        except Exception:
            _cs = False
    return _cs


def x86_ret_bytes(pe, rva, limit=8192):
    """Return N from the first `ret N` / `ret` reached by a linear sweep,
    or None if it can't be determined with reasonable confidence."""
    cs = _capstone()
    if not cs:
        return None
    s = pe.section_of(rva)
    o = pe.off(rva)
    if s is None or o is None:
        return None
    end = min(s.raw_ptr + s.raw_size, o + limit)
    code = pe.data[o:end]
    for insn in cs.disasm(code, rva):
        m = insn.mnemonic
        if m in ("ret", "retn"):
            if insn.op_str:
                try:
                    return int(insn.op_str, 0)
                except ValueError:
                    return None
            return 0
        if m in ("int3", "hlt", "ud2", "iret", "iretd", "retf"):
            return None
        if m == "jmp" and ("[" in insn.op_str or not insn.op_str.startswith("0x")):
            return None  # jump through memory/register: thunk or dispatch
        if m == "jmp":
            try:
                target = int(insn.op_str, 0)
            except ValueError:
                return None
            if target < rva:
                return None  # tail call to something earlier: unknown
    return None


# --------------------------------------------------------------------------
# Import planning
# --------------------------------------------------------------------------

class Imp(object):
    __slots__ = ("sym", "itype", "ntype", "hint", "src", "note")

    def __init__(self, sym, itype, ntype, hint, src, note=""):
        self.sym, self.itype, self.ntype, self.hint = sym, itype, ntype, hint
        self.src, self.note = src, note


def plan(pe, exports, machine, dll_stem, ordnames, x86_mode, x86_max, fastcall, fwd):
    imps = []
    stats = {"exact": 0, "range": 0, "fwd_resolved": 0, "fwd_unresolved": 0}
    for e in exports:
        impl_pe, impl = pe, e
        if e.forward:
            r = fwd.resolve(e.forward)
            if r is not None:
                impl_pe, impl = r
                e.is_data = impl.is_data
                stats["fwd_resolved"] += 1
            else:
                impl = None
                stats["fwd_unresolved"] += 1
        itype = IMPORT_DATA if e.is_data else IMPORT_CODE
        if e.name is None:
            base_name = ordnames.get(e.ordinal, "%s_ord%d" % (dll_stem, e.ordinal))
            by_ordinal = True
            label = "#%d" % e.ordinal
        else:
            base_name = e.name
            by_ordinal = False
            label = e.name
        note = "data" if e.is_data else ("fwd->" + e.forward if e.forward else "")

        if machine != M_I386:
            nt = NT_ORDINAL if by_ordinal else NT_NAME
            hint = e.ordinal if by_ordinal else e.hint
            imps.append(Imp(base_name, itype, nt, hint, label, note))
            continue

        # ---- x86 ----
        hint = e.ordinal if by_ordinal else e.hint
        if base_name[:1] in ("?", "@") or "@" in base_name:
            # already decorated (C++, fastcall, or Foo@N): exact name
            if base_name[:1] in ("?", "@"):
                sym = base_name
                nt = NT_ORDINAL if by_ordinal else NT_NAME
            else:
                sym = "_" + base_name
                nt = NT_ORDINAL if by_ordinal else NT_NOPREFIX
            imps.append(Imp(sym, itype, nt, hint, label, note))
            continue

        nt_plain = NT_ORDINAL if by_ordinal else NT_NOPREFIX
        nt_dec = NT_ORDINAL if by_ordinal else NT_UNDECORATE
        imps.append(Imp("_" + base_name, itype, nt_plain, hint, label, note))
        if itype == IMPORT_DATA or x86_mode == "none":
            continue

        sizes = None
        if x86_mode == "auto" and impl is not None:
            n = x86_ret_bytes(impl_pe, impl.rva)
            if n is not None and n % 4 == 0 and n <= 1024:
                sizes = [n]
                stats["exact"] += 1
        if sizes is None:
            sizes = list(range(0, x86_max + 1, 4))
            stats["range"] += 1
        for n in sizes:
            imps.append(Imp("_%s@%d" % (base_name, n), itype, nt_dec, hint, label,
                            "stdcall" + ("" if len(sizes) == 1 else " (range)")))
            if fastcall:
                imps.append(Imp("@%s@%d" % (base_name, n), itype, nt_dec, hint, label,
                                "fastcall"))
    return imps, stats


# --------------------------------------------------------------------------
# COFF object builders
# --------------------------------------------------------------------------

class StrTab(object):
    def __init__(self):
        self.buf = bytearray()

    def name8(self, name):
        b = name.encode("latin-1")
        if len(b) <= 8:
            return b.ljust(8, b"\0")
        off = 4 + len(self.buf)
        self.buf += b + b"\0"
        return struct.pack("<II", 0, off)

    def blob(self):
        return struct.pack("<I", 4 + len(self.buf)) + bytes(self.buf)


def coff_header(machine, nsec, symptr, nsyms):
    chars = 0x0100 if machine in (M_I386, M_ARMNT) else 0
    return struct.pack("<HHIIIHH", machine, nsec, 0, symptr, nsyms, 0, chars)


def sec_header(name, size, rawptr, relptr, nrel, chars):
    return struct.pack("<8sIIIIIIHHI", name.encode(), 0, 0, size, rawptr, relptr, 0, nrel, 0, chars)


def symbol(st, name, value, secnum, sclass):
    return st.name8(name) + struct.pack("<IhHBB", value, secnum, 0, sclass, 0)


def obj_import_descriptor(machine, dll, stem):
    st = StrTab()
    name_data = dll.encode("latin-1") + b"\0"
    hdr_sz, nsec = 20, 2
    raw2 = hdr_sz + 40 * nsec
    rel2 = raw2 + 20
    raw6 = rel2 + 3 * 10
    symptr = raw6 + len(name_data)
    rt = ADDR32NB[machine]

    out = coff_header(machine, nsec, symptr, 7)
    out += sec_header(".idata$2", 20, raw2, rel2, 3,
                      SCN_ALIGN_4 | SCN_CNT_INIT | SCN_READ | SCN_WRITE)
    out += sec_header(".idata$6", len(name_data), raw6, 0, 0,
                      SCN_ALIGN_2 | SCN_CNT_INIT | SCN_READ | SCN_WRITE)
    out += b"\0" * 20
    out += struct.pack("<IIH", 12, 2, rt)  # Name RVA         -> .idata$6
    out += struct.pack("<IIH", 0, 3, rt)   # ILT RVA          -> .idata$4
    out += struct.pack("<IIH", 16, 4, rt)  # IAT RVA          -> .idata$5
    out += name_data
    out += symbol(st, "__IMPORT_DESCRIPTOR_" + stem, 0, 1, SYM_CLASS_EXTERNAL)
    out += symbol(st, ".idata$2", 0, 1, SYM_CLASS_SECTION)
    out += symbol(st, ".idata$6", 0, 2, SYM_CLASS_STATIC)
    out += symbol(st, ".idata$4", 0, 0, SYM_CLASS_SECTION)
    out += symbol(st, ".idata$5", 0, 0, SYM_CLASS_SECTION)
    out += symbol(st, "__NULL_IMPORT_DESCRIPTOR", 0, 0, SYM_CLASS_EXTERNAL)
    out += symbol(st, "\x7f" + stem + "_NULL_THUNK_DATA", 0, 0, SYM_CLASS_EXTERNAL)
    out += st.blob()
    return bytes(out)


def obj_null_import_descriptor(machine):
    st = StrTab()
    raw = 20 + 40
    out = coff_header(machine, 1, raw + 20, 1)
    out += sec_header(".idata$3", 20, raw, 0, 0,
                      SCN_ALIGN_4 | SCN_CNT_INIT | SCN_READ | SCN_WRITE)
    out += b"\0" * 20
    out += symbol(st, "__NULL_IMPORT_DESCRIPTOR", 0, 1, SYM_CLASS_EXTERNAL)
    out += st.blob()
    return bytes(out)


def obj_null_thunk(machine, stem):
    st = StrTab()
    ps = 8 if machine in (M_AMD64, M_ARM64) else 4
    al = SCN_ALIGN_8 if ps == 8 else SCN_ALIGN_4
    raw = 20 + 80
    out = coff_header(machine, 2, raw + 2 * ps, 1)
    out += sec_header(".idata$5", ps, raw, 0, 0, al | SCN_CNT_INIT | SCN_READ | SCN_WRITE)
    out += sec_header(".idata$4", ps, raw + ps, 0, 0, al | SCN_CNT_INIT | SCN_READ | SCN_WRITE)
    out += b"\0" * (2 * ps)
    out += symbol(st, "\x7f" + stem + "_NULL_THUNK_DATA", 0, 1, SYM_CLASS_EXTERNAL)
    out += st.blob()
    return bytes(out)


def obj_short_import(machine, dll, imp):
    payload = imp.sym.encode("latin-1") + b"\0" + dll.encode("latin-1") + b"\0"
    typeinfo = (imp.itype & 3) | ((imp.ntype & 7) << 2)
    hdr = struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, machine, 0, len(payload),
                      imp.hint & 0xFFFF, typeinfo)
    return hdr + payload


# --------------------------------------------------------------------------
# Archive writer (MS COFF .lib: two linker members + longnames)
# --------------------------------------------------------------------------

def ar_header(name, size, mode=b"0"):
    return (name.ljust(16, b" ") + b"0".ljust(12, b" ") + b"".ljust(6, b" ") +
            b"".ljust(6, b" ") + mode.ljust(8, b" ") +
            str(size).encode().ljust(10, b" ") + b"`\n")


def write_archive(members):
    """members: list of (member_name:str, data:bytes, [symbol names])"""
    longnames = bytearray()
    long_off = {}
    enc_names = []
    for name, _, _ in members:
        n = name.encode("latin-1")
        if len(n) <= 15:
            enc_names.append(n + b"/")
        else:
            if n not in long_off:
                long_off[n] = len(longnames)
                longnames += n + b"\0"
            enc_names.append(b"/" + str(long_off[n]).encode())

    all_syms = []  # (name bytes, member index)
    for i, (_, _, syms) in enumerate(members):
        for s in syms:
            all_syms.append((s.encode("latin-1"), i))

    nsyms = len(all_syms)
    names_blob = b"".join(s + b"\0" for s, _ in all_syms)
    sorted_syms = sorted(all_syms, key=lambda t: t[0])
    sorted_blob = b"".join(s + b"\0" for s, _ in sorted_syms)

    first_size = 4 + 4 * nsyms + len(names_blob)
    second_size = 4 + 4 * len(members) + 4 + 2 * nsyms + len(sorted_blob)

    def pad(n):
        return n + (n & 1)

    pos = 8
    pos += 60 + pad(first_size)
    pos += 60 + pad(second_size)
    pos += 60 + pad(len(longnames))
    offsets = []
    for (_, data, _) in members:
        offsets.append(pos)
        pos += 60 + pad(len(data))

    out = bytearray(b"!<arch>\n")

    first = struct.pack(">I", nsyms)
    first += b"".join(struct.pack(">I", offsets[i]) for _, i in all_syms)
    first += names_blob
    out += ar_header(b"/", len(first)) + first
    if len(first) & 1:
        out += b"\n"

    second = struct.pack("<I", len(members))
    second += b"".join(struct.pack("<I", o) for o in offsets)
    second += struct.pack("<I", nsyms)
    second += b"".join(struct.pack("<H", i + 1) for _, i in sorted_syms)
    second += sorted_blob
    out += ar_header(b"/", len(second)) + second
    if len(second) & 1:
        out += b"\n"

    out += ar_header(b"//", len(longnames)) + longnames
    if len(longnames) & 1:
        out += b"\n"

    for (name, data, _), enc in zip(members, enc_names):
        out += ar_header(enc, len(data), b"644") + data
        if len(data) & 1:
            out += b"\n"
    return bytes(out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mkimplib",
        description="Build a COFF import library straight from a DLL's export table.")
    ap.add_argument("dll", help="input DLL")
    ap.add_argument("-o", "--out", help="output .lib (default: <dll>.lib next to input)")
    ap.add_argument("--dll-name", help="DLL name recorded in the import lib "
                    "(default: input file name)")
    ap.add_argument("--machine", choices=sorted(MACHINES), help="override detected machine")
    ap.add_argument("--ordname", action="append", default=[], metavar="ORD=NAME",
                    help="symbol name for a NONAME (ordinal-only) export; repeatable")
    ap.add_argument("--x86", choices=("auto", "range", "none"), default="auto",
                    help="x86 stdcall decoration: auto = disassemble for `ret N` (needs "
                    "capstone) and fall back to range; range = always emit _Foo@0.._Foo@MAX; "
                    "none = cdecl names only (default: auto)")
    ap.add_argument("--x86-max", type=int, default=64, metavar="BYTES",
                    help="upper bound for the stdcall range fallback (default: 64)")
    ap.add_argument("--fastcall", action="store_true",
                    help="x86: also emit @Foo@N fastcall variants")
    ap.add_argument("--fwd-path", action="append", default=[], metavar="DIR",
                    help="extra directory to search for forwarded-to DLLs; repeatable "
                    "(searched after the input's directory, before the system directory)")
    ap.add_argument("--list", action="store_true",
                    help="print the planned imports and exit without writing")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args(argv)

    with open(a.dll, "rb") as f:
        pe = PE(f.read())

    machine = MACHINES[a.machine] if a.machine else pe.machine
    if machine not in ADDR32NB:
        die("unsupported machine 0x%04x" % machine)

    dll = a.dll_name or os.path.basename(a.dll)
    stem = dll.rsplit(".", 1)[0] if "." in dll else dll

    ordnames = {}
    for spec in a.ordname:
        if "=" not in spec:
            die("--ordname expects ORD=NAME, got %r" % spec)
        k, v = spec.split("=", 1)
        ordnames[int(k, 0)] = v

    exports, internal = read_exports(pe)
    if not exports:
        die("%s has no exports" % a.dll)
    if internal and internal.lower() != dll.lower() and not a.quiet:
        warn("export directory calls itself %r; recording %r (use --dll-name to change)"
             % (internal, dll))

    if machine == M_I386 and a.x86 == "auto" and not _capstone() and not a.quiet:
        warn("capstone not installed; x86 stdcall sizes fall back to a range "
             "(pip install capstone for exact sizes)")

    sysroot = os.environ.get("SystemRoot") or os.environ.get("windir")
    sysdirs = []
    if sysroot:
        if machine == M_I386 and os.path.isdir(os.path.join(sysroot, "SysWOW64")):
            sysdirs.append(os.path.join(sysroot, "SysWOW64"))
        else:
            sysdirs.append(os.path.join(sysroot, "System32"))
    fwd = FwdResolver([os.path.dirname(os.path.abspath(a.dll))] + a.fwd_path + sysdirs)

    imps, stats = plan(pe, exports, machine, stem, ordnames, a.x86, a.x86_max,
                       a.fastcall, fwd)

    # de-duplicate symbols (aliases can collide after decoration)
    seen = set()
    uniq = []
    for i in imps:
        if i.sym in seen:
            continue
        seen.add(i.sym)
        uniq.append(i)
    imps = uniq

    if a.list:
        tn = {IMPORT_CODE: "code", IMPORT_DATA: "data"}
        nn = {NT_ORDINAL: "ordinal", NT_NAME: "name", NT_NOPREFIX: "noprefix",
              NT_UNDECORATE: "undecorate"}
        for i in imps:
            print("%-40s %-4s %-10s %-6d %s %s" % (i.sym, tn[i.itype], nn[i.ntype],
                                                   i.hint, i.src, i.note))
        return 0

    members = [
        (dll, obj_import_descriptor(machine, dll, stem), ["__IMPORT_DESCRIPTOR_" + stem]),
        (dll, obj_null_import_descriptor(machine), ["__NULL_IMPORT_DESCRIPTOR"]),
        (dll, obj_null_thunk(machine, stem), ["\x7f" + stem + "_NULL_THUNK_DATA"]),
    ]
    for i in imps:
        syms = ["__imp_" + i.sym] if i.itype == IMPORT_DATA else ["__imp_" + i.sym, i.sym]
        members.append((dll, obj_short_import(machine, dll, i), syms))

    out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.dll)), stem + ".lib")
    with open(out, "wb") as f:
        f.write(write_archive(members))

    if not a.quiet:
        ndata = sum(1 for e in exports if e.is_data)
        nnoname = sum(1 for e in exports if e.name is None)
        nfwd = sum(1 for e in exports if e.forward)
        msg = "%s: %d exports (%d data, %d noname, %d forwarded) -> %d symbols [%s]" % (
            out, len(exports), ndata, nnoname, nfwd, len(imps), MACHINE_NAMES[machine])
        if machine == M_I386 and a.x86 != "none":
            msg += "; stdcall exact=%d range=%d" % (stats["exact"], stats["range"])
        if stats["fwd_unresolved"]:
            msg += "; %d forwarder target(s) not found (--fwd-path)" % stats["fwd_unresolved"]
        print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
