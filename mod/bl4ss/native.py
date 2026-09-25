"""
Locating and calling the game's "client ready" setter — the one native call this mod makes.

A local split-screen player has no online ID, so the game's ready query for it retries forever and never calls the
setter; the player's arrival in the world then waits forever. Calling the setter for that player completes the arrival
through the game's own code path.

Locating, strongest first:
1. Signature scan of the main executable section: exactly one hit for the setter and exactly one for the approval
   check that reads the same flag, with the same flag offset.
2. The known address — only on the pinned build (PE TimeDateStamp + SizeOfImage) and only if the bytes there still
   match the setter's signature. A last resort: it keeps this build working if a scan ever
   misfires, and still refuses on any other build.
3. Otherwise nothing: the mod logs why and leaves arrival alone.
"""

from __future__ import annotations

import ctypes
import re
import struct
from ctypes import wintypes
from dataclasses import dataclass

from unrealsdk import logging

LOG_PREFIX = "[BL4SS]"

# push rsi; push rdi; push rbx; sub rsp,30h; mov rax,[rip+?]; xor rax,rsp; mov [rsp+28h],rax;
# cmp byte [rcx+FLAG],0; jne ?; mov rsi,rcx; mov byte [rcx+FLAG],1; call ?
SIG_SETTER = re.compile(
    rb"\x56\x57\x53\x48\x83\xEC\x30\x48\x8B\x05....\x48\x31\xE0\x48\x89\x44\x24\x28"
    rb"\x80\xB9(....)\x00\x0F\x85....\x48\x89\xCE\xC6\x81(....)\x01\xE8",
    re.S,
)
# cmp byte [rsi+FLAG],0; jne ?; mov rax,[rsi+PLAYERSTATE]; test rax,rax; je ?; test byte [rax+?],8
SIG_APPROVAL = re.compile(rb"\x80\xBE(....)\x00\x75.\x48\x8B\x86(....)\x48\x85\xC0\x74.\xF6\x80....\x08", re.S)

# Build 25234898 (Steam), verified in game.
PIN_TIMESTAMP = 0x6A9858AE
PIN_SIZE_OF_IMAGE = 0x309B6000
PINNED_SETTER_RVA = 0x041E846C
PINNED_FLAG_OFFSET = 0x32C1

IMAGE_SCN_MEM_EXECUTE = 0x20000000
CHUNK = 16 << 20
OVERLAP = 0x100

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_k32.ReadProcessMemory.restype = wintypes.BOOL
_k32.GetCurrentProcess.restype = wintypes.HANDLE
_k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
_k32.GetModuleHandleW.restype = wintypes.HMODULE
_PROCESS = _k32.GetCurrentProcess()
BASE = int(_k32.GetModuleHandleW(None))


@dataclass(frozen=True)
class Setter:
    address: int
    flag_offset: int
    how: str  # "signature", "pinned", or "1.8.1-verified"


def read(address: int, size: int) -> bytes | None:
    """Reads our own process memory; None instead of a crash if any page is unreadable."""
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not _k32.ReadProcessMemory(_PROCESS, ctypes.c_void_p(address), buf, size, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def _pe_info() -> tuple[int, int, list[tuple[str, int, int, int]]]:
    header = read(BASE, 0x1000) or b""
    pe = struct.unpack_from("<I", header, 0x3C)[0]
    timestamp = struct.unpack_from("<I", header, pe + 8)[0]
    n_sections = struct.unpack_from("<H", header, pe + 6)[0]
    optional_size = struct.unpack_from("<H", header, pe + 20)[0]
    size_of_image = struct.unpack_from("<I", header, pe + 24 + 56)[0]
    sections = []
    for i in range(n_sections):
        entry = pe + 24 + optional_size + i * 40
        name = header[entry:entry + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size, virtual_address = struct.unpack_from("<II", header, entry + 8)
        characteristics = struct.unpack_from("<I", header, entry + 36)[0]
        sections.append((name, virtual_address, virtual_size, characteristics))
    return timestamp, size_of_image, sections


def _scan(section_rva: int, section_size: int) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    setter_hits: list[tuple[int, int]] = []
    approval_hits: list[tuple[int, int]] = []
    pos = 0
    while pos < section_size:
        data = read(BASE + section_rva + pos, min(CHUNK + OVERLAP, section_size - pos))
        if data:
            limit = min(CHUNK, len(data))  # matches starting in the overlap belong to the next chunk
            for m in SIG_SETTER.finditer(data):
                if m.start() < limit and m.group(1) == m.group(2):
                    setter_hits.append((section_rva + pos + m.start(), struct.unpack("<I", m.group(1))[0]))
            for m in SIG_APPROVAL.finditer(data):
                if m.start() < limit:
                    approval_hits.append((section_rva + pos + m.start(), struct.unpack("<I", m.group(1))[0]))
        pos += CHUNK
    return setter_hits, approval_hits



# Local compatibility profile for the user's 1.8.1 / 4709277 executable.
# Statically verified against SHA256:
# 3cae7ca20bde46500b1f0577a01bf7ad95752dc2142e829c3b79e5494bfa7059
# This build inlines more work in the setter (larger stack frame) and uses
# near conditional jumps in the approval check. The upstream signatures
# therefore do not match. All bytes below are instructions with only
# image-relative references: ASLR does not change these byte sequences.
# Require the PE identity AND the setter, approval check, and native caller.
# Never substitute an unchecked address or write the ready flag directly.
LEGACY_TIMESTAMP = 0x6A2C7DB2
LEGACY_SIZE_OF_IMAGE = 0x34F6E000
LEGACY_SETTER_RVA = 0x0B54A9B0
LEGACY_FLAG_OFFSET = 0x32C1
LEGACY_GUARDS = (
    ("setter", LEGACY_SETTER_RVA, bytes.fromhex(
        "415741565657534881ec80000000488b057b1ffc054831e04889442478"
        "80b9c1320000000f85750100004889cec681c132000001e817dedcf9"
        "4885c00f84da000000488bb8f00100004885ff0f84ca000000"
    )),
    ("approval", 0x0B3B16C0, bytes.fromhex(
        "80bec1320000000f85e7feffff488b86980300004885c00f843bfeffff"
        "f6809a030000080f842efeffffe9c5feffff"
    )),
    ("native caller", 0x0B09539E, bytes.fromhex(
        "4584e475084c89f9e805564b00"
    )),
)


def _locate_legacy(timestamp: int, size_of_image: int) -> Setter | None:
    if (timestamp, size_of_image) != (LEGACY_TIMESTAMP, LEGACY_SIZE_OF_IMAGE):
        return None
    for label, rva, expected in LEGACY_GUARDS:
        if read(BASE + rva, len(expected)) != expected:
            logging.warning(
                f"{LOG_PREFIX} 1.8.1 compatibility: {label} validation failed "
                f"at +{rva:#x}; refusing this build-specific address"
            )
            return None
    logging.info(
        f"{LOG_PREFIX} ready setter located by 1.8.1 compatibility "
        f"(+{LEGACY_SETTER_RVA:#x}, flag {LEGACY_FLAG_OFFSET:#x}; "
        "setter + approval + native caller verified)"
    )
    return Setter(BASE + LEGACY_SETTER_RVA, LEGACY_FLAG_OFFSET, "1.8.1-verified")


def locate() -> Setter | None:
    timestamp, size_of_image, sections = _pe_info()
    legacy = _locate_legacy(timestamp, size_of_image)
    if legacy is not None:
        return legacy
    pinned = timestamp == PIN_TIMESTAMP and size_of_image == PIN_SIZE_OF_IMAGE
    code = next(((va, vs) for _n, va, vs, ch in sections if ch & IMAGE_SCN_MEM_EXECUTE), None)
    if code is not None:
        setter_hits, approval_hits = _scan(*code)
        if len(setter_hits) == 1 and len(approval_hits) == 1 and setter_hits[0][1] == approval_hits[0][1]:
            rva, flag = setter_hits[0]
            logging.info(f"{LOG_PREFIX} ready setter located by signature (+{rva:#x}, flag {flag:#x})")
            return Setter(BASE + rva, flag, "signature")
        logging.warning(f"{LOG_PREFIX} signature scan: {len(setter_hits)} setter / {len(approval_hits)} approval hits")
    if pinned:
        m = SIG_SETTER.match(read(BASE + PINNED_SETTER_RVA, 0x40) or b"")
        if m and m.group(1) == m.group(2) and struct.unpack("<I", m.group(1))[0] == PINNED_FLAG_OFFSET:
            logging.info(f"{LOG_PREFIX} ready setter located by pinned address (+{PINNED_SETTER_RVA:#x})")
            return Setter(BASE + PINNED_SETTER_RVA, PINNED_FLAG_OFFSET, "pinned")
    logging.error(
        f"{LOG_PREFIX} could not locate the ready setter safely (build TimeDateStamp {timestamp:#x}). "
        "Player 2 will not be able to spawn in the world on this game version.",
    )
    return None


_setter: Setter | None = None
_located = False


def setter() -> Setter | None:
    """The located setter, scanning once per game session."""
    global _setter, _located
    if not _located:
        _setter = locate()
        _located = True
    return _setter


def is_ready(controller_address: int) -> bool | None:
    found = setter()
    if found is None:
        return None
    value = read(controller_address + found.flag_offset, 1)
    return None if value is None else value != b"\x00"


def mark_ready(controller_address: int) -> bool:
    """Calls the setter for this controller. True if the flag reads set afterwards."""
    found = setter()
    if found is None:
        return False
    ctypes.CFUNCTYPE(None, ctypes.c_void_p)(found.address)(ctypes.c_void_p(controller_address))
    return bool(is_ready(controller_address))
