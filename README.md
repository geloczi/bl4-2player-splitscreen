# BL4SS for Borderlands 4 build `1.8.1-4709277`

> [!IMPORTANT]
> This is an unofficial, version-specific fork of **BL4 2-Player Split-Screen
> Unlocked**, patched and tested specifically for Borderlands 4
> **ECHO-4 OS 1.8.1-4709277**. Compatibility with other game builds is not
> claimed.

Version-specific builds are kept in separate branches. Check the repository's
[branch list](https://github.com/geloczi/bl4-2player-splitscreen/branches) and
select the branch matching your game build; the default branch may contain
work in progress.

The original BL4SS mod was created by
[TitanNav](https://github.com/TitanNav).

- [Original project](https://github.com/TitanNav/bl4-2player-splitscreen)
- [Original README and full mod documentation](https://github.com/TitanNav/bl4-2player-splitscreen/blob/main/README.md)
- [Original Nexus Mods page](https://www.nexusmods.com/borderlands4/mods/310)

## Compatibility scope

This patch targets the exact executable identified below. It is not a general
patch for every game installation carrying a 1.8.1 label.

| Item | Value |
| --- | --- |
| Reported game version | `1.8.1-4709277` |
| Game executable SHA-256 | `3cae7ca20bde46500b1f0577a01bf7ad95752dc2142e829c3b79e5494bfa7059` |
| PE timestamp | `0x6A2C7DB2` |
| Image size | `0x34F6E000` |
| Ready setter RVA | `0x0B54A9B0` |
| Approval check RVA | `0x0B3B16C0` |
| Ready flag offset | `0x32C1` |

The original mod's native signatures do not match this executable. Without the
compatibility profile, BL4SS reports `0 setter / 0 approval hits` and Player 2
remains in the blue travel tunnel.

The profile in `mod/bl4ss/native.py` checks the executable's PE timestamp and
image size, then verifies exact instruction bytes at the ready setter, approval
check, and a native caller. It uses the build-specific address only when every
guard passes. It does not patch the executable or write the ready flag directly.

The implementation is in `mod/bl4ss/native.py`. A focused readable diff is
provided in `native-compatibility.patch`, and `patch-manifest.json` records the
tested executable identity and packaged-mod hashes.

## Mod version locations

The mod version is defined in two places, which must remain in sync:

- `mod/bl4ss/__init__.py` — `__version__`
- `mod/bl4ss/pyproject.toml` — `version` under `[project]`

`tools/build_sdkmod.py` reads the value from `pyproject.toml` when naming the
release archive.
