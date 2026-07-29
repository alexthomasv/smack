from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DiffHunk:
    hunk_id: str
    old_path: str | None
    new_path: str | None
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "hunk_id": self.hunk_id,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "old_start": self.old_start,
            "old_len": self.old_len,
            "new_start": self.new_start,
            "new_len": self.new_len,
            "added": list(self.added),
            "removed": list(self.removed),
        }


_HUNK_RE = re.compile(r"^@@\s+-(?P<oa>\d+)(?:,(?P<ob>\d+))?\s+\+(?P<na>\d+)(?:,(?P<nb>\d+))?\s+@@")


class PatchApplyError(ValueError):
    """A unified diff cannot be applied exactly to its declared source."""


def apply_unified_diff_to_text(source_text: str, patch_text: str) -> str:
    """Apply ordered unified-diff hunks without fuzz or an external package."""

    source_lines = source_text.splitlines(keepends=True)
    source_has_newline = source_text.endswith("\n") or source_text == ""
    patch_lines = patch_text.splitlines()
    output: list[str] = []
    source_index = 0
    hunk_index = 0
    trailing_newline_dropped = False

    while hunk_index < len(patch_lines):
        match = _HUNK_RE.match(patch_lines[hunk_index])
        if match is None:
            hunk_index += 1
            continue
        old_start = int(match.group("oa"))
        old_length = int(match.group("ob") or "1")
        target_index = old_start - 1 if old_length > 0 else old_start
        target_index = max(target_index, 0)
        if target_index < source_index or target_index > len(source_lines):
            raise PatchApplyError(f"hunk at -{old_start} is outside source order")
        output.extend(source_lines[source_index:target_index])
        source_index = target_index
        consumed = 0
        last_emitted: int | None = None
        hunk_index += 1
        while hunk_index < len(patch_lines):
            body = patch_lines[hunk_index]
            if _HUNK_RE.match(body) or body.startswith(("--- ", "+++ ")):
                break
            hunk_index += 1
            if body.startswith("\\"):
                if last_emitted is not None and output[last_emitted].endswith("\n"):
                    output[last_emitted] = output[last_emitted][:-1]
                    trailing_newline_dropped = True
                continue
            if body == "" or body.startswith(" "):
                expected = body[1:] if body.startswith(" ") else ""
                if source_index >= len(source_lines):
                    raise PatchApplyError(f"hunk at -{old_start}: context past EOF")
                actual = source_lines[source_index].rstrip("\r\n")
                if actual != expected:
                    raise PatchApplyError(
                        f"hunk at -{old_start}: expected context {expected!r}, "
                        f"got {actual!r}"
                    )
                output.append(source_lines[source_index])
                last_emitted = len(output) - 1
                source_index += 1
                consumed += 1
                continue
            if body.startswith("-"):
                expected = body[1:]
                if source_index >= len(source_lines):
                    raise PatchApplyError(f"hunk at -{old_start}: delete past EOF")
                actual = source_lines[source_index].rstrip("\r\n")
                if actual != expected:
                    raise PatchApplyError(
                        f"hunk at -{old_start}: expected delete {expected!r}, "
                        f"got {actual!r}"
                    )
                source_index += 1
                consumed += 1
                last_emitted = None
                continue
            if body.startswith("+"):
                output.append(body[1:] + "\n")
                last_emitted = len(output) - 1
                continue
            raise PatchApplyError(
                f"hunk at -{old_start}: unrecognised body line {body!r}"
            )
        if consumed != old_length:
            raise PatchApplyError(
                f"hunk at -{old_start}: consumed {consumed} of "
                f"{old_length} source lines"
            )

    output.extend(source_lines[source_index:])
    result = "".join(output)
    if (
        not source_has_newline
        and not trailing_newline_dropped
        and result.endswith("\n")
    ):
        result = result[:-1]
    return result


def parse_unified_diff(text: str) -> list[DiffHunk]:
    """Parse git-style unified diff hunks into source line regions."""

    lines = text.splitlines()
    old_path: str | None = None
    new_path: str | None = None
    hunks: list[DiffHunk] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("--- "):
            old_path = clean_diff_path(line[4:].strip())
            i += 1
            continue
        if line.startswith("+++ "):
            new_path = clean_diff_path(line[4:].strip())
            i += 1
            continue

        match = _HUNK_RE.match(line)
        if not match:
            i += 1
            continue

        old_start = int(match.group("oa"))
        old_len = int(match.group("ob") or "1")
        new_start = int(match.group("na"))
        new_len = int(match.group("nb") or "1")
        i += 1

        added: list[str] = []
        removed: list[str] = []
        while i < len(lines) and not lines[i].startswith("@@"):
            body_line = lines[i]
            if body_line.startswith("--- ") or body_line.startswith("+++ "):
                break
            if body_line.startswith("+"):
                added.append(body_line[1:])
            elif body_line.startswith("-"):
                removed.append(body_line[1:])
            i += 1

        # Whitespace-only hunks still carry provenance value, but identical
        # stripped hunks are not useful for an impact seed.
        if [s.strip() for s in added] == [s.strip() for s in removed]:
            continue

        hunks.append(
            DiffHunk(
                hunk_id=f"hunk:{len(hunks) + 1}",
                old_path=old_path,
                new_path=new_path,
                old_start=old_start,
                old_len=old_len,
                new_start=new_start,
                new_len=new_len,
                added=tuple(added),
                removed=tuple(removed),
            )
        )
    return hunks


def clean_diff_path(path: str) -> str | None:
    if path == "/dev/null":
        return None
    path = path.split("\t", 1)[0]
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def span_intersects_hunk(
    *,
    source_file: str,
    start_line: int,
    end_line: int,
    hunk: DiffHunk,
    side: str,
) -> bool:
    path = hunk.old_path if side == "left" else hunk.new_path
    hunk_start = hunk.old_start if side == "left" else hunk.new_start
    hunk_len = hunk.old_len if side == "left" else hunk.new_len
    if path is not None and source_file and not path_matches(source_file, path):
        return False
    return line_ranges_intersect(start_line, end_line, hunk_start, hunk_len)


def line_ranges_intersect(start_line: int, end_line: int, hunk_start: int, hunk_len: int) -> bool:
    hunk_end = hunk_start if hunk_len == 0 else hunk_start + hunk_len - 1
    return start_line <= hunk_end and hunk_start <= end_line


def path_matches(source_path: str, diff_path: str) -> bool:
    source_norm = source_path.replace("\\", "/").lstrip("./")
    diff_norm = diff_path.replace("\\", "/").lstrip("./")
    return (
        source_norm == diff_norm
        or source_norm.endswith("/" + diff_norm)
        or diff_norm.endswith("/" + source_norm)
        or Path(source_norm).name == Path(diff_norm).name
    )
