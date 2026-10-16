"""upload handlers: receive files from the hub via WebSocket payloads.

Big difference from the legacy core: there is no `multipart/form-data` here.
File bytes arrive in the WebSocket payload as either:

  - `content_base64` (str): the file inlined as base64
  - `file_url` (str): an http(s) URL the agent fetches itself

Single upload  -> `upload_file`
Chunked upload -> `upload_init` + `upload_chunk` (N times) + `upload_complete`

Why chunked at all? WebSocket frames have a ceiling (typically 1 MiB to a few
MiB depending on infra), so anything bigger has to be split into chunks. The
hub does the splitting client-side; the agent reassembles.

Uploads always land under the configured upload base directory. Path traversal
attempts are rejected up front via `safe_path_under()`.
"""

from __future__ import annotations

import asyncio
import base64
import errno
import hashlib
import os
import ipaddress
import json
import pathlib
import re
import shutil
import socket
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sentinelx_core.executor import HandlerError
from sentinelx_core import platform_guidance as _pg
from sentinelx_core.executor_engine import safe_path_under
from sentinelx_core.policy import Policy

# 10 GiB hard ceiling, mirrors legacy SENTINEL_MAX_UPLOAD_BYTES default
MAX_UPLOAD_BYTES = 10 * 1024 * 1024 * 1024
CHUNK_READ_SIZE = 1024 * 1024  # 1 MiB


# ── SSRF defense ───────────────────────────────────────────────────────────


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so an attacker can't bounce a vetted URL into a
    rogue one (server returns 302 Location: http://169.254.169.254/...)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(
            req.full_url, code,
            f"redirect to {newurl} blocked (file_url does not follow redirects)",
            headers, fp,
        )


def _is_safe_ip(ip: str) -> bool:
    """Return True iff `ip` is a public, routable address.

    Rejects:
      - loopback (127.0.0.0/8, ::1)
      - private (RFC1918, RFC4193)
      - link-local (169.254.0.0/16, fe80::/10) — includes cloud metadata
      - multicast / reserved / unspecified
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _validate_fetch_url(url: str, trusted_hosts: tuple[str, ...]) -> None:
    """Raise HandlerError unless `url` is safe to fetch.

    Layered checks (any one failure rejects):
      1. Scheme must be https.
      2. Hostname must be in trusted_hosts (exact match, case-insensitive).
      3. Hostname must resolve, AND every resolved IP must pass
         _is_safe_ip(). This catches DNS rebinding where the host is
         in the allowlist but resolves to a private IP.

    Note: this is TOCTOU-safe only for non-TOCTOU attackers — a
    pathological DNS server could return different IPs on the
    validation lookup vs urllib's lookup. In practice this is rare
    and would require also being in trusted_hosts, which already
    requires operator opt-in.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if not host:
        raise HandlerError("invalid_payload", "file_url has no hostname")

    if scheme != "https":
        raise HandlerError("invalid_payload", "file_url must be https")

    if not trusted_hosts:
        raise HandlerError(
            "fetch_blocked",
            "file_url fetching is disabled (trusted_fetch_hosts not configured). "
            f"Add hosts to security.trusted_fetch_hosts in {_pg.CONFIG_PATH}.",
        )

    allowed = {h.lower() for h in trusted_hosts}
    if host not in allowed:
        raise HandlerError(
            "fetch_blocked",
            f"hostname '{host}' isn't in security.trusted_fetch_hosts. Add "
            f"it there in {_pg.CONFIG_PATH} (operator approval), or "
            "send the bytes directly with content_base64 (inline) or the "
            "chunked upload path (upload_init/upload_chunk/upload_complete) "
            "instead of file_url.",
        )

    # Resolve and validate every returned IP. getaddrinfo can return
    # multiple IPv4/IPv6 for one hostname; reject if any is unsafe.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise HandlerError("fetch_failed", f"DNS resolution failed: {exc}") from exc

    for info in infos:
        ip = info[4][0]
        if not _is_safe_ip(ip):
            raise HandlerError(
                "fetch_blocked",
                f"hostname '{host}' resolved to a non-public IP {ip} "
                "(loopback/private/link-local). file_url only fetches public "
                "hosts (SSRF defense). To upload a local or private-network "
                "file, use content_base64 or the chunked upload path "
                "instead.",
            )


def _finalize(tmp: Path, dest: Path) -> None:
    """Move a finished file into place, atomically, across filesystems too.

    A rename can't cross filesystems, and the staging area (under upload_base)
    often isn't on the destination's: a WSL host writing to /mnt/c, a second
    disk, a bind mount. Path.replace then fails with EXDEV, "Invalid
    cross-device link", and a transfer that had moved every byte reported an
    internal error at the very end (sxrep_XW9FTRHAH0H7). On EXDEV, copy into a
    temp file in the destination's own directory and rename THAT, so the final
    name never points at a half-written file. Any other error is raised as is.
    """
    try:
        tmp.replace(dest)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    part = dest.parent / f".{dest.name}.sentinelx-{uuid.uuid4().hex[:8]}.part"
    try:
        shutil.copyfile(tmp, part)
        with open(part, "rb") as fh:
            os.fsync(fh.fileno())
        os.replace(part, dest)
    finally:
        if part.exists():
            part.unlink(missing_ok=True)
    tmp.unlink(missing_ok=True)


def _meta_file(upload_dir: Path) -> Path:
    return upload_dir / "meta.json"


def _parts_dir(upload_dir: Path) -> Path:
    d = upload_dir / "parts"
    d.mkdir(parents=True, exist_ok=True)
    return d


_UPLOAD_ID_RE = re.compile(r"^[0-9a-fA-F]{16,64}$")


def _validated_upload_id(provided: object) -> str:
    """Safe upload_id: the caller-provided one (hex, e.g. the Hub's transfer_id)
    if valid, else a fresh uuid4 hex. The id becomes a directory name under the
    staging root, so an invalid/traversal value is rejected."""
    if provided is None:
        return uuid.uuid4().hex
    if isinstance(provided, str) and _UPLOAD_ID_RE.match(provided):
        return provided.lower()
    raise HandlerError(
        "invalid_payload",
        "upload_id, when provided, must be a 16-64 char hex string",
    )


def write_transfer_part(upload_base: Path, upload_id: str, index: int, data: bytes) -> int:
    """Write one binary transfer chunk as a staged part (cross-host transfer).

    The raw-bytes sibling of upload_chunk: writes directly into the same
    {index:08d}.part layout that upload_complete reassembles + hashes + finalizes
    atomically. The staging dir must already exist (created by upload_init with a
    matching upload_id == the Hub's transfer_id)."""
    if index < 0:
        raise HandlerError("invalid_payload", "index must be >= 0")
    tmp_root = upload_base / ".sentinelx_uploads"
    upload_dir = tmp_root / upload_id
    if not _meta_file(upload_dir).exists():
        raise HandlerError("not_found", f"upload_id not found: {upload_id}")
    part_path = _parts_dir(upload_dir) / f"{index:08d}.part"
    part_path.write_bytes(bytes(data))
    return len(data)


async def _fetch_url(
    url: str,
    dest: Path,
    *,
    trusted_hosts: tuple[str, ...],
    timeout: int = 15,
) -> tuple[int, str]:
    """Download a URL into `dest`. Returns (size, sha256_hex).

    Validates against SSRF before the fetch (see _validate_fetch_url)
    and disables redirects so a vetted host can't bounce us elsewhere.
    """
    _validate_fetch_url(url, trusted_hosts)

    def _do_fetch() -> tuple[int, str]:
        # Build an opener with NoRedirectHandler so urllib won't auto-
        # follow Location headers — we re-validate any redirect target.
        opener = urllib.request.build_opener(_NoRedirectHandler())
        hasher = hashlib.sha256()
        size = 0
        try:
            with opener.open(url, timeout=timeout) as r, dest.open("wb") as f:
                while True:
                    block = r.read(CHUNK_READ_SIZE)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_UPLOAD_BYTES:
                        raise HandlerError(
                            "file_too_large",
                            f"file exceeds the agent's upload cap of "
                            f"{MAX_UPLOAD_BYTES} bytes. Split it into smaller "
                            "pieces or compress it; chunked upload has the "
                            "same limit.",
                        )
                    hasher.update(block)
                    f.write(block)
        except urllib.error.URLError as exc:
            raise HandlerError("fetch_failed", f"could not fetch URL: {exc}") from exc
        return size, hasher.hexdigest()

    return await asyncio.to_thread(_do_fetch)


def _decode_base64_to(content_b64: str, dest: Path) -> tuple[int, str]:
    try:
        raw = base64.b64decode(content_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise HandlerError("invalid_payload", f"bad base64: {exc}") from exc
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HandlerError(
            "file_too_large",
            f"decoded size {len(raw)} exceeds the agent's upload cap of "
            f"{MAX_UPLOAD_BYTES} bytes. Split or compress the file; chunked "
            "upload has the same limit.",
        )
    dest.write_bytes(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


_STAGING_DIR_NAME = ".sentinelx_uploads"


def _reject_staging_path(upload_base: Path, dest: Path) -> None:
    """upload_file must not write into the chunked-upload staging area: a forged
    meta.json there is the lever for writing outside upload_base at completion
    (GHSA-r2h3-76g7-m95x)."""
    staging = (upload_base / _STAGING_DIR_NAME).resolve()
    d = dest.resolve()
    if d == staging or staging in d.parents:
        raise HandlerError(
            "path_not_allowed",
            f"{_STAGING_DIR_NAME}/ is reserved for chunked uploads and can't be "
            "written to directly.",
        )


def _authorised_dest(meta: dict, upload_base: Path, policy: "Policy | None") -> Path:
    """Where a completed upload may land, re-derived from meta under upload_init's
    rules. Never trusts meta['target_path'] as-is (GHSA-r2h3-76g7-m95x)."""
    target = str(meta.get("target_path") or "")
    if not target:
        raise HandlerError("invalid_state", "upload has no target_path")
    if meta.get("landed_in_place"):
        if policy is None:
            raise HandlerError("path_not_allowed", "land-in-place not permitted here")
        resolved = policy.resolve_path(target, need_write=True)
        if resolved is None:
            raise HandlerError(
                "path_not_allowed",
                f"{target} is not inside a writable (rw) file_ops path.",
            )
        return resolved
    # Not landed: the meta stores an already-resolved absolute path under
    # upload_base. Verify it still resolves inside upload_base (don't re-hang it
    # under upload_base, which would both misplace a legit file and defuse the
    # check for a forged absolute target).
    dest = pathlib.Path(target).resolve()
    base = upload_base.resolve()
    if dest != base and base not in dest.parents:
        raise HandlerError(
            "path_traversal",
            f"target_path {target} is not under the agent's upload_base directory.",
        )
    return dest


def make_upload_file_handler(policy: Policy, upload_base: Path):
    """Single-call upload (small/medium files). Bytes inline or via URL."""

    async def handle_upload_file(payload: dict[str, Any]) -> dict[str, Any]:
        target_path = payload.get("target_path")
        overwrite = bool(payload.get("overwrite", False))
        filename = payload.get("filename")
        content_b64 = payload.get("content_base64")
        file_url = payload.get("file_url")

        if not target_path:
            raise HandlerError("invalid_payload", "missing 'target_path'")
        if (content_b64 is None) == (file_url is None):
            raise HandlerError(
                "invalid_payload",
                "provide exactly one of 'content_base64' or 'file_url'",
            )

        upload_base.mkdir(parents=True, exist_ok=True)
        try:
            dest = safe_path_under(upload_base, str(target_path))
        except ValueError as exc:
            raise HandlerError(
                "path_traversal",
                f"target_path rejected: {exc}. It must resolve to a location "
                "under the agent's upload_base directory; '..' or symlinks "
                "that escape upload_base are refused.",
            ) from exc

        _reject_staging_path(upload_base, dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and not overwrite:
            raise HandlerError(
                "conflict",
                f"a file already exists at {dest}. Pass overwrite=true to "
                "replace it.",
            )

        tmp_root = upload_base / ".sentinelx_uploads"
        tmp_root.mkdir(parents=True, exist_ok=True)
        tmp = tmp_root / f"{uuid.uuid4().hex}.upload"

        try:
            if content_b64 is not None:
                size, sha256 = _decode_base64_to(content_b64, tmp)
            else:
                size, sha256 = await _fetch_url(
                    file_url,
                    tmp,
                    trusted_hosts=policy.trusted_fetch_hosts,
                    timeout=policy.file_url_timeout_seconds,
                )
            _finalize(tmp, dest)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

        return {
            "ok": True,
            "mode": "single",
            "target_path": str(dest),
            "size": size,
            "sha256": sha256,
            "filename": filename,
        }

    return handle_upload_file


def make_upload_init_handler(upload_base: Path, policy: Policy | None = None):
    async def handle_upload_init(payload: dict[str, Any]) -> dict[str, Any]:
        target_path = payload.get("target_path")
        overwrite = bool(payload.get("overwrite", False))
        total_size = int(payload.get("total_size", 0) or 0)
        filename = payload.get("filename")
        # Opt-in: land at the real path when covered by an rw file_ops entry,
        # else fall back to staging (old behaviour). Additive, breaks nothing.
        land_in_place = bool(payload.get("land_in_place", False))

        if not target_path:
            raise HandlerError("invalid_payload", "missing 'target_path'")
        if total_size and total_size > MAX_UPLOAD_BYTES:
            raise HandlerError(
                "file_too_large",
                f"declared total_size {total_size} exceeds the agent's "
                f"upload cap of {MAX_UPLOAD_BYTES} bytes. Split or compress "
                "the file before uploading.",
            )

        upload_base.mkdir(parents=True, exist_ok=True)
        # Land-in-place only when asked AND under an rw file_ops entry.
        # resolve_path(need_write=True) canonicalises symlinks and defeats
        # '..' before the prefix check -- identical to move/delete -- so this
        # widens nothing already not opened rw. Not rw -> fall through to
        # staging, no failure.
        dest = None
        landed = False
        if land_in_place and policy is not None:
            resolved_rw = policy.resolve_path(str(target_path), need_write=True)
            if resolved_rw is not None:
                dest = resolved_rw
                landed = True
        if dest is None:
            try:
                dest = safe_path_under(upload_base, str(target_path))
            except ValueError as exc:
                raise HandlerError(
                    "path_traversal",
                    f"target_path rejected: {exc}. It must resolve to a location "
                    "under the agent's upload_base directory; '..' or symlinks "
                    "that escape upload_base are refused.",
                ) from exc

        if dest.exists() and not overwrite:
            raise HandlerError(
                "conflict",
                f"a file already exists at {dest}. Pass overwrite=true to "
                "replace it.",
            )

        upload_id = _validated_upload_id(payload.get("upload_id"))
        tmp_root = upload_base / ".sentinelx_uploads"
        upload_dir = tmp_root / upload_id
        _parts_dir(upload_dir)

        meta = {
            "upload_id": upload_id,
            "target_path": str(target_path) if landed else str(dest),
            "resolved_target": str(dest),
            "landed_in_place": landed,
            "overwrite": overwrite,
            "total_size": total_size,
            "filename": filename,
        }
        _meta_file(upload_dir).write_text(json.dumps(meta))

        return {
            "ok": True,
            "mode": "chunked",
            "upload_id": upload_id,
            "target_path": str(dest),
            "total_size": total_size,
        }

    return handle_upload_init


def make_upload_chunk_handler(upload_base: Path):
    async def handle_upload_chunk(payload: dict[str, Any]) -> dict[str, Any]:
        upload_id = payload.get("upload_id")
        index = payload.get("index")
        content_b64 = payload.get("content_base64")

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")
        if index is None:
            raise HandlerError("invalid_payload", "missing 'index'")
        if content_b64 is None:
            raise HandlerError("invalid_payload", "missing 'content_base64'")

        try:
            idx = int(index)
        except (TypeError, ValueError) as exc:
            raise HandlerError("invalid_payload", "index must be int") from exc
        if idx < 0:
            raise HandlerError("invalid_payload", "index must be >= 0")

        upload_id = _validated_upload_id(upload_id)
        tmp_root = upload_base / ".sentinelx_uploads"
        upload_dir = tmp_root / upload_id
        if not _meta_file(upload_dir).exists():
            raise HandlerError("not_found", f"upload_id not found: {upload_id}")

        try:
            data = base64.b64decode(content_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HandlerError("invalid_payload", f"bad base64: {exc}") from exc

        part_path = _parts_dir(upload_dir) / f"{idx:08d}.part"
        part_path.write_bytes(data)

        return {
            "ok": True,
            "upload_id": upload_id,
            "index": idx,
            "chunk_size": len(data),
        }

    return handle_upload_chunk


def make_upload_complete_handler(upload_base: Path, policy: "Policy | None" = None):
    async def handle_upload_complete(payload: dict[str, Any]) -> dict[str, Any]:
        upload_id = payload.get("upload_id")
        sha256_expected = payload.get("sha256")

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")

        tmp_root = upload_base / ".sentinelx_uploads"
        upload_dir = tmp_root / upload_id
        meta_file = _meta_file(upload_dir)
        if not meta_file.exists():
            raise HandlerError("not_found", f"upload_id not found: {upload_id}")

        upload_id = _validated_upload_id(upload_id)
        meta = json.loads(meta_file.read_text())
        # Re-authorise instead of trusting the meta (GHSA-r2h3-76g7-m95x).
        dest = _authorised_dest(meta, upload_base, policy)
        dest.parent.mkdir(parents=True, exist_ok=True)

        parts = sorted((upload_dir / "parts").glob("*.part"))
        if not parts:
            raise HandlerError("invalid_state", "no chunks uploaded")

        # Reassemble while hashing
        tmp = upload_dir / "assembled.bin"
        hasher = hashlib.sha256()
        total = 0

        def _assemble() -> None:
            nonlocal total
            with tmp.open("wb") as out:
                for part in parts:
                    with part.open("rb") as pf:
                        while True:
                            block = pf.read(CHUNK_READ_SIZE)
                            if not block:
                                break
                            total += len(block)
                            if total > MAX_UPLOAD_BYTES:
                                raise HandlerError(
                                    "file_too_large",
                                    f"reassembled size exceeded the agent's "
                                    f"upload cap of {MAX_UPLOAD_BYTES} bytes. "
                                    "Split or compress the file; this limit "
                                    "applies to chunked uploads too.",
                                )
                            hasher.update(block)
                            out.write(block)

        await asyncio.to_thread(_assemble)
        sha256 = hasher.hexdigest()

        # Validations
        expected_size = int(meta.get("total_size", 0) or 0)
        if expected_size and total != expected_size:
            raise HandlerError(
                "size_mismatch",
                f"expected {expected_size}, got {total}",
            )
        if sha256_expected:
            # Compare hex case-insensitively. hexdigest() is always lowercase,
            # so a correct digest written in uppercase -- the convention in many
            # manifests and record systems -- was rejected as a mismatch, with a
            # message saying the bytes were wrong when they were identical.
            # Reported with a three-chunk reproduction and a lowercase control
            # of the same payload that succeeded.
            #
            # A malformed value is told apart from a wrong one: "not valid hex"
            # and "the bytes differ" call for different responses, and the old
            # message gave both the same name.
            expected_norm = str(sha256_expected).strip().lower()
            try:
                bytes.fromhex(expected_norm)
            except ValueError:
                raise HandlerError(
                    "invalid_sha256",
                    f"{sha256_expected!r} is not a valid hex SHA-256 digest. "
                    "Expected 64 hexadecimal characters; case does not matter.",
                ) from None
            if len(expected_norm) != 64:
                raise HandlerError(
                    "invalid_sha256",
                    f"expected a 64-character hex SHA-256 digest, got "
                    f"{len(expected_norm)} characters.",
                )
            if expected_norm != sha256:
                raise HandlerError(
                    "checksum_mismatch",
                    f"sha256 does not match: the assembled file hashes to "
                    f"{sha256}, the upload declared {expected_norm}. The bytes "
                    "differ, so the upload is incomplete or corrupted.",
                )
        if dest.exists() and not meta.get("overwrite", False):
            raise HandlerError(
                "conflict",
                f"a file already exists at {dest}. Pass overwrite=true to "
                "replace it.",
            )

        _finalize(tmp, dest)
        shutil.rmtree(upload_dir, ignore_errors=True)

        return {
            "ok": True,
            "mode": "chunked",
            "upload_id": upload_id,
            "target_path": str(dest),
            "size": total,
            "sha256": sha256,
            "filename": meta.get("filename"),
        }

    return handle_upload_complete
