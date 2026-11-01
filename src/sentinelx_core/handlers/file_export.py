"""file_export handlers: binary-safe source-side export for cross-host transfer.

SOURCE side of the Hub's `sentinel_transfer_file` coordinator. INTERNAL ops
(driven by the Hub, NOT exposed as model-visible MCP tools). Per transfer:

    file_export_init      -> validate source under the file_ops READ allowlist,
                             stat it, register an export session; returns
                             {transfer_id, filename, size, chunk_size, num_chunks}
    file_export_chunk xN  -> read chunk `chunk_index`; the CLIENT layer emits it
                             as a raw binary frame [transfer_id|chunk_index|bytes]
                             (returned via "__binary_payload__", never JSON'd)
    file_export_complete  -> finalize; returns {sha256, size, chunks_read}

Security: the source path is gated exactly like read/list/search via
`policy.resolve_path(path, need_write=False)` (symlinks canonicalized), so it
never escapes the operator-approved read scope. rw is NOT required (this is a
read). The existing 64 KiB-capped `read` op is unsuitable for whole-file binary
export, hence this dedicated primitive.

sha256 is computed incrementally as chunks are read IN ORDER (the Hub pulls
sequentially with backpressure). The destination verifies it independently at
upload_complete, so this is an integrity cross-check, not the sole guarantee.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx_protocol import TRANSFER_CHUNK_BYTES

from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy

_SESSION_TTL_SECONDS = 3600


@dataclass
class _ExportSession:
    transfer_id: str
    path: Path
    size: int
    chunk_size: int
    num_chunks: int
    filename: str
    created_at: float
    hasher: Any = field(default_factory=hashlib.sha256)
    next_index: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


_sessions: dict[str, _ExportSession] = {}
_sessions_lock = threading.Lock()


def _sweep_locked(now: float) -> None:
    for tid in [t for t, s in _sessions.items() if now - s.created_at > _SESSION_TTL_SECONDS]:
        _sessions.pop(tid, None)


def _valid_transfer_id(tid: object) -> str:
    if not isinstance(tid, str) or len(tid) != 32:
        raise HandlerError("invalid_payload", "transfer_id must be a 32-char hex string (16 bytes)")
    try:
        bytes.fromhex(tid)
    except ValueError as exc:
        raise HandlerError("invalid_payload", f"transfer_id is not valid hex: {exc}") from exc
    return tid.lower()


def _stat_regular(p: Path) -> os.stat_result:
    try:
        st = p.stat()
    except FileNotFoundError as exc:
        raise HandlerError("not_found", f"source file not found: {p}") from exc
    except PermissionError as exc:
        raise HandlerError("permission_denied", f"cannot stat source (unix perms): {p}") from exc
    if stat.S_ISDIR(st.st_mode):
        raise HandlerError("is_directory", f"source is a directory, not a file: {p}")
    if not stat.S_ISREG(st.st_mode):
        raise HandlerError("not_a_file", f"source is not a regular file: {p}")
    return st


def make_file_export_init_handler(policy: Policy):
    async def handle(payload: dict[str, Any]) -> dict[str, Any]:
        transfer_id = _valid_transfer_id(payload.get("transfer_id"))
        src = payload.get("source_path")
        if not isinstance(src, str) or not src.strip():
            raise HandlerError("invalid_payload", "missing or non-string 'source_path'")
        try:
            chunk_size = int(payload.get("chunk_size") or TRANSFER_CHUNK_BYTES)
        except (TypeError, ValueError):
            chunk_size = TRANSFER_CHUNK_BYTES
        if not 0 < chunk_size <= TRANSFER_CHUNK_BYTES:
            chunk_size = TRANSFER_CHUNK_BYTES

        if not policy.file_ops_paths:
            raise HandlerError(
                "path_not_allowed",
                "file_ops has no paths configured in this agent's config; "
                "cannot export. Add an entry under file_ops.paths.",
            )
        resolved = policy.resolve_path(src, need_write=False)
        if resolved is None:
            raise HandlerError(
                "path_not_allowed",
                f"source_path {src!r} (or its target after resolving symlinks) is "
                "not under any configured file_ops path. Reading requires access "
                "'r' or 'rw' on a covering entry.",
            )
        st = _stat_regular(resolved)
        size = int(st.st_size)
        num_chunks = ((size + chunk_size - 1) // chunk_size) or 1  # >=1 (empty file -> 1 empty chunk)

        now = time.time()
        sess = _ExportSession(
            transfer_id=transfer_id, path=resolved, size=size, chunk_size=chunk_size,
            num_chunks=num_chunks, filename=resolved.name, created_at=now,
        )
        with _sessions_lock:
            _sweep_locked(now)
            _sessions[transfer_id] = sess
        return {
            "transfer_id": transfer_id,
            "filename": resolved.name,
            "source_path": str(resolved),
            "size": size,
            "chunk_size": chunk_size,
            "num_chunks": num_chunks,
        }
    return handle


def make_file_export_chunk_handler(policy: Policy):
    async def handle(payload: dict[str, Any]) -> dict[str, Any]:
        transfer_id = _valid_transfer_id(payload.get("transfer_id"))
        try:
            index = int(payload.get("chunk_index"))
        except (TypeError, ValueError) as exc:
            raise HandlerError("invalid_payload", "chunk_index must be an int") from exc
        with _sessions_lock:
            sess = _sessions.get(transfer_id)
        if sess is None:
            raise HandlerError(
                "not_found",
                f"no export session for transfer_id {transfer_id} "
                "(expired or file_export_init was never called)",
            )
        if not 0 <= index < sess.num_chunks:
            raise HandlerError(
                "invalid_payload",
                f"chunk_index {index} out of range (num_chunks={sess.num_chunks})",
            )

        def _read_and_hash() -> tuple[bytes, bool]:
            with sess.lock:
                with sess.path.open("rb") as f:
                    f.seek(index * sess.chunk_size)
                    data = f.read(sess.chunk_size)
                if index == sess.next_index:
                    sess.hasher.update(data)
                    sess.next_index += 1
                return data, (index + 1 >= sess.num_chunks)

        data, eof = await asyncio.to_thread(_read_and_hash)
        return {
            "transfer_id": transfer_id,
            "chunk_index": index,
            "__binary_payload__": data,
            "bytes": len(data),
            "eof": eof,
        }
    return handle


def make_file_export_complete_handler():
    async def handle(payload: dict[str, Any]) -> dict[str, Any]:
        transfer_id = _valid_transfer_id(payload.get("transfer_id"))
        with _sessions_lock:
            sess = _sessions.pop(transfer_id, None)
        if sess is None:
            raise HandlerError("not_found", f"no export session for transfer_id {transfer_id}")
        in_order = sess.next_index == sess.num_chunks
        return {
            "transfer_id": transfer_id,
            "size": sess.size,
            "chunks_read": sess.next_index,
            "num_chunks": sess.num_chunks,
            "sha256": sess.hasher.hexdigest() if in_order else None,
            "sha256_complete": in_order,
        }
    return handle
