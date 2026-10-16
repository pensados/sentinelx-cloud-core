"""Tests for upload handlers."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    p = Policy()
    object.__setattr__(p, "upload_base", tmp_path)
    return p


async def test_upload_file_inline_base64(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    payload = b"hello world\n" * 10
    b64 = base64.b64encode(payload).decode()

    result = await handlers["upload_file"]({
        "target_path": "test/hello.txt",
        "content_base64": b64,
        "filename": "hello.txt",
    })
    assert result["ok"] is True
    assert result["mode"] == "single"
    assert result["size"] == len(payload)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert Path(result["target_path"]).read_bytes() == payload


async def test_upload_file_rejects_path_traversal(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_file"]({
            "target_path": "../../../etc/passwd",
            "content_base64": base64.b64encode(b"hi").decode(),
        })
    assert exc.value.code == "path_traversal"


async def test_upload_file_conflict_when_exists(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    payload = b"first"
    b64 = base64.b64encode(payload).decode()

    # First write succeeds
    result1 = await handlers["upload_file"]({
        "target_path": "x.txt",
        "content_base64": b64,
    })
    assert result1["ok"] is True

    # Second without overwrite fails
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_file"]({
            "target_path": "x.txt",
            "content_base64": b64,
        })
    assert exc.value.code == "conflict"


async def test_upload_file_overwrite_works(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    b64a = base64.b64encode(b"first").decode()
    b64b = base64.b64encode(b"second").decode()

    await handlers["upload_file"]({"target_path": "x.txt", "content_base64": b64a})
    r = await handlers["upload_file"]({
        "target_path": "x.txt", "content_base64": b64b, "overwrite": True,
    })
    assert r["ok"] is True
    assert Path(r["target_path"]).read_bytes() == b"second"


async def test_upload_file_requires_one_source(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    # Neither source
    with pytest.raises(HandlerError):
        await handlers["upload_file"]({"target_path": "x.txt"})
    # Both sources
    with pytest.raises(HandlerError):
        await handlers["upload_file"]({
            "target_path": "x.txt",
            "content_base64": base64.b64encode(b"a").decode(),
            "file_url": "http://example.com",
        })


async def test_chunked_upload_full_cycle(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    payload = b"A" * 200_000  # 200 KB, split into 2 chunks of 100 KB
    chunk1 = payload[:100_000]
    chunk2 = payload[100_000:]

    init = await handlers["upload_init"]({
        "target_path": "big/file.bin",
        "total_size": len(payload),
        "filename": "file.bin",
    })
    assert init["ok"] is True
    upload_id = init["upload_id"]

    # Upload chunks
    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 0,
        "content_base64": base64.b64encode(chunk1).decode(),
    })
    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 1,
        "content_base64": base64.b64encode(chunk2).decode(),
    })

    # Complete with sha256 verification
    expected_sha = hashlib.sha256(payload).hexdigest()
    result = await handlers["upload_complete"]({
        "upload_id": upload_id,
        "sha256": expected_sha,
    })
    assert result["ok"] is True
    assert result["size"] == len(payload)
    assert result["sha256"] == expected_sha
    assert Path(result["target_path"]).read_bytes() == payload


async def test_chunked_upload_size_mismatch(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    init = await handlers["upload_init"]({
        "target_path": "x.bin",
        "total_size": 100,  # we'll only upload 5 bytes
    })
    upload_id = init["upload_id"]

    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 0,
        "content_base64": base64.b64encode(b"hello").decode(),
    })

    with pytest.raises(HandlerError) as exc:
        await handlers["upload_complete"]({"upload_id": upload_id})
    assert exc.value.code == "size_mismatch"


async def test_chunked_upload_checksum_mismatch(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    init = await handlers["upload_init"]({"target_path": "x.bin"})
    upload_id = init["upload_id"]

    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 0,
        "content_base64": base64.b64encode(b"hello").decode(),
    })

    with pytest.raises(HandlerError) as exc:
        await handlers["upload_complete"]({
            "upload_id": upload_id,
            "sha256": "0" * 64,  # definitely wrong
        })
    assert exc.value.code == "checksum_mismatch"


async def test_upload_complete_unknown_id(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_complete"]({"upload_id": "does-not-exist"})
    assert exc.value.code == "not_found"


async def test_upload_chunk_unknown_id(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    # A well-formed but unknown id still reports not_found.
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_chunk"]({
            "upload_id": "a" * 32,
            "index": 0,
            "content_base64": base64.b64encode(b"x").decode(),
        })
    assert exc.value.code == "not_found"


async def test_upload_chunk_malformed_id_is_rejected(policy: Policy) -> None:
    # A non-hex id (e.g. one with '..') is rejected before any filesystem access
    # (GHSA-r2h3-76g7-m95x).
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_chunk"]({
            "upload_id": "does-not-exist",
            "index": 0,
            "content_base64": base64.b64encode(b"x").decode(),
        })
    assert exc.value.code == "invalid_payload"


# ── SSRF defense for file_url ─────────────────────────────────────────────


async def test_file_url_blocked_by_default(policy: Policy) -> None:
    """Default policy has empty trusted_fetch_hosts → file_url disabled."""
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "https://drop.pensa.ar/abc",
        })
    assert exc_info.value.code == "fetch_blocked"


async def test_file_url_blocked_for_untrusted_host(policy: Policy) -> None:
    """Even with trusted hosts configured, a different host is rejected."""
    object.__setattr__(policy, "trusted_fetch_hosts", ("drop.pensa.ar",))
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "https://evil.example.com/abc",
        })
    assert exc_info.value.code == "fetch_blocked"


async def test_file_url_blocked_for_metadata_ip_literal(policy: Policy) -> None:
    """Even if the operator misconfigures the allowlist with a metadata
    IP, the IP-safety check rejects it."""
    object.__setattr__(policy, "trusted_fetch_hosts", ("169.254.169.254",))
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "https://169.254.169.254/latest/meta-data/",
        })
    assert exc_info.value.code == "fetch_blocked"


async def test_file_url_blocked_for_private_ip_literal(policy: Policy) -> None:
    """RFC1918 IPs in the allowlist are still rejected by IP safety."""
    object.__setattr__(policy, "trusted_fetch_hosts", ("10.0.0.5",))
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "https://10.0.0.5/admin",
        })
    assert exc_info.value.code == "fetch_blocked"


async def test_file_url_blocked_for_loopback_via_dns(policy: Policy) -> None:
    """A trusted hostname that resolves to 127.0.0.1 is rejected after
    DNS resolution. (This is the DNS-rebinding-at-config-time defense.)"""
    object.__setattr__(policy, "trusted_fetch_hosts", ("localhost",))
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "https://localhost/test",
        })
    assert exc_info.value.code == "fetch_blocked"


async def test_file_url_rejects_http_scheme(policy: Policy) -> None:
    """Even with a trusted host, http:// is rejected (https only)."""
    object.__setattr__(policy, "trusted_fetch_hosts", ("drop.pensa.ar",))
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "http://drop.pensa.ar/abc",
        })
    assert exc_info.value.code == "invalid_payload"


async def test_file_url_rejects_file_scheme(policy: Policy) -> None:
    """file:// can never reach the trusted-host check."""
    object.__setattr__(policy, "trusted_fetch_hosts", ("drop.pensa.ar",))
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "file:///etc/passwd",
        })
    assert exc_info.value.code == "invalid_payload"


async def test_file_url_rejects_url_without_hostname(policy: Policy) -> None:
    """URLs that parse without a hostname are rejected up front."""
    object.__setattr__(policy, "trusted_fetch_hosts", ("drop.pensa.ar",))
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc_info:
        await handlers["upload_file"]({
            "target_path": "x/y.txt",
            "file_url": "https:///path-only",
        })
    assert exc_info.value.code == "invalid_payload"
