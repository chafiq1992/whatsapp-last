import hmac
import hashlib
from base64 import b64encode


def _strip_wrapping_quotes(value: str) -> str:
    """Remove a single pair of wrapping quotes if present.

    Cloud Run / .env setups sometimes accidentally include quotes, e.g.
    SHOPIFY_WEBHOOK_SECRET_IRRAKIDS="deadbeef..."
    """
    s = (value or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1].strip()
    return s


def _is_hex_64(s: str) -> bool:
    t = (s or "").strip().lower()
    return len(t) == 64 and all(c in "0123456789abcdef" for c in t)


def _b64_variants(digest: bytes) -> list[str]:
    """Return common Shopify HMAC header variants (with/without base64 padding)."""
    b64 = b64encode(digest).decode("utf-8")
    no_pad = b64.rstrip("=")
    return [b64] if no_pad == b64 else [b64, no_pad]


def compute_shopify_hmac_candidates(secret: str, body: bytes) -> tuple[list[str], dict]:
    """Compute candidate `X-Shopify-Hmac-Sha256` header values.

    Shopify uses base64(HMAC_SHA256(secret, raw_body)).
    Some UIs show a 64-char hex secret; we tolerate both:
    - literal UTF-8 bytes of the secret string
    - hex-decoded bytes (if the secret looks like hex)
    """
    secret_norm = _strip_wrapping_quotes(secret)
    info = {
        "secret_len": len(secret_norm or ""),
        "secret_is_hex_64": bool(_is_hex_64(secret_norm)),
        "body_len": len(body or b""),
    }

    candidates: list[str] = []
    # Normal "secret as string" mode
    try:
        digest = hmac.new(secret_norm.encode("utf-8"), body or b"", hashlib.sha256).digest()
        candidates.extend(_b64_variants(digest))
    except Exception:
        pass

    # Optional: secret is actually a 64-hex string, and Shopify might be using raw bytes
    # (rare, but we keep it for compatibility with previous behavior).
    try:
        if _is_hex_64(secret_norm):
            key = bytes.fromhex(secret_norm.strip().lower())
            digest2 = hmac.new(key, body or b"", hashlib.sha256).digest()
            candidates.extend(_b64_variants(digest2))
    except Exception:
        pass

    # Deduplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out, info


def verify_shopify_webhook_hmac(secret: str, body: bytes, header_value: str | None) -> tuple[bool, dict]:
    """Verify Shopify webhook HMAC; returns (ok, safe_debug_info)."""
    hdr = (header_value or "").strip()
    candidates, info = compute_shopify_hmac_candidates(secret, body)

    ok = bool(hdr) and any(hmac.compare_digest(exp, hdr) for exp in candidates)

    # Provide safe debug info (no secrets, only prefixes/lengths) for logging on failure.
    debug = dict(info)
    debug.update(
        {
            "header_len": len(hdr or ""),
            "header_prefix": (hdr[:8] + "…") if hdr else "",
            "candidates": len(candidates),
            "candidate_prefixes": [(c[:8] + "…") for c in candidates[:3]],
        }
    )
    return ok, debug


