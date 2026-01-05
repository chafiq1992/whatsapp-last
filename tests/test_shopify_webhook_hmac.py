import hmac
import hashlib
from base64 import b64encode


def _expected_header(secret: str, body: bytes) -> str:
    return b64encode(hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()).decode("utf-8")


def test_verify_shopify_hmac_ok_plain_secret():
    from backend.shopify_webhook import verify_shopify_webhook_hmac

    secret = "mysecret"
    body = b'{"hello":"world"}'
    hdr = _expected_header(secret, body)
    ok, dbg = verify_shopify_webhook_hmac(secret, body, hdr)
    assert ok is True
    assert dbg["body_len"] == len(body)


def test_verify_shopify_hmac_ok_wrapping_quotes_are_ignored():
    from backend.shopify_webhook import verify_shopify_webhook_hmac

    secret_real = "mysecret"
    secret_env = f'"{secret_real}"'
    body = b'{"id":123}'
    hdr = _expected_header(secret_real, body)
    ok, _ = verify_shopify_webhook_hmac(secret_env, body, hdr)
    assert ok is True


def test_verify_shopify_hmac_ok_without_base64_padding():
    from backend.shopify_webhook import verify_shopify_webhook_hmac

    secret = "mysecret"
    body = b'{"pad":"test"}'
    hdr = _expected_header(secret, body)
    hdr_no_pad = hdr.rstrip("=")
    ok, _ = verify_shopify_webhook_hmac(secret, body, hdr_no_pad)
    assert ok is True


