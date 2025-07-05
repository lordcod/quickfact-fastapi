import time
import json
import hashlib
from urllib.parse import urlparse
from fastapi import HTTPException
from jose.utils import base64url_encode
from jose import jwt, jwk


POW_BITS = 5


def verify_pow(server_nonce: str, nonce: str, fingerprint: str):
    h = hashlib.sha256(
        f"{server_nonce}:{nonce}:{fingerprint}".encode()
    ).hexdigest()
    if not h.startswith("0" * (POW_BITS // 4)):
        raise HTTPException(400, "Bad PoW")


def jwk_thumbprint(jwk_pub: dict) -> str:
    """RFC 7638 thumbprint (base64url)"""
    canon = json.dumps({
        "crv": jwk_pub["crv"], "kty": jwk_pub["kty"],
        "x": jwk_pub["x"], "y": jwk_pub["y"]
    }, separators=(",", ":"), sort_keys=True).encode()
    return base64url_encode(hashlib.sha256(canon).digest()).decode()


def verify_dpop(method: str, url: str, dpop_jwt: str, jwk_pub: dict):
    header = jwt.get_unverified_header(dpop_jwt)
    alg = header["alg"]
    key = jwk.construct(jwk_pub, algorithm=alg)
    header = jwt.get_unverified_header(dpop_jwt)
    if header.get("typ") != "dpop+jwt":
        raise ValueError("wrong typ")
    payload = jwt.decode(dpop_jwt, key, algorithms=[header["alg"]])
    if payload["htm"] != method:
        raise ValueError("htm mismatch")
    if urlparse(payload["htu"]).path != urlparse(url).path:
        raise ValueError("htu mismatch")
    if abs(payload["iat"] - int(time.time())) > 3:
        raise ValueError("iat window")
    return True
