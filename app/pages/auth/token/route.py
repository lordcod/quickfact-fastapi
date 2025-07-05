from fastapi import APIRouter, HTTPException, Request
from app.core.config import SECRET_KEY
from app.models.schemas import TokenRequest
from app.shared.clients.redis_client import client
from app.shared.protection.utils import verify_pow, verify_dpop, jwk_thumbprint
import time
from jose import jwt

router = APIRouter()


@router.post("/")
async def issue_token(data: TokenRequest, request: Request):
    ip = request.client.host

    # 1. Rate‑limit
    if await client.incr(f"rl:token:{ip}:{data.fingerprint}") > 5:
        raise HTTPException(429, "Too many token requests")
    await client.expire(f"rl:token:{ip}:{data.fingerprint}", 60)

    # 2. Nonce single‑use
    if not await client.delete(f"nonce:{data.server_nonce}"):
        raise HTTPException(400, "Nonce reused")

    # 3. PoW проверка
    verify_pow(data.server_nonce, data.nonce, data.fingerprint)

    # 4. DPoP валидатор
    try:
        verify_dpop(
            "POST",
            "http://localhost:8000/auth/token",
            data.dpop,
            data.jwk
        )
    except Exception as exc:
        raise HTTPException(400, "Bad DPoP") from exc

    thumbprint = jwk_thumbprint(data.jwk)

    # 5. JWT
    now = int(time.time())
    payload = {
        "sub": "anon",
        "iat": now,
        "exp": now + 120,
        "cnf": {"jkt": thumbprint, "jwk": data.jwk},
        "fp": data.fingerprint,
        "scopes": ["*"]
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return {"token": token}
