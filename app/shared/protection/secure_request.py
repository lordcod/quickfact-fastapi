import time
from typing import Iterable, Set, Dict, Any

from fastapi import Header, HTTPException, Request
from jose import jwt

from app.core.config import SECRET_KEY
from app.shared.clients.redis_client import client
from app.shared.protection.utils import verify_dpop, jwk_thumbprint


class SecureRequest:
    """Depends‑валидатор Zero‑Trust с настраиваемыми правами."""

    RATE_LIMIT = 60          # req / minute per thumbprint

    def __init__(self, required_scopes: Iterable[str] | None = None) -> None:
        self.required_scopes: Set[str] = set(required_scopes or [])

    # ──────────────────────────────────────────────────────────
    # public API (вызывается FastAPI)
    # ──────────────────────────────────────────────────────────

    async def __call__(
        self,
        request: Request,
        x_page_token: str = Header(alias="X-Page-Token"),
        dpop:         str = Header(alias="DPoP"),
        x_fp:          str = Header(alias="X-FP"),
    ) -> Dict[str, Any]:
        payload = self._parse_and_verify_token(x_page_token)
        self._check_fingerprint(payload, x_fp)
        thumb = self._check_dpop(request, dpop, payload)
        await self._rate_limit(thumb)
        self._check_scopes(payload)

        # проброс в request.state (при желании)
        request.state.jwt = payload
        request.state.user = payload.get("sub", "anon")
        request.state.scope = set(payload.get("scopes", []))

        return payload

    # ──────────────────────────────────────────────────────────
    # private helpers
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _unauth(msg: str) -> None:
        raise HTTPException(401, msg)

    @staticmethod
    def _forbid(msg: str) -> None:
        raise HTTPException(403, msg)

    # 1. JWT ----------------------------------------------------
    def _parse_and_verify_token(self, token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except Exception:
            self._unauth("Bad token")

        if payload["exp"] < int(time.time()):
            self._unauth("Token expired")

        return payload

    # 2. Fingerprint -------------------------------------------
    def _check_fingerprint(self, payload: Dict[str, Any], x_fp: str) -> None:
        if x_fp != payload.get("fp"):
            self._forbid("FP mismatch")

    # 3. DPoP (+ thumbprint) -----------------------------------
    def _check_dpop(
        self, request: Request, dpop_jwt: str, payload: Dict[str, Any]
    ) -> str:
        jwk_pub = payload["cnf"]["jwk"]
        thumb = payload["cnf"]["jkt"]

        if jwk_thumbprint(jwk_pub) != thumb:
            self._forbid("jkt mismatch")

        try:
            verify_dpop(
                request.method,
                str(request.url),
                dpop_jwt,
                jwk_pub
            )
        except Exception as exc:
            print(exc, type(exc))
            raise HTTPException(400, "Bad DPoP")

        return thumb

    # 4. Rate‑limit -------------------------------------------
    async def _rate_limit(self, thumb: str) -> None:
        key = f"rl:req:{thumb}"
        if await client.incr(key) > self.RATE_LIMIT:
            raise HTTPException(429, "Too fast")
        await client.expire(key, 60)

    # 5. Scopes -----------------------------------------------
    def _check_scopes(self, payload: Dict[str, Any]) -> None:
        token_scopes = set(payload.get("scopes", []))
        if "*" in token_scopes:
            return                          # супер‑права
        if not self.required_scopes.issubset(token_scopes):
            self._forbid("scope denied")
