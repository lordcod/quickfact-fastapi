
import uuid
from fastapi import APIRouter, HTTPException, Header, Request
from app.shared.clients.redis_client import client
from app.shared.protection.utils import POW_BITS

router = APIRouter()


@router.get("/")
async def get_challenge(
    request: Request,
    x_fp: str = Header(default="nofp")
):
    ip = request.client.host

    if await client.incr(f"rl:challenge:{ip}:{x_fp}") > 30:
        raise HTTPException(429, "Too many challenge requests")
    await client.expire(f"rl:challenge:{ip}:{x_fp}", 60)

    nonce = str(uuid.uuid4())
    await client.setex(f"nonce:{nonce}", 300, "1")

    return {"server_nonce": nonce, "pow_bits": POW_BITS}
