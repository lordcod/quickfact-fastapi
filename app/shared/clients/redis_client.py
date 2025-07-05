import redis.asyncio as redis
from app.core.config import REDIS_URL

pool = redis.ConnectionPool.from_url(REDIS_URL)
client = redis.Redis.from_pool(pool)
