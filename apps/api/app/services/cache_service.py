import json
import time
from typing import Any, Dict, Optional
from app.core.config import settings

class CacheService:
    def __init__(self):
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        self._redis_client = None
        self._init_redis()

    def _init_redis(self):
        try:
            import redis
            self._redis_client = redis.Redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=1.0,
                socket_connect_timeout=1.0
            )
            # Test connection
            self._redis_client.ping()
        except Exception:
            self._redis_client = None

    def get(self, key: str) -> Optional[Any]:
        if self._redis_client:
            try:
                val = self._redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception:
                pass

        # In-memory fallback
        item = self._memory_cache.get(key)
        if item:
            if item["expires_at"] > time.time():
                return item["data"]
            else:
                del self._memory_cache[key]
        return None

    def set(self, key: str, value: Any, ttl: int = settings.ANALYSIS_CACHE_TTL_SECONDS):
        serialized = json.dumps(value)
        if self._redis_client:
            try:
                self._redis_client.setex(key, ttl, serialized)
                return
            except Exception:
                pass

        # In-memory fallback
        self._memory_cache[key] = {
            "data": value,
            "expires_at": time.time() + ttl
        }

    def delete(self, key: str):
        if self._redis_client:
            try:
                self._redis_client.delete(key)
            except Exception:
                pass
        self._memory_cache.pop(key, None)

cache_service = CacheService()
