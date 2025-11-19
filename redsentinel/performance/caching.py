"""
Caching - In-memory and Redis caching for performance
Reduces redundant operations and API calls
"""

import time
import json
import hashlib
from typing import Any, Optional, Dict
from functools import wraps
import logging

logger = logging.getLogger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None


class InMemoryCache:
    """
    Simple in-memory cache with TTL
    
    Features:
    - TTL support
    - Size limits
    - LRU eviction
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key not in self.cache:
            return None
        
        entry = self.cache[key]
        
        # Check if expired
        if entry['expires_at'] < time.time():
            del self.cache[key]
            return None
        
        # Update access time for LRU
        entry['last_accessed'] = time.time()
        
        return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache"""
        if ttl is None:
            ttl = self.default_ttl
        
        # Evict old entries if cache is full
        if len(self.cache) >= self.max_size:
            self._evict_lru()
        
        self.cache[key] = {
            'value': value,
            'expires_at': time.time() + ttl,
            'last_accessed': time.time()
        }
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if key in self.cache:
            del self.cache[key]
            return True
        return False
    
    def clear(self):
        """Clear all cache"""
        self.cache.clear()
    
    def _evict_lru(self):
        """Evict least recently used entry"""
        if not self.cache:
            return
        
        # Find LRU entry
        lru_key = min(self.cache.items(), key=lambda x: x[1]['last_accessed'])[0]
        del self.cache[lru_key]


class RedisCache:
    """
    Redis-based distributed cache
    
    Features:
    - Distributed caching
    - Persistence
    - High performance
    """
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0, default_ttl: int = 3600):
        if not REDIS_AVAILABLE:
            logger.error("Redis not installed")
            self.client = None
            return
        
        try:
            self.client = redis.Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=True
            )
            
            # Test connection
            self.client.ping()
            logger.info(f"Connected to Redis at {host}:{port}")
        
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.client = None
        
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from Redis"""
        if not self.client:
            return None
        
        try:
            value = self.client.get(key)
            if value:
                return json.loads(value)
            return None
        
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in Redis"""
        if not self.client:
            return
        
        if ttl is None:
            ttl = self.default_ttl
        
        try:
            self.client.setex(
                key,
                ttl,
                json.dumps(value)
            )
        
        except Exception as e:
            logger.error(f"Redis set error: {e}")
    
    def delete(self, key: str) -> bool:
        """Delete key from Redis"""
        if not self.client:
            return False
        
        try:
            return self.client.delete(key) > 0
        
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    def clear(self):
        """Clear all keys (use with caution!)"""
        if not self.client:
            return
        
        try:
            self.client.flushdb()
        
        except Exception as e:
            logger.error(f"Redis clear error: {e}")


class CacheManager:
    """
    Unified cache manager supporting multiple backends
    
    Features:
    - Automatic backend selection
    - Fallback to in-memory if Redis unavailable
    - Cache key generation
    """
    
    def __init__(self, use_redis: bool = False):
        self.use_redis = use_redis
        
        if use_redis and REDIS_AVAILABLE:
            from redsentinel.core.config_manager import config
            
            redis_host = config.get('performance.redis_host', 'localhost')
            redis_port = config.get('performance.redis_port', 6379)
            cache_ttl = config.get('performance.cache_ttl', 3600)
            
            self.backend = RedisCache(redis_host, redis_port, default_ttl=cache_ttl)
            
            # Fallback to in-memory if Redis connection failed
            if not self.backend.client:
                logger.warning("Falling back to in-memory cache")
                self.backend = InMemoryCache(default_ttl=cache_ttl)
        else:
            self.backend = InMemoryCache()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return self.backend.get(key)
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache"""
        self.backend.set(key, value, ttl)
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        return self.backend.delete(key)
    
    def clear(self):
        """Clear cache"""
        self.backend.clear()
    
    @staticmethod
    def generate_key(*args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = json.dumps({
            'args': args,
            'kwargs': kwargs
        }, sort_keys=True)
        
        return hashlib.md5(key_data.encode()).hexdigest()


# Global cache manager
_cache_manager = None


def get_cache_manager() -> CacheManager:
    """Get global cache manager"""
    global _cache_manager
    
    if _cache_manager is None:
        from redsentinel.core.config_manager import config
        
        enable_caching = config.get('performance.enable_caching', True)
        use_redis = REDIS_AVAILABLE and config.get('performance.redis_host')
        
        if enable_caching:
            _cache_manager = CacheManager(use_redis=use_redis)
        else:
            _cache_manager = CacheManager(use_redis=False)
    
    return _cache_manager


def cached(ttl: Optional[int] = None):
    """
    Decorator to cache function results
    
    Usage:
        @cached(ttl=300)
        def expensive_function(arg1, arg2):
            return result
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache_manager()
            
            # Generate cache key
            cache_key = f"{func.__name__}_{CacheManager.generate_key(*args, **kwargs)}"
            
            # Try to get from cache
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit: {func.__name__}")
                return cached_result
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Store in cache
            cache.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    return decorator


# Example usage
if __name__ == "__main__":
    cache = CacheManager()
    
    # Set value
    cache.set("test_key", {"data": "test_value"}, ttl=60)
    
    # Get value
    value = cache.get("test_key")
    print(f"Cached value: {value}")
    
    # Test cached decorator
    @cached(ttl=30)
    def expensive_computation(x, y):
        print("Computing...")
        time.sleep(1)
        return x + y
    
    print("First call (will compute):")
    result1 = expensive_computation(5, 3)
    print(f"Result: {result1}")
    
    print("\nSecond call (from cache):")
    result2 = expensive_computation(5, 3)
    print(f"Result: {result2}")
