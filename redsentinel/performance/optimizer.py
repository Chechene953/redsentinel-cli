"""
RedSentinel - Performance Optimizer
Author: Alexandre Tavares - Redsentinel
Version: 7.0

Performance optimizations:
- Multiprocessing for CPU-bound tasks
- Batch processing
- Resource management
- Memory optimization
- Connection pooling
- Caching strategies
"""

import asyncio
import logging
import multiprocessing as mp
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import time
import psutil
from functools import lru_cache, wraps

logger = logging.getLogger(__name__)


@dataclass
class ResourceMetrics:
    """System resource metrics"""
    cpu_percent: float
    memory_percent: float
    memory_available: int
    active_connections: int
    timestamp: datetime


class ResourceManager:
    """
    Manage system resources and prevent overload
    """
    
    def __init__(self, max_cpu: float = 80.0, max_memory: float = 80.0):
        self.max_cpu = max_cpu
        self.max_memory = max_memory
        self.process = psutil.Process()
    
    def get_metrics(self) -> ResourceMetrics:
        """Get current resource metrics"""
        return ResourceMetrics(
            cpu_percent=psutil.cpu_percent(interval=0.1),
            memory_percent=psutil.virtual_memory().percent,
            memory_available=psutil.virtual_memory().available,
            active_connections=len(self.process.connections()),
            timestamp=datetime.now()
        )
    
    def can_process(self) -> bool:
        """Check if system can handle more processing"""
        metrics = self.get_metrics()
        
        if metrics.cpu_percent > self.max_cpu:
            logger.warning(f"CPU usage high: {metrics.cpu_percent}%")
            return False
        
        if metrics.memory_percent > self.max_memory:
            logger.warning(f"Memory usage high: {metrics.memory_percent}%")
            return False
        
        return True
    
    async def wait_for_resources(self, timeout: float = 60.0):
        """Wait until resources are available"""
        start = time.time()
        
        while not self.can_process():
            if time.time() - start > timeout:
                raise TimeoutError("Timeout waiting for resources")
            
            await asyncio.sleep(1)
            logger.debug("Waiting for resources...")


class BatchProcessor:
    """
    Batch processing for efficiency
    """
    
    def __init__(
        self,
        batch_size: int = 100,
        flush_interval: float = 5.0
    ):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.batch: List[Any] = []
        self.last_flush = time.time()
        self.processor: Optional[Callable] = None
    
    def add(self, item: Any):
        """Add item to batch"""
        self.batch.append(item)
        
        # Auto-flush if batch full or time elapsed
        if (len(self.batch) >= self.batch_size or
            time.time() - self.last_flush >= self.flush_interval):
            self.flush()
    
    def flush(self):
        """Flush batch"""
        if not self.batch:
            return
        
        if self.processor:
            try:
                self.processor(self.batch)
            except Exception as e:
                logger.error(f"Batch processing error: {e}")
        
        self.batch.clear()
        self.last_flush = time.time()
    
    def set_processor(self, processor: Callable):
        """Set batch processor function"""
        self.processor = processor


class MultiprocessingPool:
    """
    Multiprocessing pool for CPU-bound tasks
    """
    
    def __init__(self, workers: Optional[int] = None):
        self.workers = workers or mp.cpu_count()
        self.pool: Optional[ProcessPoolExecutor] = None
        logger.info(f"Multiprocessing pool with {self.workers} workers")
    
    def __enter__(self):
        self.pool = ProcessPoolExecutor(max_workers=self.workers)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pool:
            self.pool.shutdown(wait=True)
    
    async def map_async(
        self,
        func: Callable,
        items: List[Any],
        chunk_size: Optional[int] = None
    ) -> List[Any]:
        """
        Map function over items in parallel
        
        Args:
            func: Function to apply
            items: Items to process
            chunk_size: Items per chunk
        
        Returns:
            List of results
        """
        if not self.pool:
            raise RuntimeError("Pool not initialized. Use 'with' statement.")
        
        chunk_size = chunk_size or max(1, len(items) // self.workers)
        
        loop = asyncio.get_event_loop()
        
        # Submit tasks
        futures = []
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            future = loop.run_in_executor(
                self.pool,
                _process_chunk,
                func,
                chunk
            )
            futures.append(future)
        
        # Wait for results
        results = []
        for future in asyncio.as_completed(futures):
            chunk_results = await future
            results.extend(chunk_results)
        
        return results


def _process_chunk(func: Callable, items: List[Any]) -> List[Any]:
    """Process a chunk of items (helper for multiprocessing)"""
    return [func(item) for item in items]


class MemoryOptimizer:
    """
    Memory optimization utilities
    """
    
    @staticmethod
    def chunk_generator(items: List[Any], chunk_size: int):
        """Generate chunks to avoid loading all items in memory"""
        for i in range(0, len(items), chunk_size):
            yield items[i:i+chunk_size]
    
    @staticmethod
    def clear_cache():
        """Clear all LRU caches"""
        # Find all cached functions and clear them
        import gc
        for obj in gc.get_objects():
            if hasattr(obj, 'cache_clear'):
                try:
                    obj.cache_clear()
                    logger.debug(f"Cleared cache for {obj}")
                except:
                    pass
    
    @staticmethod
    def get_size(obj: Any) -> int:
        """Get size of object in bytes"""
        import sys
        size = sys.getsizeof(obj)
        
        if isinstance(obj, dict):
            size += sum(MemoryOptimizer.get_size(k) + MemoryOptimizer.get_size(v) 
                       for k, v in obj.items())
        elif isinstance(obj, (list, tuple)):
            size += sum(MemoryOptimizer.get_size(item) for item in obj)
        
        return size


class CacheManager:
    """
    Advanced caching with TTL
    """
    
    def __init__(self, max_size: int = 1000, ttl: float = 3600.0):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: Dict[str, tuple] = {}  # key: (value, timestamp)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key not in self.cache:
            return None
        
        value, timestamp = self.cache[key]
        
        # Check TTL
        if time.time() - timestamp > self.ttl:
            del self.cache[key]
            return None
        
        return value
    
    def set(self, key: str, value: Any):
        """Set value in cache"""
        # Evict oldest if full
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.cache.keys(), 
                           key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]
        
        self.cache[key] = (value, time.time())
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
    
    def size(self) -> int:
        """Get cache size"""
        return len(self.cache)


def timed_cache(seconds: int = 3600):
    """
    Decorator for timed LRU cache
    
    Args:
        seconds: Cache TTL in seconds
    """
    def decorator(func):
        func = lru_cache(maxsize=128)(func)
        func.lifetime = timedelta(seconds=seconds)
        func.expiration = datetime.now() + func.lifetime
        
        @wraps(func)
        def wrapped_func(*args, **kwargs):
            if datetime.now() >= func.expiration:
                func.cache_clear()
                func.expiration = datetime.now() + func.lifetime
            
            return func(*args, **kwargs)
        
        return wrapped_func
    
    return decorator


class AsyncConnectionPool:
    """
    Connection pool for async operations
    """
    
    def __init__(self, factory: Callable, min_size: int = 5, max_size: int = 20):
        self.factory = factory
        self.min_size = min_size
        self.max_size = max_size
        self.pool: List[Any] = []
        self.in_use: List[Any] = []
        self.initialized = False
    
    async def initialize(self):
        """Initialize pool"""
        if self.initialized:
            return
        
        for _ in range(self.min_size):
            conn = await self.factory()
            self.pool.append(conn)
        
        self.initialized = True
        logger.info(f"Connection pool initialized with {self.min_size} connections")
    
    async def acquire(self):
        """Acquire connection from pool"""
        if not self.initialized:
            await self.initialize()
        
        if self.pool:
            conn = self.pool.pop()
        elif len(self.in_use) < self.max_size:
            conn = await self.factory()
        else:
            # Wait for available connection
            while not self.pool:
                await asyncio.sleep(0.1)
            conn = self.pool.pop()
        
        self.in_use.append(conn)
        return conn
    
    async def release(self, conn: Any):
        """Release connection back to pool"""
        if conn in self.in_use:
            self.in_use.remove(conn)
            self.pool.append(conn)
    
    async def close(self):
        """Close all connections"""
        for conn in self.pool + self.in_use:
            if hasattr(conn, 'close'):
                await conn.close()
        
        self.pool.clear()
        self.in_use.clear()


class PerformanceOptimizer:
    """
    Main performance optimizer orchestrator
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.resource_manager = ResourceManager(
            max_cpu=config.get('max_cpu', 80.0),
            max_memory=config.get('max_memory', 80.0)
        )
        self.cache_manager = CacheManager(
            max_size=config.get('cache_size', 1000),
            ttl=config.get('cache_ttl', 3600.0)
        )
        self.batch_processor = BatchProcessor(
            batch_size=config.get('batch_size', 100),
            flush_interval=config.get('flush_interval', 5.0)
        )
    
    async def optimize_scan(
        self,
        targets: List[str],
        scan_func: Callable
    ) -> List[Any]:
        """
        Optimize scan execution with multiprocessing and batching
        
        Args:
            targets: List of targets to scan
            scan_func: Scan function to apply
        
        Returns:
            List of scan results
        """
        logger.info(f"Optimizing scan for {len(targets)} targets")
        
        # Wait for resources if needed
        await self.resource_manager.wait_for_resources()
        
        # Use multiprocessing for CPU-bound scanning
        with MultiprocessingPool() as pool:
            results = await pool.map_async(scan_func, targets)
        
        return results
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance report"""
        metrics = self.resource_manager.get_metrics()
        
        return {
            'timestamp': metrics.timestamp.isoformat(),
            'cpu_percent': metrics.cpu_percent,
            'memory_percent': metrics.memory_percent,
            'memory_available_mb': metrics.memory_available / (1024 * 1024),
            'active_connections': metrics.active_connections,
            'cache_size': self.cache_manager.size(),
            'batch_size': len(self.batch_processor.batch),
        }


# Decorators for performance
def measure_time(func):
    """Decorator to measure function execution time"""
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        start = time.time()
        result = await func(*args, **kwargs)
        duration = time.time() - start
        logger.info(f"{func.__name__} took {duration:.2f}s")
        return result
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        logger.info(f"{func.__name__} took {duration:.2f}s")
        return result
    
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry function on failure"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying...")
                    await asyncio.sleep(delay)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying...")
                    time.sleep(delay)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Usage example
if __name__ == "__main__":
    async def main():
        config = {
            'max_cpu': 80.0,
            'max_memory': 80.0,
            'cache_size': 1000,
            'cache_ttl': 3600.0,
            'batch_size': 100
        }
        
        optimizer = PerformanceOptimizer(config)
        
        # Test optimization
        def dummy_scan(target):
            return f"Scanned {target}"
        
        targets = [f"target_{i}" for i in range(1000)]
        
        results = await optimizer.optimize_scan(targets, dummy_scan)
        
        print(f"Scanned {len(results)} targets")
        print(f"Performance report: {optimizer.get_performance_report()}")
    
    asyncio.run(main())

