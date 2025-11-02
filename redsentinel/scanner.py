# redsentinel/scanner.py
import asyncio, socket

async def tcp_connect(host, port, timeout=3):
    loop = asyncio.get_event_loop()
    try:
        fut = loop.run_in_executor(None, lambda: _sync_connect(host, port, timeout))
        return await asyncio.wait_for(fut, timeout+1)
    except Exception:
        return False

def _sync_connect(host, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

async def scan_ports(host, ports, concurrency=100):
    sem = asyncio.Semaphore(concurrency)
    async def scan_one(p):
        async with sem:
            open_ = await tcp_connect(host, p)
            return p, open_
    tasks = [scan_one(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return {p: o for p,o in results}
