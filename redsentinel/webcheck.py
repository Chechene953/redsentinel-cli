# redsentinel/webcheck.py
import aiohttp

async def fetch_http_info(url, session=None, timeout=10):
    close = False
    if session is None:
        session = aiohttp.ClientSession()
        close = True
    try:
        async with session.get(url, allow_redirects=True, timeout=timeout) as resp:
            headers = dict(resp.headers)
            status = resp.status
            text_preview = (await resp.text())[:1000]
            return {"url": url, "status": status, "headers": headers, "preview": text_preview}
    except Exception as e:
        return {"url": url, "error": str(e)}
    finally:
        if close:
            await session.close()

def tls_info_from_host(host, port=443, timeout=3):
    import socket, ssl
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"subject": cert.get("subject"), "issuer": cert.get("issuer"), "notAfter": cert.get("notAfter")}
    except Exception as e:
        return {"error": str(e)}
