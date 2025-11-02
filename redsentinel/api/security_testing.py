# redsentinel/api/security_testing.py
import aiohttp
import logging
import json

logger = logging.getLogger(__name__)


async def test_api_endpoint(url, method="GET", headers=None, data=None):
    """
    Test an API endpoint for security issues
    
    Args:
        url: API endpoint URL
        method: HTTP method
        headers: Optional headers
        data: Optional request data
    
    Returns:
        dict with test results
    """
    results = {
        "url": url,
        "method": method,
        "status": None,
        "vulnerabilities": []
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            # Test different methods
            if method.upper() == "GET":
                async with session.get(url, headers=headers, timeout=10) as resp:
                    results["status"] = resp.status
                    await analyze_api_response(resp, results)
            elif method.upper() == "POST":
                async with session.post(url, headers=headers, json=data, timeout=10) as resp:
                    results["status"] = resp.status
                    await analyze_api_response(resp, results)
    
    except Exception as e:
        results["error"] = str(e)
        logger.error(f"API test error: {e}")
    
    return results


async def analyze_api_response(resp, results):
    """
    Analyze API response for security issues
    
    Args:
        resp: aiohttp response
        results: Results dict to update
    """
    headers = resp.headers
    
    # Check for security headers
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age",
        "Content-Security-Policy": None
    }
    
    missing_headers = []
    for header, required_value in security_headers.items():
        if header not in headers:
            missing_headers.append(header)
        elif required_value and required_value not in str(headers.get(header, "")):
            missing_headers.append(header)
    
    if missing_headers:
        results["vulnerabilities"].append({
            "type": "Missing Security Headers",
            "details": missing_headers,
            "severity": "MEDIUM"
        })
    
    # Check for information disclosure
    server_header = headers.get("Server", "")
    if server_header:
        results["vulnerabilities"].append({
            "type": "Information Disclosure",
            "details": f"Server: {server_header}",
            "severity": "LOW"
        })
    
    # Check for CORS misconfiguration
    cors_header = headers.get("Access-Control-Allow-Origin", "")
    if cors_header == "*":
        results["vulnerabilities"].append({
            "type": "CORS Misconfiguration",
            "details": "Allows all origins",
            "severity": "MEDIUM"
        })


async def test_graphql_introspection(url):
    """
    Test GraphQL introspection
    
    Args:
        url: GraphQL endpoint
    
    Returns:
        dict with introspection results
    """
    results = {
        "url": url,
        "introspection_enabled": False,
        "schema": None
    }
    
    introspection_query = {
        "query": "{ __schema { queryType { name } } }"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=introspection_query, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("data"):
                        results["introspection_enabled"] = True
                        results["schema"] = data.get("data")
    except Exception as e:
        logger.error(f"GraphQL introspection error: {e}")
    
    return results


async def discover_api_endpoints(base_url, common_paths=None):
    """
    Discover API endpoints
    
    Args:
        base_url: Base API URL
        common_paths: List of common API paths
    
    Returns:
        list of discovered endpoints
    """
    if common_paths is None:
        common_paths = [
            "/api/v1",
            "/api/v2",
            "/api",
            "/v1",
            "/v2",
            "/graphql",
            "/swagger.json",
            "/openapi.json",
            "/.well-known/openapi.json"
        ]
    
    discovered = []
    
    try:
        async with aiohttp.ClientSession() as session:
            for path in common_paths:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    async with session.get(url, timeout=10) as resp:
                        if resp.status in [200, 401, 403]:
                            discovered.append({
                                "url": url,
                                "status": resp.status,
                                "content_type": resp.headers.get("Content-Type", "")
                            })
                except Exception:
                    continue
    except Exception as e:
        logger.error(f"API discovery error: {e}")
    
    return discovered


async def comprehensive_api_security_scan(base_url):
    """
    Comprehensive API security scan
    
    Args:
        base_url: Base API URL
    
    Returns:
        dict with scan results
    """
    results = {
        "base_url": base_url,
        "endpoints": [],
        "vulnerabilities": [],
        "graphql": None
    }
    
    # Discover endpoints
    endpoints = await discover_api_endpoints(base_url)
    results["endpoints"] = endpoints
    
    # Test main API endpoint
    main_test = await test_api_endpoint(base_url)
    results["vulnerabilities"].extend(main_test.get("vulnerabilities", []))
    
    # Test GraphQL if found
    graphql_urls = [ep["url"] for ep in endpoints if "graphql" in ep["url"].lower()]
    if graphql_urls:
        graphql_test = await test_graphql_introspection(graphql_urls[0])
        results["graphql"] = graphql_test
    
    return results

