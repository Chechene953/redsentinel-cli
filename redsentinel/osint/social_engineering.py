# redsentinel/osint/social_engineering.py
import aiohttp
import logging
import re

logger = logging.getLogger(__name__)


def extract_email_patterns(text):
    """
    Extract email patterns from text
    
    Args:
        text: Text to search
    
    Returns:
        set of email patterns
    """
    # Common email patterns
    patterns = []
    
    # Standard email regex
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_regex, text)
    
    patterns.extend(emails)
    
    return list(set(patterns))


async def search_github(organization):
    """
    Search GitHub for organization information
    
    Args:
        organization: Organization name
    
    Returns:
        dict with GitHub data
    """
    results = {
        "organization": organization,
        "repositories": [],
        "members": [],
        "email_patterns": []
    }
    
    # Note: GitHub API requires authentication for private info
    # This is a basic implementation
    api_url = f"https://api.github.com/orgs/{organization}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(api_url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results["public_info"] = data
    except Exception as e:
        logger.error(f"GitHub search error: {e}")
    
    return results


async def search_pastebin(domain):
    """
    Search Pastebin for domain mentions
    
    Args:
        domain: Domain to search for
    
    Returns:
        list of found pastes
    """
    # Note: Pastebin doesn't have a public API
    # This would require scraping or paid services
    # For now, return placeholder
    
    return {
        "domain": domain,
        "matches": [],
        "note": "Pastebin search requires API access or scraping"
    }


async def search_leak_db(domain):
    """
    Search for leaks involving a domain
    
    Args:
        domain: Domain to search
    
    Returns:
        dict with leak information
    """
    # Placeholder for leak database searches
    # Would integrate with services like:
    # - Have I Been Pwned
    # - LeakCheck
    # - WeLeakInfo
    
    return {
        "domain": domain,
        "leaks": [],
        "note": "Leak database search requires API access"
    }


async def discover_email_patterns(company_name):
    """
    Discover common email patterns for a company
    
    Args:
        company_name: Company name
    
    Returns:
        list of email patterns
    """
    patterns = [
        f"{{first}}.{{last}}@{company_name}.com",
        f"{{first}}{{last}}@{company_name}.com",
        f"{{first}}_{{last}}@{company_name}.com",
        f"{{first}}-{{last}}@{company_name}.com",
        f"{{f}}{{last}}@{company_name}.com",
        f"{{first}}{{l}}@{company_name}.com",
        f"{{first}}@{company_name}.com",
        f"{{last}}@{company_name}.com"
    ]
    
    return {
        "company": company_name,
        "patterns": patterns,
        "common_domains": [
            f"{company_name}.com",
            f"{company_name}.net",
            f"{company_name}.org"
        ]
    }

