"""
GitHub Reconnaissance
Search for leaked secrets, exposed repositories, and organization intelligence
"""

import aiohttp
import asyncio
import re
from typing import List, Dict, Any, Optional
import logging
import base64

logger = logging.getLogger(__name__)


class GitHubRecon:
    """
    GitHub reconnaissance and OSINT collection
    Search for leaked credentials, API keys, and sensitive data
    """
    
    API_BASE = "https://api.github.com"
    SEARCH_CODE = f"{API_BASE}/search/code"
    SEARCH_REPOS = f"{API_BASE}/search/repositories"
    SEARCH_USERS = f"{API_BASE}/search/users"
    SEARCH_COMMITS = f"{API_BASE}/search/commits"
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'aws_secret[_\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
        'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'api_key': r'api[_\s]*key[_\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
        'password': r'password[_\s]*[=:]\s*["\']([^"\']{8,})',
        'token': r'token[_\s]*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})',
        'secret': r'secret[_\s]*[=:]\s*["\']([^"\']{8,})',
        'database_url': r'(mysql|postgresql|mongodb)://[^\s]+',
        'jwt': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
        'google_api': r'AIza[0-9A-Za-z_-]{35}',
        'stripe_key': r'sk_live_[0-9a-zA-Z]{24}',
        'github_token': r'gh[ps]_[A-Za-z0-9]{36}',
    }
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub recon
        
        Args:
            token: GitHub personal access token (increases rate limits)
        """
        self.token = token
        self.session = None
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'RedSentinel-OSINT'
        }
        
        if token:
            self.headers['Authorization'] = f'token {token}'
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def search_code(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search GitHub code
        
        Args:
            query: Search query
            limit: Maximum results
        
        Returns:
            List of code search results
        """
        try:
            results = []
            per_page = min(limit, 100)
            
            params = {
                'q': query,
                'per_page': per_page
            }
            
            async with self.session.get(self.SEARCH_CODE, params=params) as response:
                if response.status == 403:
                    logger.warning("GitHub API rate limit exceeded")
                    return []
                
                if response.status != 200:
                    logger.error(f"GitHub API error: {response.status}")
                    return []
                
                data = await response.json()
                items = data.get('items', [])
                
                for item in items[:limit]:
                    results.append({
                        'name': item.get('name'),
                        'path': item.get('path'),
                        'repository': item.get('repository', {}).get('full_name'),
                        'html_url': item.get('html_url'),
                        'git_url': item.get('git_url'),
                        'score': item.get('score')
                    })
                
                logger.info(f"Found {len(results)} code results for: {query}")
                return results
        
        except Exception as e:
            logger.error(f"Error searching code: {e}")
            return []
    
    async def search_repositories(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Search GitHub repositories
        
        Args:
            query: Search query
            limit: Maximum results
        
        Returns:
            List of repositories
        """
        try:
            results = []
            per_page = min(limit, 100)
            
            params = {
                'q': query,
                'per_page': per_page,
                'sort': 'updated'
            }
            
            async with self.session.get(self.SEARCH_REPOS, params=params) as response:
                if response.status != 200:
                    return []
                
                data = await response.json()
                items = data.get('items', [])
                
                for item in items[:limit]:
                    results.append({
                        'name': item.get('name'),
                        'full_name': item.get('full_name'),
                        'description': item.get('description'),
                        'html_url': item.get('html_url'),
                        'stars': item.get('stargazers_count'),
                        'forks': item.get('forks_count'),
                        'language': item.get('language'),
                        'created_at': item.get('created_at'),
                        'updated_at': item.get('updated_at')
                    })
                
                logger.info(f"Found {len(results)} repositories for: {query}")
                return results
        
        except Exception as e:
            logger.error(f"Error searching repositories: {e}")
            return []
    
    async def search_organization(self, org_name: str) -> Dict[str, Any]:
        """
        Get organization information and repositories
        
        Args:
            org_name: Organization name
        
        Returns:
            Organization data
        """
        try:
            # Get org info
            async with self.session.get(f"{self.API_BASE}/orgs/{org_name}") as response:
                if response.status != 200:
                    return {}
                
                org_data = await response.json()
            
            # Get org repos
            async with self.session.get(f"{self.API_BASE}/orgs/{org_name}/repos") as response:
                repos = await response.json() if response.status == 200 else []
            
            # Get org members
            async with self.session.get(f"{self.API_BASE}/orgs/{org_name}/members") as response:
                members = await response.json() if response.status == 200 else []
            
            return {
                'name': org_data.get('name'),
                'login': org_data.get('login'),
                'description': org_data.get('description'),
                'email': org_data.get('email'),
                'location': org_data.get('location'),
                'blog': org_data.get('blog'),
                'public_repos': org_data.get('public_repos'),
                'public_gists': org_data.get('public_gists'),
                'followers': org_data.get('followers'),
                'created_at': org_data.get('created_at'),
                'repositories': [{'name': r.get('name'), 'url': r.get('html_url')} for r in repos[:20]],
                'members': [{'login': m.get('login'), 'url': m.get('html_url')} for m in members[:20]],
                'member_count': len(members)
            }
        
        except Exception as e:
            logger.error(f"Error getting organization data: {e}")
            return {}
    
    async def search_leaked_secrets(self, target: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Search for leaked secrets and credentials
        
        Args:
            target: Target domain or organization name
        
        Returns:
            Dictionary of found secrets by type
        """
        results = {}
        
        try:
            # Search for various sensitive patterns
            searches = [
                f'{target} password',
                f'{target} api_key',
                f'{target} secret',
                f'{target} token',
                f'{target} private_key',
                f'{target} AWS_ACCESS_KEY',
                f'{target} database',
            ]
            
            for search_query in searches:
                logger.info(f"Searching for: {search_query}")
                code_results = await self.search_code(search_query, limit=30)
                
                if code_results:
                    pattern_type = search_query.split()[-1].lower()
                    if pattern_type not in results:
                        results[pattern_type] = []
                    
                    results[pattern_type].extend(code_results)
                
                # Rate limiting
                await asyncio.sleep(2)
            
            # Deduplicate
            for key in results:
                results[key] = [dict(t) for t in {tuple(d.items()) for d in results[key]}]
            
            logger.info(f"Found {sum(len(v) for v in results.values())} potential leaks")
            return results
        
        except Exception as e:
            logger.error(f"Error searching for secrets: {e}")
            return results
    
    async def search_exposed_emails(self, domain: str) -> List[str]:
        """
        Search for exposed email addresses
        
        Args:
            domain: Target domain
        
        Returns:
            List of email addresses
        """
        try:
            emails = set()
            
            # Search code for email patterns
            search_query = f'{domain} "@{domain}"'
            results = await self.search_code(search_query, limit=50)
            
            # Extract emails from results metadata
            email_pattern = r'[\w\.-]+@' + re.escape(domain)
            
            for result in results:
                # Check in name, path, repository name
                for field in ['name', 'path', 'repository']:
                    if field in result and result[field]:
                        found = re.findall(email_pattern, str(result[field]))
                        emails.update(found)
            
            logger.info(f"Found {len(emails)} email addresses for {domain}")
            return list(emails)
        
        except Exception as e:
            logger.error(f"Error searching emails: {e}")
            return []
    
    async def search_technology_stack(self, org_name: str) -> Dict[str, int]:
        """
        Identify technology stack from repositories
        
        Args:
            org_name: Organization name
        
        Returns:
            Dictionary of technologies and their usage count
        """
        try:
            repos = await self.search_repositories(f'org:{org_name}', limit=100)
            
            tech_stack = {}
            
            for repo in repos:
                lang = repo.get('language')
                if lang:
                    tech_stack[lang] = tech_stack.get(lang, 0) + 1
            
            # Sort by usage
            tech_stack = dict(sorted(tech_stack.items(), key=lambda x: x[1], reverse=True))
            
            logger.info(f"Identified {len(tech_stack)} technologies for {org_name}")
            return tech_stack
        
        except Exception as e:
            logger.error(f"Error identifying tech stack: {e}")
            return {}
    
    async def comprehensive_recon(self, target: str, target_type: str = 'domain') -> Dict[str, Any]:
        """
        Perform comprehensive GitHub reconnaissance
        
        Args:
            target: Target (domain, organization, or user)
            target_type: Type of target (domain, organization, user)
        
        Returns:
            Complete reconnaissance data
        """
        results = {
            'target': target,
            'target_type': target_type,
            'repositories': [],
            'code_matches': [],
            'leaked_secrets': {},
            'emails': [],
            'organization': {},
            'technology_stack': {}
        }
        
        try:
            if target_type == 'organization':
                # Organization recon
                results['organization'] = await self.search_organization(target)
                results['technology_stack'] = await self.search_technology_stack(target)
                results['repositories'] = await self.search_repositories(f'org:{target}', limit=50)
            
            elif target_type == 'domain':
                # Domain recon
                results['repositories'] = await self.search_repositories(target, limit=50)
                results['code_matches'] = await self.search_code(target, limit=100)
                results['emails'] = await self.search_exposed_emails(target)
            
            # Always search for leaked secrets
            results['leaked_secrets'] = await self.search_leaked_secrets(target)
            
            return results
        
        except Exception as e:
            logger.error(f"Error in comprehensive recon: {e}")
            return results


async def github_reconnaissance(target: str, token: Optional[str] = None, 
                               target_type: str = 'domain') -> Dict[str, Any]:
    """
    Convenience function for GitHub reconnaissance
    
    Args:
        target: Target (domain, organization, or user)
        token: GitHub personal access token
        target_type: Type of target
    
    Returns:
        Reconnaissance results
    """
    async with GitHubRecon(token=token) as github:
        return await github.comprehensive_recon(target, target_type)


# Export
__all__ = ['GitHubRecon', 'github_reconnaissance']

