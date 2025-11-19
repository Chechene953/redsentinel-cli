"""
Advanced Email Harvesting
Collect email addresses from multiple sources
- Search engines
- Web pages
- Social media
- Breach databases
- WHOIS records
- Certificate Transparency logs
"""

import aiohttp
import asyncio
import re
from typing import List, Dict, Any, Set, Optional
import logging
from urllib.parse import quote, urlencode

logger = logging.getLogger(__name__)


class EmailHarvester:
    """
    Advanced email harvesting from multiple sources
    """
    
    # Email regex patterns
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    def __init__(self):
        self.session = None
        self.collected_emails: Set[str] = set()
    
    async def __aenter__(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session = aiohttp.ClientSession(headers=headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def extract_emails(self, text: str, domain: Optional[str] = None) -> Set[str]:
        """
        Extract email addresses from text
        
        Args:
            text: Text to search
            domain: Filter by domain (optional)
        
        Returns:
            Set of email addresses
        """
        emails = set(re.findall(self.EMAIL_PATTERN, text, re.IGNORECASE))
        
        if domain:
            emails = {e for e in emails if e.lower().endswith(f'@{domain.lower()}')}
        
        # Validate emails
        valid_emails = set()
        for email in emails:
            email = email.lower().strip()
            # Basic validation
            if len(email) > 5 and '@' in email and '.' in email.split('@')[1]:
                valid_emails.add(email)
        
        return valid_emails
    
    async def harvest_from_url(self, url: str, domain: Optional[str] = None) -> Set[str]:
        """
        Harvest emails from a specific URL
        
        Args:
            url: Target URL
            domain: Filter by domain
        
        Returns:
            Set of emails found
        """
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    text = await response.text()
                    emails = self.extract_emails(text, domain)
                    logger.info(f"Found {len(emails)} emails from {url}")
                    return emails
        
        except Exception as e:
            logger.debug(f"Error harvesting from URL {url}: {e}")
        
        return set()
    
    async def harvest_from_google(self, domain: str, max_pages: int = 5) -> Set[str]:
        """
        Harvest emails using Google search (requires scraping)
        
        Args:
            domain: Target domain
            max_pages: Maximum search result pages
        
        Returns:
            Set of emails
        """
        emails = set()
        
        try:
            # Note: This is a simplified version
            # Production should use official Google Custom Search API
            search_queries = [
                f'@{domain}',
                f'email @{domain}',
                f'contact @{domain}',
                f'site:{domain} email',
                f'site:{domain} contact',
            ]
            
            for query in search_queries:
                logger.info(f"Searching: {query}")
                
                # This is a placeholder - actual implementation would need
                # proper Google search integration or custom search API
                # For now, we'll just return empty set
                # In production, implement proper search API integration
                
                await asyncio.sleep(2)  # Rate limiting
        
        except Exception as e:
            logger.error(f"Error harvesting from Google: {e}")
        
        return emails
    
    async def harvest_from_bing(self, domain: str, max_results: int = 50) -> Set[str]:
        """
        Harvest emails using Bing search API
        
        Args:
            domain: Target domain
            max_results: Maximum results
        
        Returns:
            Set of emails
        """
        emails = set()
        
        try:
            # Bing search queries
            queries = [
                f'@{domain}',
                f'site:{domain} email',
                f'site:{domain} contact',
            ]
            
            for query in queries:
                # Placeholder for Bing API integration
                # Would require Bing Search API key
                logger.debug(f"Bing search: {query}")
                await asyncio.sleep(1)
        
        except Exception as e:
            logger.error(f"Error harvesting from Bing: {e}")
        
        return emails
    
    async def harvest_from_hunter_io(self, domain: str, api_key: Optional[str] = None) -> Set[str]:
        """
        Harvest emails using Hunter.io API
        
        Args:
            domain: Target domain
            api_key: Hunter.io API key
        
        Returns:
            Set of emails
        """
        emails = set()
        
        if not api_key:
            logger.warning("Hunter.io API key not provided")
            return emails
        
        try:
            url = f'https://api.hunter.io/v2/domain-search'
            params = {
                'domain': domain,
                'api_key': api_key,
                'limit': 100
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if 'data' in data and 'emails' in data['data']:
                        for email_data in data['data']['emails']:
                            email = email_data.get('value')
                            if email:
                                emails.add(email.lower())
                    
                    logger.info(f"Hunter.io found {len(emails)} emails for {domain}")
        
        except Exception as e:
            logger.error(f"Error harvesting from Hunter.io: {e}")
        
        return emails
    
    async def harvest_from_clearbit(self, domain: str, api_key: Optional[str] = None) -> Set[str]:
        """
        Harvest emails using Clearbit API
        
        Args:
            domain: Target domain
            api_key: Clearbit API key
        
        Returns:
            Set of emails
        """
        emails = set()
        
        if not api_key:
            logger.warning("Clearbit API key not provided")
            return emails
        
        try:
            # Clearbit Prospector API
            url = f'https://prospector.clearbit.com/v1/people/search'
            headers = {'Authorization': f'Bearer {api_key}'}
            params = {'domain': domain, 'limit': 100}
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if 'results' in data:
                        for person in data['results']:
                            email = person.get('email')
                            if email:
                                emails.add(email.lower())
                    
                    logger.info(f"Clearbit found {len(emails)} emails for {domain}")
        
        except Exception as e:
            logger.error(f"Error harvesting from Clearbit: {e}")
        
        return emails
    
    async def harvest_from_website(self, domain: str, max_pages: int = 20) -> Set[str]:
        """
        Crawl website and extract emails
        
        Args:
            domain: Target domain
            max_pages: Maximum pages to crawl
        
        Returns:
            Set of emails
        """
        emails = set()
        visited_urls = set()
        urls_to_visit = [f'https://{domain}', f'https://www.{domain}']
        
        try:
            while urls_to_visit and len(visited_urls) < max_pages:
                url = urls_to_visit.pop(0)
                
                if url in visited_urls:
                    continue
                
                visited_urls.add(url)
                
                try:
                    async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status != 200:
                            continue
                        
                        text = await response.text()
                        
                        # Extract emails
                        found_emails = self.extract_emails(text, domain)
                        emails.update(found_emails)
                        
                        # Extract more URLs to visit
                        # Simple link extraction
                        links = re.findall(r'href=[\'"]?([^\'" >]+)', text)
                        for link in links:
                            if link.startswith('/'):
                                link = f'https://{domain}{link}'
                            elif link.startswith(f'http://{domain}') or link.startswith(f'https://{domain}'):
                                pass
                            else:
                                continue
                            
                            if link not in visited_urls and link not in urls_to_visit:
                                urls_to_visit.append(link)
                
                except Exception as e:
                    logger.debug(f"Error crawling {url}: {e}")
                    continue
                
                await asyncio.sleep(0.5)  # Rate limiting
            
            logger.info(f"Website crawl found {len(emails)} emails from {len(visited_urls)} pages")
        
        except Exception as e:
            logger.error(f"Error crawling website: {e}")
        
        return emails
    
    async def harvest_from_linkedin(self, company: str) -> Set[str]:
        """
        Harvest emails from LinkedIn (requires authentication)
        
        Args:
            company: Company name
        
        Returns:
            Set of emails
        """
        # Note: LinkedIn scraping requires authentication and is against ToS
        # This is a placeholder for legitimate API usage
        logger.warning("LinkedIn harvesting requires proper API access")
        return set()
    
    async def generate_email_patterns(self, domain: str, names: List[str]) -> Set[str]:
        """
        Generate potential email addresses based on common patterns
        
        Args:
            domain: Target domain
            names: List of names (first, last)
        
        Returns:
            Set of potential emails
        """
        emails = set()
        
        for name_data in names:
            if isinstance(name_data, str):
                parts = name_data.lower().split()
                if len(parts) >= 2:
                    first = parts[0]
                    last = parts[-1]
                else:
                    continue
            else:
                continue
            
            # Common patterns
            patterns = [
                f'{first}@{domain}',
                f'{last}@{domain}',
                f'{first}.{last}@{domain}',
                f'{first[0]}{last}@{domain}',
                f'{first}{last[0]}@{domain}',
                f'{first}_{last}@{domain}',
                f'{first}-{last}@{domain}',
                f'{last}.{first}@{domain}',
                f'{first}{last}@{domain}',
            ]
            
            emails.update(patterns)
        
        return emails
    
    async def comprehensive_harvest(self, domain: str, 
                                   hunter_api_key: Optional[str] = None,
                                   clearbit_api_key: Optional[str] = None,
                                   crawl_website: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive email harvesting
        
        Args:
            domain: Target domain
            hunter_api_key: Hunter.io API key
            clearbit_api_key: Clearbit API key
            crawl_website: Whether to crawl website
        
        Returns:
            Complete email harvesting results
        """
        results = {
            'domain': domain,
            'emails': set(),
            'sources': {},
            'patterns': []
        }
        
        try:
            tasks = []
            
            # Hunter.io
            if hunter_api_key:
                task = self.harvest_from_hunter_io(domain, hunter_api_key)
                tasks.append(('hunter_io', task))
            
            # Clearbit
            if clearbit_api_key:
                task = self.harvest_from_clearbit(domain, clearbit_api_key)
                tasks.append(('clearbit', task))
            
            # Website crawl
            if crawl_website:
                task = self.harvest_from_website(domain, max_pages=20)
                tasks.append(('website', task))
            
            # Execute all tasks
            for source, task in tasks:
                try:
                    emails = await task
                    results['sources'][source] = {
                        'count': len(emails),
                        'emails': list(emails)
                    }
                    results['emails'].update(emails)
                
                except Exception as e:
                    logger.error(f"Error harvesting from {source}: {e}")
                    results['sources'][source] = {
                        'count': 0,
                        'error': str(e)
                    }
            
            # Analyze email patterns
            email_patterns = {}
            for email in results['emails']:
                local_part = email.split('@')[0]
                
                # Detect pattern
                if '.' in local_part:
                    pattern = 'first.last'
                elif '_' in local_part:
                    pattern = 'first_last'
                elif '-' in local_part:
                    pattern = 'first-last'
                elif len(local_part) <= 10 and not any(c.isdigit() for c in local_part):
                    pattern = 'firstname'
                else:
                    pattern = 'unknown'
                
                email_patterns[pattern] = email_patterns.get(pattern, 0) + 1
            
            results['patterns'] = email_patterns
            results['emails'] = list(results['emails'])
            results['total_found'] = len(results['emails'])
            
            logger.info(f"Email harvest complete. Found {results['total_found']} emails")
            
            return results
        
        except Exception as e:
            logger.error(f"Error in comprehensive harvest: {e}")
            results['emails'] = list(results['emails'])
            return results


async def harvest_emails(domain: str, hunter_api_key: Optional[str] = None,
                        clearbit_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function for email harvesting
    
    Args:
        domain: Target domain
        hunter_api_key: Hunter.io API key
        clearbit_api_key: Clearbit API key
    
    Returns:
        Email harvesting results
    """
    async with EmailHarvester() as harvester:
        return await harvester.comprehensive_harvest(
            domain, 
            hunter_api_key=hunter_api_key,
            clearbit_api_key=clearbit_api_key
        )


# Export
__all__ = ['EmailHarvester', 'harvest_emails']

