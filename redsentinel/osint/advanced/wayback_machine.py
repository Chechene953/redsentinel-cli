"""
Wayback Machine Integration
Retrieve historical data from Internet Archive
"""

import aiohttp
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class WaybackMachine:
    """
    Wayback Machine API client
    Retrieve historical snapshots and URLs
    """
    
    CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
    ARCHIVE_URL = "https://web.archive.org/web/{timestamp}/{url}"
    AVAILABILITY_API = "https://archive.org/wayback/available"
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_snapshots(self, url: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get historical snapshots for a URL
        
        Args:
            url: Target URL
            limit: Maximum number of snapshots
        
        Returns:
            List of snapshot records
        """
        try:
            params = {
                'url': url,
                'output': 'json',
                'limit': limit,
                'filter': 'statuscode:200'
            }
            
            async with self.session.get(self.CDX_API_URL, params=params) as response:
                if response.status != 200:
                    logger.error(f"Wayback API error: {response.status}")
                    return []
                
                data = await response.json()
                
                if not data or len(data) < 2:
                    return []
                
                # First row is headers
                headers = data[0]
                snapshots = []
                
                for row in data[1:]:
                    snapshot = dict(zip(headers, row))
                    
                    # Parse timestamp
                    ts = snapshot.get('timestamp', '')
                    if len(ts) == 14:
                        try:
                            dt = datetime.strptime(ts, '%Y%m%d%H%M%S')
                            snapshot['datetime'] = dt.isoformat()
                        except:
                            pass
                    
                    # Add archive URL
                    snapshot['archive_url'] = self.ARCHIVE_URL.format(
                        timestamp=snapshot.get('timestamp', ''),
                        url=snapshot.get('original', '')
                    )
                    
                    snapshots.append(snapshot)
                
                logger.info(f"Found {len(snapshots)} snapshots for {url}")
                return snapshots
        
        except Exception as e:
            logger.error(f"Error getting Wayback snapshots: {e}")
            return []
    
    async def get_latest_snapshot(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get the latest available snapshot
        
        Args:
            url: Target URL
        
        Returns:
            Latest snapshot info or None
        """
        try:
            params = {'url': url}
            
            async with self.session.get(self.AVAILABILITY_API, params=params) as response:
                if response.status != 200:
                    return None
                
                data = await response.json()
                
                if 'archived_snapshots' in data and 'closest' in data['archived_snapshots']:
                    snapshot = data['archived_snapshots']['closest']
                    return {
                        'available': snapshot.get('available', False),
                        'url': snapshot.get('url', ''),
                        'timestamp': snapshot.get('timestamp', ''),
                        'status': snapshot.get('status', '')
                    }
                
                return None
        
        except Exception as e:
            logger.error(f"Error getting latest snapshot: {e}")
            return None
    
    async def get_urls_by_pattern(self, domain: str, url_pattern: str = '*', 
                                  limit: int = 1000) -> List[str]:
        """
        Get URLs matching a pattern from archives
        
        Args:
            domain: Target domain
            url_pattern: URL pattern (* for wildcard)
            limit: Maximum results
        
        Returns:
            List of URLs
        """
        try:
            params = {
                'url': f"{domain}/{url_pattern}",
                'output': 'json',
                'fl': 'original',
                'collapse': 'original',
                'limit': limit
            }
            
            async with self.session.get(self.CDX_API_URL, params=params) as response:
                if response.status != 200:
                    return []
                
                data = await response.json()
                
                if not data:
                    return []
                
                # Extract unique URLs
                urls = list(set([row[0] for row in data if row]))
                
                logger.info(f"Found {len(urls)} archived URLs for {domain}")
                return urls
        
        except Exception as e:
            logger.error(f"Error getting URLs: {e}")
            return []
    
    async def search_historical_content(self, domain: str, keyword: str, 
                                       limit: int = 50) -> List[Dict[str, Any]]:
        """
        Search for keyword in historical content
        
        Args:
            domain: Target domain
            keyword: Search keyword
            limit: Maximum results
        
        Returns:
            List of matches
        """
        try:
            # Get snapshots
            snapshots = await self.get_snapshots(domain, limit=limit)
            
            # For each snapshot, check content (simplified - actual implementation would fetch content)
            # This is a basic version - full implementation would require fetching actual content
            results = []
            
            for snapshot in snapshots[:limit]:
                results.append({
                    'url': snapshot.get('original', ''),
                    'archive_url': snapshot.get('archive_url', ''),
                    'timestamp': snapshot.get('timestamp', ''),
                    'note': 'Content search requires fetching archived pages'
                })
            
            return results
        
        except Exception as e:
            logger.error(f"Error searching historical content: {e}")
            return []
    
    async def get_technology_history(self, domain: str) -> Dict[str, Any]:
        """
        Track technology changes over time
        
        Args:
            domain: Target domain
        
        Returns:
            Technology history data
        """
        try:
            snapshots = await self.get_snapshots(domain, limit=200)
            
            # Group by year
            tech_timeline = {}
            
            for snapshot in snapshots:
                ts = snapshot.get('timestamp', '')
                if len(ts) >= 4:
                    year = ts[:4]
                    
                    if year not in tech_timeline:
                        tech_timeline[year] = {
                            'year': year,
                            'snapshots': 0,
                            'mime_types': set(),
                            'status_codes': set()
                        }
                    
                    tech_timeline[year]['snapshots'] += 1
                    
                    if 'mimetype' in snapshot:
                        tech_timeline[year]['mime_types'].add(snapshot['mimetype'])
                    
                    if 'statuscode' in snapshot:
                        tech_timeline[year]['status_codes'].add(snapshot['statuscode'])
            
            # Convert sets to lists for JSON serialization
            for year, data in tech_timeline.items():
                data['mime_types'] = list(data['mime_types'])
                data['status_codes'] = list(data['status_codes'])
            
            return {
                'domain': domain,
                'timeline': list(tech_timeline.values()),
                'total_snapshots': len(snapshots)
            }
        
        except Exception as e:
            logger.error(f"Error getting technology history: {e}")
            return {}


async def search_wayback(domain: str, limit: int = 100) -> Dict[str, Any]:
    """
    Convenience function for Wayback Machine search
    
    Args:
        domain: Target domain
        limit: Maximum snapshots
    
    Returns:
        Wayback data
    """
    async with WaybackMachine() as wayback:
        snapshots = await wayback.get_snapshots(domain, limit=limit)
        latest = await wayback.get_latest_snapshot(domain)
        urls = await wayback.get_urls_by_pattern(domain, limit=500)
        tech_history = await wayback.get_technology_history(domain)
        
        return {
            'snapshots': snapshots,
            'snapshot_count': len(snapshots),
            'latest_snapshot': latest,
            'archived_urls': urls,
            'url_count': len(urls),
            'technology_history': tech_history
        }


# Export
__all__ = ['WaybackMachine', 'search_wayback']

