"""
Cloud Asset Discovery
Discover exposed cloud storage buckets and assets (AWS S3, Azure Blob, GCP, etc.)
"""

import aiohttp
import asyncio
from typing import List, Dict, Any, Optional
import logging
import re

logger = logging.getLogger(__name__)


class CloudAssetDiscovery:
    """
    Discover exposed cloud storage assets
    - AWS S3 buckets
    - Azure Blob storage
    - Google Cloud Storage
    - DigitalOcean Spaces
    - CloudFront distributions
    """
    
    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def check_s3_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """
        Check if S3 bucket exists and is accessible
        
        Args:
            bucket_name: S3 bucket name
        
        Returns:
            Bucket information
        """
        result = {
            'bucket_name': bucket_name,
            'provider': 'AWS S3',
            'exists': False,
            'accessible': False,
            'listable': False,
            'url': f'https://{bucket_name}.s3.amazonaws.com',
            'files': []
        }
        
        try:
            # Try standard S3 endpoint
            urls = [
                f'https://{bucket_name}.s3.amazonaws.com',
                f'https://s3.amazonaws.com/{bucket_name}',
                f'http://{bucket_name}.s3.amazonaws.com',
            ]
            
            for url in urls:
                try:
                    async with self.session.get(url, allow_redirects=False) as response:
                        result['exists'] = True
                        result['status_code'] = response.status
                        result['url'] = url
                        
                        if response.status == 200:
                            result['accessible'] = True
                            
                            # Try to parse XML listing
                            text = await response.text()
                            if '<ListBucketResult' in text:
                                result['listable'] = True
                                
                                # Extract file keys (basic parsing)
                                keys = re.findall(r'<Key>([^<]+)</Key>', text)
                                result['files'] = keys[:50]  # Limit to first 50
                                result['file_count'] = len(keys)
                        
                        elif response.status == 403:
                            result['accessible'] = False
                            result['message'] = 'Bucket exists but access denied'
                        
                        break
                
                except aiohttp.ClientError:
                    continue
            
            if result['exists']:
                logger.info(f"S3 bucket found: {bucket_name} (accessible: {result['accessible']})")
        
        except Exception as e:
            logger.debug(f"Error checking S3 bucket {bucket_name}: {e}")
        
        return result
    
    async def check_azure_blob(self, account_name: str, container_name: str = None) -> Dict[str, Any]:
        """
        Check Azure Blob Storage
        
        Args:
            account_name: Azure storage account name
            container_name: Container name (optional)
        
        Returns:
            Azure blob information
        """
        result = {
            'account_name': account_name,
            'container_name': container_name,
            'provider': 'Azure Blob',
            'exists': False,
            'accessible': False,
            'listable': False
        }
        
        try:
            if container_name:
                url = f'https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list'
            else:
                url = f'https://{account_name}.blob.core.windows.net/?comp=list'
            
            result['url'] = url
            
            async with self.session.get(url) as response:
                result['status_code'] = response.status
                
                if response.status == 200:
                    result['exists'] = True
                    result['accessible'] = True
                    result['listable'] = True
                    
                    text = await response.text()
                    # Parse blob names
                    blobs = re.findall(r'<Name>([^<]+)</Name>', text)
                    result['blobs'] = blobs[:50]
                    result['blob_count'] = len(blobs)
                
                elif response.status in [401, 403]:
                    result['exists'] = True
                    result['accessible'] = False
            
            if result['exists']:
                logger.info(f"Azure blob found: {account_name}/{container_name or ''}")
        
        except Exception as e:
            logger.debug(f"Error checking Azure blob: {e}")
        
        return result
    
    async def check_gcp_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """
        Check Google Cloud Storage bucket
        
        Args:
            bucket_name: GCS bucket name
        
        Returns:
            Bucket information
        """
        result = {
            'bucket_name': bucket_name,
            'provider': 'Google Cloud Storage',
            'exists': False,
            'accessible': False,
            'listable': False,
            'url': f'https://storage.googleapis.com/{bucket_name}'
        }
        
        try:
            urls = [
                f'https://storage.googleapis.com/{bucket_name}',
                f'https://{bucket_name}.storage.googleapis.com'
            ]
            
            for url in urls:
                try:
                    async with self.session.get(url) as response:
                        result['status_code'] = response.status
                        
                        if response.status == 200:
                            result['exists'] = True
                            result['accessible'] = True
                            
                            text = await response.text()
                            if '<ListBucketResult' in text:
                                result['listable'] = True
                                
                                keys = re.findall(r'<Key>([^<]+)</Key>', text)
                                result['files'] = keys[:50]
                                result['file_count'] = len(keys)
                        
                        elif response.status == 403:
                            result['exists'] = True
                            result['accessible'] = False
                        
                        break
                
                except aiohttp.ClientError:
                    continue
            
            if result['exists']:
                logger.info(f"GCP bucket found: {bucket_name}")
        
        except Exception as e:
            logger.debug(f"Error checking GCP bucket: {e}")
        
        return result
    
    async def check_digitalocean_space(self, space_name: str, region: str = 'nyc3') -> Dict[str, Any]:
        """
        Check DigitalOcean Spaces
        
        Args:
            space_name: Space name
            region: DO region (nyc3, sfo2, sgp1, etc.)
        
        Returns:
            Space information
        """
        result = {
            'space_name': space_name,
            'region': region,
            'provider': 'DigitalOcean Spaces',
            'exists': False,
            'accessible': False,
            'url': f'https://{space_name}.{region}.digitaloceanspaces.com'
        }
        
        try:
            url = f'https://{space_name}.{region}.digitaloceanspaces.com'
            
            async with self.session.get(url) as response:
                result['status_code'] = response.status
                
                if response.status == 200:
                    result['exists'] = True
                    result['accessible'] = True
                
                elif response.status == 403:
                    result['exists'] = True
                    result['accessible'] = False
            
            if result['exists']:
                logger.info(f"DO Space found: {space_name}")
        
        except Exception as e:
            logger.debug(f"Error checking DO Space: {e}")
        
        return result
    
    async def check_cloudfront(self, domain: str) -> Dict[str, Any]:
        """
        Check CloudFront distribution
        
        Args:
            domain: Domain or CloudFront URL
        
        Returns:
            CloudFront information
        """
        result = {
            'domain': domain,
            'provider': 'CloudFront',
            'exists': False,
            'cloudfront_detected': False
        }
        
        try:
            url = f'https://{domain}' if not domain.startswith('http') else domain
            
            async with self.session.get(url, allow_redirects=True) as response:
                result['status_code'] = response.status
                result['exists'] = response.status < 500
                
                # Check headers for CloudFront
                headers = response.headers
                if 'X-Cache' in headers or 'X-Amz-Cf-Id' in headers:
                    result['cloudfront_detected'] = True
                    result['cache_status'] = headers.get('X-Cache', '')
                    result['cf_id'] = headers.get('X-Amz-Cf-Id', '')
                
                # Check Server header
                server = headers.get('Server', '')
                if 'CloudFront' in server:
                    result['cloudfront_detected'] = True
            
            if result['cloudfront_detected']:
                logger.info(f"CloudFront detected: {domain}")
        
        except Exception as e:
            logger.debug(f"Error checking CloudFront: {e}")
        
        return result
    
    async def generate_bucket_names(self, target: str) -> List[str]:
        """
        Generate potential bucket names based on target
        
        Args:
            target: Target domain or company name
        
        Returns:
            List of potential bucket names
        """
        # Clean target
        target = target.replace('http://', '').replace('https://', '')
        target = target.split('/')[0].split('.')[0]
        
        # Common patterns
        patterns = [
            target,
            f'{target}-backup',
            f'{target}-backups',
            f'{target}-prod',
            f'{target}-production',
            f'{target}-dev',
            f'{target}-development',
            f'{target}-staging',
            f'{target}-test',
            f'{target}-assets',
            f'{target}-static',
            f'{target}-media',
            f'{target}-files',
            f'{target}-uploads',
            f'{target}-data',
            f'{target}-logs',
            f'{target}-cdn',
            f'{target}-public',
            f'{target}-private',
            f'{target}-internal',
            f'{target}-webapp',
            f'{target}-mobile',
            f'{target}-app',
            f'www-{target}',
            f'prod-{target}',
            f'dev-{target}',
            f'backup-{target}',
            f'assets-{target}',
        ]
        
        return patterns
    
    async def comprehensive_scan(self, target: str, include_azure: bool = True,
                                include_gcp: bool = True, include_do: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive cloud asset discovery
        
        Args:
            target: Target domain or company name
            include_azure: Check Azure
            include_gcp: Check GCP
            include_do: Check DigitalOcean
        
        Returns:
            Complete cloud asset discovery results
        """
        results = {
            'target': target,
            's3_buckets': [],
            'azure_blobs': [],
            'gcp_buckets': [],
            'do_spaces': [],
            'cloudfront': None
        }
        
        try:
            bucket_names = await self.generate_bucket_names(target)
            logger.info(f"Testing {len(bucket_names)} potential cloud asset names")
            
            # Check S3 buckets
            s3_tasks = [self.check_s3_bucket(name) for name in bucket_names]
            s3_results = await asyncio.gather(*s3_tasks, return_exceptions=True)
            results['s3_buckets'] = [r for r in s3_results if isinstance(r, dict) and r.get('exists')]
            
            # Check GCP buckets
            if include_gcp:
                gcp_tasks = [self.check_gcp_bucket(name) for name in bucket_names]
                gcp_results = await asyncio.gather(*gcp_tasks, return_exceptions=True)
                results['gcp_buckets'] = [r for r in gcp_results if isinstance(r, dict) and r.get('exists')]
            
            # Check Azure (limited without container names)
            if include_azure:
                azure_accounts = [target, target.replace('-', ''), target.replace('_', '')]
                azure_tasks = [self.check_azure_blob(name) for name in azure_accounts]
                azure_results = await asyncio.gather(*azure_tasks, return_exceptions=True)
                results['azure_blobs'] = [r for r in azure_results if isinstance(r, dict) and r.get('exists')]
            
            # Check DigitalOcean Spaces
            if include_do:
                regions = ['nyc3', 'sfo2', 'sgp1', 'ams3']
                do_tasks = []
                for name in bucket_names[:10]:  # Limit DO checks
                    for region in regions:
                        do_tasks.append(self.check_digitalocean_space(name, region))
                
                do_results = await asyncio.gather(*do_tasks, return_exceptions=True)
                results['do_spaces'] = [r for r in do_results if isinstance(r, dict) and r.get('exists')]
            
            # Check CloudFront
            results['cloudfront'] = await self.check_cloudfront(target)
            
            # Summary
            results['summary'] = {
                's3_found': len(results['s3_buckets']),
                'gcp_found': len(results['gcp_buckets']),
                'azure_found': len(results['azure_blobs']),
                'do_found': len(results['do_spaces']),
                'total_found': len(results['s3_buckets']) + len(results['gcp_buckets']) + 
                              len(results['azure_blobs']) + len(results['do_spaces'])
            }
            
            logger.info(f"Cloud scan complete. Found {results['summary']['total_found']} assets")
            
            return results
        
        except Exception as e:
            logger.error(f"Error in comprehensive cloud scan: {e}")
            return results


async def discover_cloud_assets(target: str) -> Dict[str, Any]:
    """
    Convenience function for cloud asset discovery
    
    Args:
        target: Target domain or company name
    
    Returns:
        Cloud asset discovery results
    """
    async with CloudAssetDiscovery() as scanner:
        return await scanner.comprehensive_scan(target)


# Export
__all__ = ['CloudAssetDiscovery', 'discover_cloud_assets']

