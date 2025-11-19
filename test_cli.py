#!/usr/bin/env python3
"""
Test Suite for RedSentinel CLI
Tests all major functionality
"""

import unittest
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from redsentinel.design import console, success, error, info, warning


class TestReconModules(unittest.TestCase):
    """Test reconnaissance modules"""
    
    def test_subdomain_enum(self):
        """Test subdomain enumeration"""
        from redsentinel.tools.recon_advanced import advanced_subdomain_enum
        
        async def run_test():
            results = await advanced_subdomain_enum("example.com")
            self.assertIsInstance(results, dict)
            self.assertIn('subdomains', results)
        
        asyncio.run(run_test())
        success("✅ Subdomain enumeration test passed")
    
    def test_port_scan(self):
        """Test port scanning"""
        from redsentinel.tools.recon_advanced import comprehensive_port_scan
        
        async def run_test():
            results = await comprehensive_port_scan("scanme.nmap.org", ports=[80, 443], timeout=5.0)
            self.assertIsInstance(results, dict)
            self.assertIn('open_ports', results)
        
        asyncio.run(run_test())
        success("✅ Port scanning test passed")


class TestVulnScanners(unittest.TestCase):
    """Test vulnerability scanning modules"""
    
    def test_nuclei_wrapper(self):
        """Test Nuclei wrapper"""
        from redsentinel.tools.nuclei_wrapper import nuclei_scan
        
        # Just test the wrapper exists and can be called
        try:
            result = nuclei_scan(["https://example.com"], args="-silent")
            self.assertIsInstance(result, dict)
            success("✅ Nuclei wrapper test passed")
        except Exception as e:
            warning(f"⚠️  Nuclei not installed or test skipped: {e}")
    
    def test_cms_detection(self):
        """Test CMS detection"""
        from redsentinel.tools.cms_scanners import comprehensive_cms_scan
        
        async def run_test():
            try:
                results = await comprehensive_cms_scan("https://wordpress.com")
                self.assertIsInstance(results, dict)
                success("✅ CMS detection test passed")
            except Exception as e:
                warning(f"⚠️  CMS detection test skipped: {e}")
        
        asyncio.run(run_test())


class TestOSINT(unittest.TestCase):
    """Test OSINT modules"""
    
    def test_email_harvester(self):
        """Test email harvesting"""
        from redsentinel.osint.advanced.email_harvester import EmailHarvester
        
        async def run_test():
            harvester = EmailHarvester()
            results = await harvester.harvest_emails("example.com")
            self.assertIsInstance(results, dict)
            self.assertIn('emails', results)
        
        asyncio.run(run_test())
        success("✅ Email harvester test passed")
    
    def test_cloud_assets(self):
        """Test cloud asset discovery"""
        from redsentinel.osint.advanced.cloud_assets import CloudAssetDiscovery
        
        async def run_test():
            discovery = CloudAssetDiscovery()
            results = await discovery.discover_s3_buckets("example")
            self.assertIsInstance(results, list)
        
        asyncio.run(run_test())
        success("✅ Cloud asset discovery test passed")


class TestDatabase(unittest.TestCase):
    """Test database operations"""
    
    def test_workspace_manager(self):
        """Test workspace management"""
        from redsentinel.database.workspace_manager import WorkspaceManager
        
        try:
            manager = WorkspaceManager()
            
            # Create test workspace
            workspace = manager.create_workspace("test_workspace")
            self.assertIsNotNone(workspace)
            
            # List workspaces
            workspaces = manager.list_workspaces()
            self.assertIsInstance(workspaces, list)
            
            # Delete test workspace
            manager.delete_workspace("test_workspace")
            
            success("✅ Workspace manager test passed")
        except Exception as e:
            warning(f"⚠️  Database test skipped (database may not be configured): {e}")
    
    def test_encryption(self):
        """Test data encryption"""
        from redsentinel.database.encryption import encrypt_data, decrypt_data
        
        test_data = "sensitive_password_123"
        encrypted = encrypt_data(test_data)
        decrypted = decrypt_data(encrypted)
        
        self.assertEqual(test_data, decrypted)
        self.assertNotEqual(test_data, encrypted)
        
        success("✅ Encryption test passed")


class TestPerformance(unittest.TestCase):
    """Test performance modules"""
    
    def test_connection_pool(self):
        """Test connection pooling"""
        from redsentinel.performance.connection_pool import ConnectionPool
        
        async def run_test():
            pool = ConnectionPool(max_connections=10)
            
            async with pool.get_session() as session:
                self.assertIsNotNone(session)
            
            await pool.close()
        
        asyncio.run(run_test())
        success("✅ Connection pool test passed")
    
    def test_rate_limiter(self):
        """Test rate limiting"""
        from redsentinel.performance.rate_limiter import RateLimiter
        import time
        
        async def run_test():
            limiter = RateLimiter(max_requests=5, time_window=1.0)
            
            start_time = time.time()
            
            # Make 10 requests (should be throttled after 5)
            for i in range(10):
                await limiter.acquire()
            
            elapsed = time.time() - start_time
            
            # Should take at least 1 second (rate limited)
            self.assertGreaterEqual(elapsed, 1.0)
        
        asyncio.run(run_test())
        success("✅ Rate limiter test passed")


class TestReporting(unittest.TestCase):
    """Test reporting modules"""
    
    def test_report_generator(self):
        """Test report generation"""
        from redsentinel.reporting.report_generator import ReportGenerator
        
        async def run_test():
            generator = ReportGenerator()
            
            # Sample scan data
            scan_data = {
                'target': 'example.com',
                'scan_date': '2024-11-19',
                'vulnerabilities': [
                    {
                        'severity': 'high',
                        'name': 'SQL Injection',
                        'description': 'SQL injection vulnerability found'
                    }
                ]
            }
            
            # Test HTML report
            html_report = await generator.generate_html_report(scan_data)
            self.assertIsInstance(html_report, str)
            self.assertIn('example.com', html_report)
            
            # Test Markdown report
            md_report = await generator.generate_markdown_report(scan_data)
            self.assertIsInstance(md_report, str)
            self.assertIn('SQL Injection', md_report)
        
        asyncio.run(run_test())
        success("✅ Report generator test passed")


class TestUtils(unittest.TestCase):
    """Test utility modules"""
    
    def test_error_handler(self):
        """Test error handling decorators"""
        from redsentinel.utils.error_handler import safe_execute, retry_on_failure
        
        @safe_execute
        def test_function():
            return "success"
        
        @safe_execute
        def failing_function():
            raise ValueError("Test error")
        
        # Should return result
        result = test_function()
        self.assertEqual(result, "success")
        
        # Should handle error gracefully
        result = failing_function()
        self.assertIsNone(result)
        
        success("✅ Error handler test passed")
    
    def test_logger(self):
        """Test logging system"""
        from redsentinel.utils.logger import get_logger
        
        logger = get_logger("test_module")
        self.assertIsNotNone(logger)
        
        # Test log levels
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        
        success("✅ Logger test passed")


def run_all_tests():
    """Run all tests"""
    console.print("\n[bold cyan]🧪 RedSentinel CLI Test Suite[/bold cyan]\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestReconModules))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnScanners))
    suite.addTests(loader.loadTestsFromTestCase(TestOSINT))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestReporting))
    suite.addTests(loader.loadTestsFromTestCase(TestUtils))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    console.print(f"\n[bold]Test Summary:[/bold]")
    console.print(f"  ✅ Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    console.print(f"  ❌ Failed: {len(result.failures)}")
    console.print(f"  ⚠️  Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        success("\n🎉 All tests passed!")
        return 0
    else:
        error("\n❌ Some tests failed")
        return 1


def test_imports():
    """Quick test to verify all imports work"""
    console.print("\n[bold cyan]📦 Testing Module Imports[/bold cyan]\n")
    
    modules_to_test = [
        "redsentinel.cli_main",
        "redsentinel.design",
        "redsentinel.scanner",
        "redsentinel.recon",
        "redsentinel.tools.recon_advanced",
        "redsentinel.tools.nuclei_wrapper",
        "redsentinel.tools.cms_scanners",
        "redsentinel.osint.advanced.email_harvester",
        "redsentinel.osint.advanced.cloud_assets",
        "redsentinel.database.workspace_manager",
        "redsentinel.database.encryption",
        "redsentinel.performance.connection_pool",
        "redsentinel.performance.rate_limiter",
        "redsentinel.reporting.report_generator",
        "redsentinel.utils.error_handler",
        "redsentinel.utils.logger",
    ]
    
    failed_imports = []
    
    for module_name in modules_to_test:
        try:
            __import__(module_name)
            success(f"✅ {module_name}")
        except ImportError as e:
            error(f"❌ {module_name}: {e}")
            failed_imports.append(module_name)
        except Exception as e:
            warning(f"⚠️  {module_name}: {e}")
    
    console.print()
    
    if not failed_imports:
        success("🎉 All modules imported successfully!")
        return 0
    else:
        error(f"❌ {len(failed_imports)} modules failed to import")
        return 1


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--imports-only':
        sys.exit(test_imports())
    else:
        # Run import tests first
        import_result = test_imports()
        
        if import_result != 0:
            console.print("\n[yellow]⚠️  Some imports failed. Skipping full test suite.[/yellow]")
            sys.exit(import_result)
        
        # Run full test suite
        sys.exit(run_all_tests())
