"""
RedSentinel - Advanced TUI Interface
Author: Alexandre Tavares - Redsentinel
Version: 7.0

Premium TUI with Textual:
- Full-screen interface
- Multi-pane layout
- Command palette
- Vim keybindings
- Real-time updates
- Theme customization
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
    from textual.widgets import (
        Header, Footer, Static, DataTable, Button, Input, Label,
        Tree, TabbedContent, TabPane, Log, ProgressBar, Checkbox, Select
    )
    from textual.binding import Binding
    from textual.screen import Screen
    from textual import on
    from rich.syntax import Syntax
    from rich.table import Table as RichTable
    from rich.panel import Panel
    from rich.console import Console
    TEXTUAL_AVAILABLE = True
except ImportError:
    logger.warning("Textual not available. Install with: pip install textual")
    TEXTUAL_AVAILABLE = False


if TEXTUAL_AVAILABLE:
    
    class DashboardScreen(Screen):
        """Main dashboard screen"""
        
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("s", "scan", "New Scan"),
            Binding("r", "results", "View Results"),
            Binding("p", "proxy", "Proxy"),
            Binding("o", "osint", "OSINT"),
            ("ctrl+c", "quit", "Quit"),
        ]
        
        def compose(self) -> ComposeResult:
            """Create dashboard layout"""
            yield Header(show_clock=True)
            
            with Vertical():
                # Stats panel
                with Horizontal(id="stats-panel"):
                    yield Static("[bold cyan]Active Scans:[/] 0", id="stat-scans", classes="stat-box")
                    yield Static("[bold green]Vulnerabilities:[/] 0", id="stat-vulns", classes="stat-box")
                    yield Static("[bold yellow]Targets:[/] 0", id="stat-targets", classes="stat-box")
                    yield Static("[bold magenta]OSINT:[/] 0", id="stat-osint", classes="stat-box")
                
                # Main content area with tabs
                with TabbedContent(initial="scans"):
                    with TabPane("Scans", id="scans"):
                        yield self.create_scans_table()
                    
                    with TabPane("Vulnerabilities", id="vulnerabilities"):
                        yield self.create_vulns_table()
                    
                    with TabPane("OSINT", id="osint"):
                        yield self.create_osint_panel()
                    
                    with TabPane("Proxy", id="proxy"):
                        yield self.create_proxy_panel()
                    
                    with TabPane("Reports", id="reports"):
                        yield self.create_reports_panel()
            
            yield Footer()
        
        def create_scans_table(self) -> DataTable:
            """Create scans data table"""
            table = DataTable(id="scans-table")
            table.add_columns("ID", "Target", "Status", "Start Time", "Vulns", "Progress")
            
            # Sample data
            table.add_rows([
                ["scan_001", "https://example.com", "Running", "2024-11-19 10:00", "5", "45%"],
                ["scan_002", "https://target.com", "Complete", "2024-11-19 09:00", "23", "100%"],
            ])
            
            return table
        
        def create_vulns_table(self) -> DataTable:
            """Create vulnerabilities table"""
            table = DataTable(id="vulns-table")
            table.add_columns("Severity", "Name", "Target", "Category", "CWE")
            
            # Sample data
            table.add_rows([
                ["CRITICAL", "SQL Injection", "example.com/login", "A03:2021", "CWE-89"],
                ["HIGH", "XSS", "example.com/search", "A03:2021", "CWE-79"],
                ["MEDIUM", "Missing Security Headers", "example.com", "A05:2021", "CWE-16"],
            ])
            
            return table
        
        def create_osint_panel(self) -> Container:
            """Create OSINT panel"""
            container = ScrollableContainer()
            container.mount(Label("[bold cyan]OSINT Results[/]"))
            container.mount(Static("GitHub: 5 leaked secrets found"))
            container.mount(Static("Cloud: 3 exposed S3 buckets"))
            container.mount(Static("Emails: 12 addresses harvested"))
            container.mount(Static("Subdomains: 45 discovered"))
            return container
        
        def create_proxy_panel(self) -> Container:
            """Create proxy control panel"""
            container = Vertical()
            container.mount(Label("[bold magenta]Proxy Controls[/]"))
            container.mount(Button("Start Proxy", id="proxy-start", variant="success"))
            container.mount(Button("Stop Proxy", id="proxy-stop", variant="error"))
            container.mount(Static("Status: Stopped", id="proxy-status"))
            container.mount(Static("Requests intercepted: 0", id="proxy-count"))
            return container
        
        def create_reports_panel(self) -> Container:
            """Create reports panel"""
            container = Vertical()
            container.mount(Label("[bold green]Generate Report[/]"))
            container.mount(Input(placeholder="Scan ID", id="report-scan-id"))
            container.mount(Select([
                ("PDF", "pdf"),
                ("HTML", "html"),
                ("JSON", "json"),
                ("XML", "xml"),
                ("CSV", "csv"),
                ("Markdown", "markdown")
            ], id="report-format", prompt="Select format"))
            container.mount(Checkbox("Include Compliance Mapping", id="report-compliance"))
            container.mount(Button("Generate Report", id="report-generate", variant="primary"))
            return container
        
        def action_scan(self) -> None:
            """Start new scan"""
            self.app.push_screen(ScanConfigScreen())
        
        def action_results(self) -> None:
            """View results"""
            self.app.push_screen(ResultsScreen())
        
        def action_proxy(self) -> None:
            """Open proxy"""
            self.app.push_screen(ProxyScreen())
        
        def action_osint(self) -> None:
            """Open OSINT"""
            self.app.push_screen(OSINTScreen())
    
    
    class ScanConfigScreen(Screen):
        """Scan configuration screen"""
        
        BINDINGS = [
            Binding("escape", "app.pop_screen", "Back"),
        ]
        
        def compose(self) -> ComposeResult:
            yield Header()
            
            with Vertical():
                yield Label("[bold cyan]Configure New Scan[/]", id="title")
                
                yield Label("Target URL:")
                yield Input(placeholder="https://example.com", id="scan-target")
                
                yield Label("Scan Type:")
                yield Select([
                    ("Quick Scan", "quick"),
                    ("Full Scan", "full"),
                    ("OWASP Top 10", "owasp"),
                    ("Custom", "custom")
                ], id="scan-type")
                
                yield Label("Modules:")
                with Vertical():
                    yield Checkbox("Port Scanning", id="module-portscan", value=True)
                    yield Checkbox("Web Scanning", id="module-webscan", value=True)
                    yield Checkbox("OSINT", id="module-osint", value=True)
                    yield Checkbox("Vulnerability Scan", id="module-vulnscan", value=True)
                    yield Checkbox("Fuzzing", id="module-fuzz", value=False)
                
                with Horizontal():
                    yield Button("Start Scan", id="scan-start", variant="success")
                    yield Button("Cancel", id="scan-cancel", variant="error")
            
            yield Footer()
        
        @on(Button.Pressed, "#scan-start")
        def start_scan(self) -> None:
            """Start the scan"""
            target = self.query_one("#scan-target", Input).value
            scan_type = self.query_one("#scan-type", Select).value
            
            # TODO: Start actual scan
            self.app.pop_screen()
            self.app.notify(f"Started {scan_type} scan on {target}", title="Scan Started", severity="information")
        
        @on(Button.Pressed, "#scan-cancel")
        def cancel_scan(self) -> None:
            """Cancel scan configuration"""
            self.app.pop_screen()
    
    
    class ResultsScreen(Screen):
        """Results viewing screen"""
        
        BINDINGS = [
            Binding("escape", "app.pop_screen", "Back"),
            Binding("e", "export", "Export"),
        ]
        
        def compose(self) -> ComposeResult:
            yield Header()
            
            with Vertical():
                yield Label("[bold green]Scan Results[/]")
                
                # Vulnerability details
                with ScrollableContainer():
                    yield Static(self.create_vuln_panel("SQL Injection", "CRITICAL"))
                    yield Static(self.create_vuln_panel("XSS", "HIGH"))
                    yield Static(self.create_vuln_panel("Missing Headers", "MEDIUM"))
            
            yield Footer()
        
        def create_vuln_panel(self, name: str, severity: str) -> str:
            """Create vulnerability panel"""
            color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "cyan"
            }.get(severity, "white")
            
            return f"""
[bold {color}]{name}[/] - [{color}]{severity}[/]

[bold]URL:[/] https://example.com/endpoint
[bold]Category:[/] A03:2021-Injection
[bold]CWE:[/] CWE-89

[bold]Description:[/]
SQL injection vulnerability detected in user input parameter.

[bold]Remediation:[/]
Use parameterized queries or prepared statements.
"""
        
        def action_export(self) -> None:
            """Export results"""
            self.app.notify("Results exported to results.json", title="Export Complete")
    
    
    class ProxyScreen(Screen):
        """Proxy interface screen"""
        
        BINDINGS = [
            Binding("escape", "app.pop_screen", "Back"),
            Binding("i", "intercept", "Toggle Intercept"),
        ]
        
        def compose(self) -> ComposeResult:
            yield Header()
            
            with Vertical():
                yield Label("[bold magenta]HTTP/HTTPS Proxy[/]")
                
                with Horizontal():
                    yield Button("Start", id="proxy-start", variant="success")
                    yield Button("Stop", id="proxy-stop", variant="error")
                    yield Static("Status: Stopped", id="proxy-status")
                
                yield Label("Request History:")
                
                # Request history table
                table = DataTable(id="proxy-history")
                table.add_columns("Time", "Method", "URL", "Status", "Size")
                table.add_rows([
                    ["10:30:15", "GET", "example.com/api", "200", "1.2KB"],
                    ["10:30:16", "POST", "example.com/login", "302", "0.5KB"],
                ])
                yield table
                
                yield Label("Request Details:")
                yield Log(id="proxy-details", highlight=True)
            
            yield Footer()
        
        @on(Button.Pressed, "#proxy-start")
        def start_proxy(self) -> None:
            """Start proxy"""
            self.query_one("#proxy-status", Static).update("Status: Running on :8080")
            self.app.notify("Proxy started on port 8080", severity="information")
        
        @on(Button.Pressed, "#proxy-stop")
        def stop_proxy(self) -> None:
            """Stop proxy"""
            self.query_one("#proxy-status", Static).update("Status: Stopped")
            self.app.notify("Proxy stopped", severity="information")
        
        def action_intercept(self) -> None:
            """Toggle interception"""
            self.app.notify("Interception toggled", severity="information")
    
    
    class OSINTScreen(Screen):
        """OSINT interface screen"""
        
        BINDINGS = [
            Binding("escape", "app.pop_screen", "Back"),
        ]
        
        def compose(self) -> ComposeResult:
            yield Header()
            
            with Vertical():
                yield Label("[bold cyan]OSINT Reconnaissance[/]")
                
                yield Label("Target Domain:")
                yield Input(placeholder="example.com", id="osint-target")
                
                yield Label("OSINT Sources:")
                with Vertical():
                    yield Checkbox("GitHub", id="osint-github", value=True)
                    yield Checkbox("Shodan", id="osint-shodan", value=True)
                    yield Checkbox("Wayback Machine", id="osint-wayback", value=True)
                    yield Checkbox("Cloud Assets", id="osint-cloud", value=True)
                    yield Checkbox("Email Harvesting", id="osint-email", value=True)
                    yield Checkbox("Certificate Transparency", id="osint-ct", value=False)
                
                yield Button("Start OSINT", id="osint-start", variant="primary")
                
                yield Label("Results:")
                yield Log(id="osint-results", highlight=True)
            
            yield Footer()
        
        @on(Button.Pressed, "#osint-start")
        def start_osint(self) -> None:
            """Start OSINT gathering"""
            target = self.query_one("#osint-target", Input).value
            log = self.query_one("#osint-results", Log)
            
            log.write_line(f"Starting OSINT on {target}...")
            log.write_line("[green]GitHub:[/] Searching for leaked secrets...")
            log.write_line("[green]Shodan:[/] Querying for exposed services...")
            log.write_line("[green]Cloud:[/] Discovering cloud assets...")
            
            self.app.notify("OSINT gathering started", severity="information")
    
    
    class RedSentinelTUI(App):
        """RedSentinel Advanced TUI Application"""
        
        CSS = """
        Screen {
            background: $surface;
        }
        
        #stats-panel {
            height: 5;
            dock: top;
            background: $boost;
            padding: 1;
        }
        
        .stat-box {
            width: 1fr;
            height: 3;
            background: $panel;
            border: solid $primary;
            padding: 1;
            content-align: center middle;
        }
        
        DataTable {
            height: 1fr;
        }
        
        Button {
            margin: 1;
        }
        
        Input {
            margin: 1 0;
        }
        
        Label {
            margin: 1 0;
        }
        
        Checkbox {
            margin: 0 2;
        }
        
        #title {
            text-align: center;
            text-style: bold;
            background: $boost;
            padding: 1;
        }
        """
        
        TITLE = "RedSentinel v7.0 - Machine de Guerre Cyber"
        SUB_TITLE = "Professional Security Assessment Platform"
        
        BINDINGS = [
            Binding("ctrl+q", "quit", "Quit", show=True),
            Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
            Binding("ctrl+s", "screenshot", "Screenshot"),
        ]
        
        def on_mount(self) -> None:
            """Initialize app"""
            self.push_screen(DashboardScreen())
        
        def action_toggle_dark(self) -> None:
            """Toggle dark mode"""
            self.dark = not self.dark
        
        def action_screenshot(self) -> None:
            """Take screenshot"""
            path = self.save_screenshot()
            self.notify(f"Screenshot saved to {path}", title="Screenshot")


class TUILauncher:
    """
    TUI Launcher for RedSentinel
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        if not TEXTUAL_AVAILABLE:
            logger.error("Textual not available. Install with: pip install textual")
            raise ImportError("Textual not installed")
    
    def launch(self):
        """Launch the TUI"""
        logger.info("Launching RedSentinel TUI...")
        
        app = RedSentinelTUI()
        app.run()


# Usage example
if __name__ == "__main__":
    if TEXTUAL_AVAILABLE:
        config = {}
        launcher = TUILauncher(config)
        launcher.launch()
    else:
        print("ERROR: Textual not installed. Install with: pip install textual")

