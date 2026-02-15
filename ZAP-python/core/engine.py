import logging
import time
from typing import List, Dict
from core.context import ScanContext
from core.parser import SpecParser, APIEndpoint
from scanners.base import BaseScanner
from scanners.api_headers import SecurityHeadersScanner
from scanners.api_injection import SqlInjectionScanner
from scanners.api_idor import UsernameIdorScanner
from scanners.api_mass_assignment import MassAssignmentScanner
from scanners.api_ssrf import SsrfScanner
from scanners.api_jwt import JwtScanner

# Import scanners dynamically or statically for now
# from scanners.api_bola import BolaScanner (Future)

class AttackEngine:
    """
    Orchestrates the attack process.
    Equivalent to ZAP's ActiveScanController.
    """
    
    def __init__(self, context: ScanContext):
        self.context = context
        self.scanners: List[BaseScanner] = []
        self.results: List[Dict] = []
        
    def load_scanners(self):
        """Auto-discover and load all scanners from scanners/ directory."""
        import importlib
        import pkgutil
        import scanners
        from inspect import isclass

        self.scanners = []
        package = scanners
        prefix = package.__name__ + "."

        for _, name, _ in pkgutil.iter_modules(package.__path__, prefix):
            if name == "scanners.base":
                continue
                
            try:
                module = importlib.import_module(name)
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if (isclass(attribute) and 
                        attribute.__module__ == name and
                        issubclass(attribute, BaseScanner) and 
                        attribute is not BaseScanner):
                        
                        scanner_instance = attribute(self.context)
                        self.scanners.append(scanner_instance)
                        logging.info(f"Loaded scanner: {scanner_instance.name} [{scanner_instance.scan_id}]")
            except Exception as e:
                logging.error(f"Failed to load scanner from {name}: {e}")
        
    def start_scan(self, spec_path: str = None):
        """
        Main execution loop.
        1. Parse Spec -> Endpoints
        2. Filter Endpoints (Scope)
        3. For each Endpoint -> Run all Scanners (Parallel)
        """
        import concurrent.futures
        
        logging.info("Starting Attack Engine...")
        
        # 1. Parse Spec
        endpoints = []
        if spec_path:
            parser = SpecParser(spec_path)
            endpoints = parser.parse()
            logging.info(f"Discovered {len(endpoints)} testable endpoints.")
        else:
            logging.warning("No spec provided. Crawling implementation pending.")
            return

        # 2. Attack Loop (Parallel Config: 50 Workers)
        total_endpoints = len(endpoints)
        logging.info(f"Scanning with 50 concurrent threads...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_endpoint = {
                executor.submit(self._scan_endpoint, endpoint): endpoint 
                for endpoint in endpoints
            }
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_endpoint):
                completed += 1
                endpoint = future_to_endpoint[future]
                try:
                    results = future.result()
                    if results:
                        self.results.extend(results)
                    
                    if completed % 5 == 0:
                        logging.info(f"Progress: {completed}/{total_endpoints} endpoints scanned.")
                except Exception as exc:
                    logging.error(f"Endpoint {endpoint.path} generated an exception: {exc}")

        logging.info("Scan complete.")
        return self.results

    def _scan_endpoint(self, endpoint: APIEndpoint) -> List[Dict]:
        """Helper method to run all scanners for a single endpoint."""
        endpoint_findings = []
        for scanner in self.scanners:
            try:
                logging.debug(f"Running {scanner.scan_id} on {endpoint.method} {endpoint.path}")
                findings = scanner.run(
                    endpoint.path,
                    endpoint.method,
                    {"params": endpoint.params, "schema": endpoint.body_schema, "example": endpoint.example}
                )
                if findings:
                    # Enrich findings with endpoint context
                    for f in findings:
                        f['method'] = endpoint.method
                        f['path'] = endpoint.path
                    endpoint_findings.extend(findings)
            except Exception as e:
                logging.error(f"Error executing scanner {scanner.name} on {endpoint.path}: {e}")
        return endpoint_findings
    
    def generate_report(self):
        """Generate final report logic."""
        return {
            "target": self.context.target_url,
            "timestamp": time.time(),
            "findings": self.results,
            "summary": {
                "total_findings": len(self.results),
                "scanners_run": [s.name for s in self.scanners]
            }
        }

    def save_markdown_report(self, filename: str = "report.md"):
        """Generates a structured human-readable Markdown report."""
        
        EXPLOITABILITY = {
            "Critical": "High",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Info": "None"
        }
        
        with open(filename, "w") as f:
            f.write(f"# ZAP-Python Security Report\n\n")
            f.write(f"**Target:** {self.context.target_url}\n")
            f.write(f"**Scanners:** {', '.join([s.name for s in self.scanners])}\n")
            f.write(f"**Total Findings:** {len(self.results)}\n\n")
            
            # Grouping Logic
            grouped = {}
            # Track unique scan findings using a hash of specific fields
            seen_finding_hashes = set()
            
            for r in self.results:
                sev = r.get('severity', 'Info')
                title = r.get('title', 'Unknown')
                
                # Unique Key: Title + Method + Path + Evidence
                # We use this to filter out exact duplicates (same vuln, same endpoint, same evidence)
                # But we ALLOW same vuln on same endpoint if evidence differs (different payload)
                unique_key = (
                    title,
                    r.get('method', ''),
                    r.get('path', ''),
                    str(r.get('evidence', ''))
                )
                
                if unique_key in seen_finding_hashes:
                    continue
                seen_finding_hashes.add(unique_key)
                
                if sev not in grouped: grouped[sev] = {}
                if title not in grouped[sev]: grouped[sev][title] = []
                grouped[sev][title].append(r)
            
            severity_order = ["Critical", "High", "Medium", "Low", "Info"]
            
            for sev in severity_order:
                if sev not in grouped: continue
                
                f.write(f"## {sev} Severity Findings\n\n")
                
                vulns = grouped[sev]
                for title, findings in vulns.items():
                    first = findings[0]
                    category = first.get('category', 'Unknown')
                    exploitability = EXPLOITABILITY.get(sev, "Unknown")
                    
                    f.write(f"### {title}\n")
                    f.write(f"**Category:** {category}\n")
                    f.write(f"**Exploitability:** {exploitability}\n")
                    f.write(f"**Description:** {first['description']}\n\n")
                    f.write(f"**Affected Endpoints ({len(findings)}):**\n\n")
                    
                    # Sort findings by endpoint for readability
                    sorted_findings = sorted(findings, key=lambda x: (x.get('path', ''), x.get('method', '')))
                    
                    for i, finding in enumerate(sorted_findings):
                        method = finding.get('method', 'UNKNOWN')
                        path = finding.get('path', 'UNKNOWN')
                        
                        f.write(f"#### {i+1}. {method} {path}\n")
                        f.write("```text\n")
                        # Indent evidence block
                        evidence_lines = str(finding.get('evidence', 'No specific evidence provided.')).split('\n')
                        for line in evidence_lines:
                            f.write(f"{line}\n")
                        f.write("```\n\n")
                    
                    f.write("---\n")
