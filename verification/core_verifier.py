#!/usr/bin/env python3
"""
Echo Forge-AI Integrity Core Verification System
Multi-agent verification system for CVE manifest analysis and checksum validation
Lineage: RepoReportEcho_092425
"""

import hashlib
import json
import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('verification.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EchoForgeVerifier:
    """Core verification engine for the Echo Forge-AI Integrity system"""
    
    LINEAGE_ID = "RepoReportEcho_092425"
    SUPPORTED_HASH_ALGORITHMS = ['sha256', 'md5', 'sha1']
    
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.reports_path = self.base_path / "reports"
        self.data_path = self.base_path / "data" / "cve"
        self.verification_results = []
        
        # Ensure directories exist
        self.reports_path.mkdir(parents=True, exist_ok=True)
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized EchoForgeVerifier with base path: {self.base_path}")
    
    def generate_checksum(self, data: str, algorithm: str = 'sha256') -> str:
        """Generate checksum for given data using specified algorithm"""
        if algorithm not in self.SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hash_func = getattr(hashlib, algorithm)()
        hash_func.update(data.encode('utf-8'))
        return hash_func.hexdigest()
    
    def generate_file_checksum(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Generate checksum for a file"""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    def verify_cve_manifest(self, manifest_path: Path) -> Dict[str, Any]:
        """Verify and analyze a CVE manifest file"""
        logger.info(f"Verifying CVE manifest: {manifest_path}")
        
        if not manifest_path.exists():
            raise FileNotFoundError(f"CVE manifest not found: {manifest_path}")
        
        try:
            with open(manifest_path, 'r') as f:
                manifest_data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in manifest {manifest_path}: {e}")
            raise
        
        # Validate manifest structure
        required_fields = ['cve_id', 'description', 'severity', 'published_date']
        missing_fields = [field for field in required_fields if field not in manifest_data]
        
        if missing_fields:
            logger.warning(f"Missing required fields in {manifest_path}: {missing_fields}")
        
        # Generate checksums
        file_checksum = self.generate_file_checksum(manifest_path)
        content_checksum = self.generate_checksum(json.dumps(manifest_data, sort_keys=True))
        
        verification_result = {
            'manifest_file': str(manifest_path),
            'cve_id': manifest_data.get('cve_id', 'UNKNOWN'),
            'severity': manifest_data.get('severity', 'UNKNOWN'),
            'file_checksum': file_checksum,
            'content_checksum': content_checksum,
            'missing_fields': missing_fields,
            'valid': len(missing_fields) == 0,
            'timestamp': datetime.utcnow().isoformat(),
            'lineage_id': self.LINEAGE_ID
        }
        
        self.verification_results.append(verification_result)
        logger.info(f"Verified CVE {manifest_data.get('cve_id', 'UNKNOWN')}: {'VALID' if verification_result['valid'] else 'INVALID'}")
        
        return verification_result
    
    def batch_verify_manifests(self, manifest_directory: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Verify all CVE manifests in a directory"""
        if manifest_directory is None:
            manifest_directory = self.data_path
        
        if not manifest_directory.exists():
            logger.warning(f"Manifest directory does not exist: {manifest_directory}")
            return []
        
        manifest_files = list(manifest_directory.glob("*.json"))
        logger.info(f"Found {len(manifest_files)} manifest files to verify")
        
        results = []
        for manifest_file in manifest_files:
            try:
                result = self.verify_cve_manifest(manifest_file)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to verify {manifest_file}: {e}")
                # Create error result
                error_result = {
                    'manifest_file': str(manifest_file),
                    'cve_id': 'ERROR',
                    'severity': 'ERROR',
                    'file_checksum': '',
                    'content_checksum': '',
                    'missing_fields': [],
                    'valid': False,
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat(),
                    'lineage_id': self.LINEAGE_ID
                }
                results.append(error_result)
        
        return results
    
    def generate_csv_report(self, results: List[Dict[str, Any]], output_path: Optional[Path] = None) -> Path:
        """Generate CSV report from verification results"""
        if output_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = self.reports_path / "csv" / f"cve_verification_report_{timestamp}.csv"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not results:
            logger.warning("No results to generate CSV report")
            return output_path
        
        fieldnames = results[0].keys()
        
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        
        # Generate checksum for the report
        report_checksum = self.generate_file_checksum(output_path)
        
        # Create checksum file
        checksum_path = output_path.with_suffix('.csv.sha256')
        with open(checksum_path, 'w') as f:
            f.write(f"{report_checksum}  {output_path.name}\n")
        
        logger.info(f"Generated CSV report: {output_path}")
        logger.info(f"Report checksum: {report_checksum}")
        
        return output_path
    
    def generate_markdown_report(self, results: List[Dict[str, Any]], output_path: Optional[Path] = None) -> Path:
        """Generate Markdown report from verification results"""
        if output_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = self.reports_path / "md" / f"cve_verification_report_{timestamp}.md"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        valid_count = sum(1 for r in results if r.get('valid', False))
        invalid_count = len(results) - valid_count
        
        markdown_content = f"""# CVE Verification Report - {self.LINEAGE_ID}

**Generated**: {datetime.utcnow().isoformat()}Z  
**Total Manifests**: {len(results)}  
**Valid Manifests**: {valid_count}  
**Invalid Manifests**: {invalid_count}  

## Summary

This report contains the verification results for CVE manifests processed by the Echo Forge-AI Integrity system.

### Validation Statistics
- **Success Rate**: {(valid_count/len(results)*100):.1f}% if results else 0
- **Processing Date**: {datetime.utcnow().strftime("%Y-%m-%d")}
- **Lineage ID**: {self.LINEAGE_ID}

## Detailed Results

| CVE ID | Severity | Status | File Checksum | Issues |
|--------|----------|--------|---------------|--------|
"""
        
        for result in results:
            status = "✅ VALID" if result.get('valid', False) else "❌ INVALID"
            issues = ", ".join(result.get('missing_fields', [])) or "None"
            checksum_short = result.get('file_checksum', '')[:16] + "..." if result.get('file_checksum') else "N/A"
            
            markdown_content += f"| {result.get('cve_id', 'UNKNOWN')} | {result.get('severity', 'UNKNOWN')} | {status} | `{checksum_short}` | {issues} |\n"
        
        markdown_content += f"""
## Verification Metadata

**Report Generated By**: Echo Forge-AI Integrity Core Verifier  
**Timestamp**: {datetime.utcnow().isoformat()}Z  
**Lineage**: {self.LINEAGE_ID}  
**System Version**: 1.0.0  

### Checksum Information
This report has been generated with cryptographic integrity verification.
All processed files include SHA-256 checksums for validation.

---
*Generated by Echo Forge-AI Integrity Multi-Agent Verification System*
"""
        
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        
        # Generate checksum for the report
        report_checksum = self.generate_file_checksum(output_path)
        
        # Create checksum file
        checksum_path = output_path.with_suffix('.md.sha256')
        with open(checksum_path, 'w') as f:
            f.write(f"{report_checksum}  {output_path.name}\n")
        
        logger.info(f"Generated Markdown report: {output_path}")
        logger.info(f"Report checksum: {report_checksum}")
        
        return output_path
    
    def generate_html_report(self, results: List[Dict[str, Any]], output_path: Optional[Path] = None) -> Path:
        """Generate HTML report from verification results"""
        if output_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = self.reports_path / "html" / f"cve_verification_report_{timestamp}.html"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        valid_count = sum(1 for r in results if r.get('valid', False))
        invalid_count = len(results) - valid_count
        success_rate = (valid_count/len(results)*100) if results else 0
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE Verification Report - {self.LINEAGE_ID}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ text-align: center; padding: 15px; border-radius: 5px; background-color: #f8f9fa; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #007acc; }}
        .stat-label {{ font-size: 0.9em; color: #666; }}
        .results-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .results-table th, .results-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .results-table th {{ background-color: #007acc; color: white; }}
        .valid {{ color: #28a745; font-weight: bold; }}
        .invalid {{ color: #dc3545; font-weight: bold; }}
        .checksum {{ font-family: monospace; font-size: 0.8em; color: #666; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CVE Verification Report</h1>
            <h2>{self.LINEAGE_ID}</h2>
            <p>Generated: {datetime.utcnow().isoformat()}Z</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{len(results)}</div>
                <div class="stat-label">Total Manifests</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{valid_count}</div>
                <div class="stat-label">Valid Manifests</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{invalid_count}</div>
                <div class="stat-label">Invalid Manifests</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{success_rate:.1f}%</div>
                <div class="stat-label">Success Rate</div>
            </div>
        </div>
        
        <h3>Detailed Verification Results</h3>
        <table class="results-table">
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>File Checksum</th>
                    <th>Issues</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for result in results:
            status_class = "valid" if result.get('valid', False) else "invalid"
            status_text = "✅ VALID" if result.get('valid', False) else "❌ INVALID"
            issues = ", ".join(result.get('missing_fields', [])) or "None"
            checksum_short = result.get('file_checksum', '')[:16] + "..." if result.get('file_checksum') else "N/A"
            
            html_content += f"""
                <tr>
                    <td>{result.get('cve_id', 'UNKNOWN')}</td>
                    <td>{result.get('severity', 'UNKNOWN')}</td>
                    <td class="{status_class}">{status_text}</td>
                    <td class="checksum">{checksum_short}</td>
                    <td>{issues}</td>
                    <td>{result.get('timestamp', 'N/A')}</td>
                </tr>
"""
        
        html_content += f"""
            </tbody>
        </table>
        
        <div class="footer">
            <p><strong>Echo Forge-AI Integrity Multi-Agent Verification System</strong></p>
            <p>Lineage: {self.LINEAGE_ID} | Version: 1.0.0</p>
            <p>This report includes cryptographic integrity verification for all processed files.</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        # Generate checksum for the report
        report_checksum = self.generate_file_checksum(output_path)
        
        # Create checksum file
        checksum_path = output_path.with_suffix('.html.sha256')
        with open(checksum_path, 'w') as f:
            f.write(f"{report_checksum}  {output_path.name}\n")
        
        logger.info(f"Generated HTML report: {output_path}")
        logger.info(f"Report checksum: {report_checksum}")
        
        return output_path
    
    def run_full_verification(self) -> Tuple[Path, Path, Path]:
        """Run complete verification process and generate all report formats"""
        logger.info("Starting full verification process")
        
        # Batch verify all manifests
        results = self.batch_verify_manifests()
        
        if not results:
            logger.warning("No verification results to process")
            return None, None, None
        
        # Generate all report formats
        csv_report = self.generate_csv_report(results)
        md_report = self.generate_markdown_report(results)
        html_report = self.generate_html_report(results)
        
        logger.info("Full verification process completed")
        logger.info(f"Reports generated: CSV={csv_report}, MD={md_report}, HTML={html_report}")
        
        return csv_report, md_report, html_report

def main():
    """Main entry point for the verification system"""
    if len(sys.argv) > 1:
        base_path = sys.argv[1]
    else:
        base_path = "."
    
    verifier = EchoForgeVerifier(base_path)
    
    try:
        csv_report, md_report, html_report = verifier.run_full_verification()
        
        if csv_report and md_report and html_report:
            print(f"Verification completed successfully!")
            print(f"CSV Report: {csv_report}")
            print(f"Markdown Report: {md_report}")
            print(f"HTML Report: {html_report}")
        else:
            print("No reports generated - no CVE manifests found to process")
            
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()