#!/usr/bin/env python3
"""
Python Dialect Processor for Echo Forge-AI Integrity
Handles Python-specific verification tasks and data processing
Lineage: RepoReportEcho_092425
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np
from datetime import datetime
import logging

# Add the verification module to path
sys.path.append(str(Path(__file__).parent.parent.parent / "verification"))
from core_verifier import EchoForgeVerifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PythonDialectProcessor:
    """Python-specific processing for CVE analysis and data manipulation"""
    
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.verifier = EchoForgeVerifier(base_path)
        logger.info("Initialized Python Dialect Processor")
    
    def analyze_severity_distribution(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze severity distribution of CVE results"""
        if not results:
            return {"error": "No results to analyze"}
        
        # Create DataFrame for analysis
        df = pd.DataFrame(results)
        
        # Severity distribution
        severity_counts = df['severity'].value_counts().to_dict()
        
        # Valid/Invalid distribution
        validity_counts = df['valid'].value_counts().to_dict()
        
        # Calculate statistics
        total_count = len(results)
        valid_percentage = (validity_counts.get(True, 0) / total_count) * 100
        
        analysis = {
            "total_manifests": total_count,
            "severity_distribution": severity_counts,
            "validity_distribution": {
                "valid": validity_counts.get(True, 0),
                "invalid": validity_counts.get(False, 0),
                "valid_percentage": round(valid_percentage, 2)
            },
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "lineage_id": EchoForgeVerifier.LINEAGE_ID,
            "processor": "Python Dialect"
        }
        
        logger.info(f"Severity analysis completed: {severity_counts}")
        return analysis
    
    def generate_risk_matrix(self, results: List[Dict[str, Any]]) -> np.ndarray:
        """Generate a risk assessment matrix from CVE data"""
        if not results:
            return np.array([])
        
        # Create numerical mapping for severity
        severity_mapping = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3,
            'CRITICAL': 4,
            'UNKNOWN': 0,
            'ERROR': 0
        }
        
        # Create risk matrix
        risk_scores = []
        for result in results:
            severity = result.get('severity', 'UNKNOWN')
            validity_factor = 1.0 if result.get('valid', False) else 0.5
            risk_score = severity_mapping.get(severity, 0) * validity_factor
            risk_scores.append(risk_score)
        
        risk_matrix = np.array(risk_scores).reshape(-1, 1)
        logger.info(f"Generated risk matrix with shape: {risk_matrix.shape}")
        return risk_matrix
    
    def calculate_checksum_integrity(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate integrity metrics based on checksums"""
        if not results:
            return {"error": "No results to analyze"}
        
        checksum_analysis = {
            "total_files": len(results),
            "files_with_checksums": 0,
            "unique_checksums": set(),
            "checksum_length_distribution": {},
            "potential_duplicates": []
        }
        
        for result in results:
            file_checksum = result.get('file_checksum', '')
            if file_checksum:
                checksum_analysis["files_with_checksums"] += 1
                checksum_analysis["unique_checksums"].add(file_checksum)
                
                # Track checksum length distribution
                checksum_length = len(file_checksum)
                if checksum_length in checksum_analysis["checksum_length_distribution"]:
                    checksum_analysis["checksum_length_distribution"][checksum_length] += 1
                else:
                    checksum_analysis["checksum_length_distribution"][checksum_length] = 1
        
        # Convert set to count for JSON serialization
        checksum_analysis["unique_checksum_count"] = len(checksum_analysis["unique_checksums"])
        del checksum_analysis["unique_checksums"]  # Remove set for JSON compatibility
        
        # Calculate integrity percentage
        if checksum_analysis["total_files"] > 0:
            integrity_percentage = (checksum_analysis["files_with_checksums"] / 
                                   checksum_analysis["total_files"]) * 100
            checksum_analysis["integrity_percentage"] = round(integrity_percentage, 2)
        
        checksum_analysis["analysis_timestamp"] = datetime.utcnow().isoformat()
        checksum_analysis["lineage_id"] = EchoForgeVerifier.LINEAGE_ID
        
        logger.info(f"Checksum integrity analysis: {integrity_percentage:.2f}% coverage" if 'integrity_percentage' in locals() else "Checksum analysis completed")
        return checksum_analysis
    
    def export_to_dataframe(self, results: List[Dict[str, Any]]) -> pd.DataFrame:
        """Export verification results to pandas DataFrame for further analysis"""
        if not results:
            return pd.DataFrame()
        
        df = pd.DataFrame(results)
        
        # Add computed columns
        df['processing_date'] = datetime.utcnow().strftime('%Y-%m-%d')
        df['risk_score'] = df['severity'].map({
            'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4
        }).fillna(0)
        
        logger.info(f"Created DataFrame with {len(df)} rows and {len(df.columns)} columns")
        return df
    
    def generate_statistical_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive statistical summary of verification results"""
        if not results:
            return {"error": "No results to analyze"}
        
        df = pd.DataFrame(results)
        
        summary = {
            "dataset_info": {
                "total_records": len(df),
                "columns": list(df.columns),
                "data_types": df.dtypes.astype(str).to_dict()
            },
            "severity_analysis": {
                "distribution": df['severity'].value_counts().to_dict(),
                "most_common": df['severity'].mode().iloc[0] if not df['severity'].empty else None
            },
            "validity_analysis": {
                "valid_count": int(df['valid'].sum()),
                "invalid_count": int((~df['valid']).sum()),
                "validity_rate": float(df['valid'].mean()) if len(df) > 0 else 0
            },
            "temporal_analysis": {
                "earliest_timestamp": df['timestamp'].min() if 'timestamp' in df.columns else None,
                "latest_timestamp": df['timestamp'].max() if 'timestamp' in df.columns else None
            },
            "missing_data_analysis": {
                "missing_fields_summary": {},
                "total_missing_field_instances": 0
            }
        }
        
        # Analyze missing fields
        for _, result in df.iterrows():
            missing_fields = result.get('missing_fields', [])
            if missing_fields:
                for field in missing_fields:
                    if field in summary["missing_data_analysis"]["missing_fields_summary"]:
                        summary["missing_data_analysis"]["missing_fields_summary"][field] += 1
                    else:
                        summary["missing_data_analysis"]["missing_fields_summary"][field] = 1
                    summary["missing_data_analysis"]["total_missing_field_instances"] += 1
        
        summary["generation_metadata"] = {
            "generated_by": "Python Dialect Processor",
            "timestamp": datetime.utcnow().isoformat(),
            "lineage_id": EchoForgeVerifier.LINEAGE_ID,
            "version": "1.0.0"
        }
        
        logger.info("Generated comprehensive statistical summary")
        return summary
    
    def run_advanced_analysis(self) -> Dict[str, Any]:
        """Run comprehensive analysis using Python data science capabilities"""
        logger.info("Starting advanced Python analysis")
        
        # Get verification results
        results = self.verifier.batch_verify_manifests()
        
        if not results:
            return {"error": "No data available for analysis"}
        
        # Perform various analyses
        analyses = {
            "severity_distribution": self.analyze_severity_distribution(results),
            "checksum_integrity": self.calculate_checksum_integrity(results),
            "statistical_summary": self.generate_statistical_summary(results),
            "risk_matrix_shape": self.generate_risk_matrix(results).shape
        }
        
        # Save DataFrame for potential external use
        df = self.export_to_dataframe(results)
        if not df.empty:
            output_path = self.base_path / "reports" / "python_analysis_dataframe.csv"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(output_path, index=False)
            analyses["dataframe_export"] = str(output_path)
        
        analyses["analysis_metadata"] = {
            "total_records_processed": len(results),
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "lineage_id": EchoForgeVerifier.LINEAGE_ID,
            "processor": "Python Dialect Advanced Analysis"
        }
        
        logger.info("Advanced Python analysis completed")
        return analyses

def main():
    """Main entry point for Python dialect processor"""
    base_path = sys.argv[1] if len(sys.argv) > 1 else "."
    
    processor = PythonDialectProcessor(base_path)
    
    try:
        # Run advanced analysis
        analysis_results = processor.run_advanced_analysis()
        
        # Save analysis results
        output_path = Path(base_path) / "reports" / "python" / f"advanced_analysis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)
        
        print(f"Python dialect analysis completed: {output_path}")
        print(f"Analysis summary: {analysis_results.get('analysis_metadata', {})}")
        
    except Exception as e:
        logger.error(f"Python dialect processing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()