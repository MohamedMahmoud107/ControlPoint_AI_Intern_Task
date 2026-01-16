import json
import re
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from openai import OpenAI

@dataclass
class OTThreat:
    cve_id: str
    cvss_score: float
    description: str
    ai_insight: str
    ot_keywords_found: List[str]
    timestamp: str

class CVEOTAnalyzer:
    def __init__(self, openai_api_key: str, model="gpt-4o-mini"):
        self.client = OpenAI(api_key=openai_api_key)
        self.model = model
        
        # OT/ICS keywords to look for
        self.ot_keywords = [
            'SCADA', 'PLC', 'HMI', 'DCS', 'ICS', 'RTU',
            'Siemens', 'Rockwell', 'Allen-Bradley', 'Schneider', 'ABB', 'Emerson',
            'Modbus', 'DNP3', 'OPC', 'PROFINET', 'EtherNet/IP', 'BACnet',
            'industrial', 'factory', 'manufacturing', 'critical infrastructure',
            'water treatment', 'power grid', 'energy', 'oil gas', 'chemical plant',
            'OT', 'operational technology', 'industrial control', 'process control'
        ]
    
    def is_ot_related(self, description: str) -> bool:
        """Check if CVE description contains OT/ICS keywords"""
        description_lower = description.lower()
        keywords_lower = [k.lower() for k in self.ot_keywords]
        for keyword in keywords_lower:
            if keyword in description_lower:
                return True
        return False
    
    def analyze_with_llm(self, cve_data: Dict) -> Optional[OTThreat]:
        """Use new OpenAI Responses API to analyze CVE and generate OT insights"""
        description = cve_data['description']
        cve_id = cve_data['cve_id']
        cvss_score = cve_data.get('cvss_score', 0.0)
        
        # Quick keyword-based check
        found_keywords = [k for k in self.ot_keywords if k.lower() in description.lower()]
        if not found_keywords:
            return None  # Skip if no OT keywords
        
        try:
            prompt = f"""
Analyze this CVE for Operational Technology (OT/ICS) impact:

CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss_score if cvss_score else 'Not specified'}

Task:
1. Confirm this is OT/ICS related
2. Explain why this is dangerous for industrial environments/factories
3. Focus on potential impact to: production lines, safety systems, physical processes

Respond in JSON format:
{{
    "is_ot_related": true/false,
    "risk_explanation": "Detailed explanation of OT risks",
    "affected_systems": ["PLC", "SCADA", etc.],
    "recommended_actions": ["Immediate actions to take"]
}}
"""
            response = self.client.responses.create(
                model=self.model,
                input=[
                    {"role": "system", "content": "You are an OT cybersecurity expert analyzing vulnerabilities in industrial control systems."},
                    {"role": "user", "content": prompt}
                ]
            )

            llm_response_text = response.output_text.strip()
            llm_response = json.loads(llm_response_text)
            
            if llm_response.get("is_ot_related", False):
                return OTThreat(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    description=description[:500],
                    ai_insight=llm_response.get("risk_explanation", "No insight provided"),
                    ot_keywords_found=found_keywords,
                    timestamp=datetime.now().isoformat()
                )
            else:
                return None
        
        except Exception as e:
            print(f"Error analyzing CVE {cve_id} with LLM: {e}")
            # Fallback: consider CVE OT-related if keywords found
            return OTThreat(
                cve_id=cve_id,
                cvss_score=cvss_score,
                description=description[:500],
                ai_insight="Rule-based OT detection (LLM unavailable)",
                ot_keywords_found=found_keywords,
                timestamp=datetime.now().isoformat()
            )
    
    def batch_analyze(self, cves: List[Dict]) -> List[OTThreat]:
        """Analyze multiple CVEs and return OT threats"""
        ot_threats = []
        for cve in cves:
            threat = self.analyze_with_llm(cve)
            if threat:
                ot_threats.append(threat)
                print(f"Found OT threat: {threat.cve_id}")
        return ot_threats
