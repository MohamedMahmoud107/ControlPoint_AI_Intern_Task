import json
import time
from datetime import datetime
from typing import List
from cve_fetcher import CVEFetcher
from cve_analyzer import CVEOTAnalyzer, OTThreat
from dataclasses import asdict


class AutonomousOTAgent:
    def __init__(self, openai_api_key: str):
        self.fetcher = CVEFetcher()
        self.analyzer = CVEOTAnalyzer(openai_api_key)
        self.ot_threats: List[OTThreat] = []
        self.output_file = "ot_threats.json"
        self.load_existing_threats()
    
    def load_existing_threats(self):
        """Load previously detected threats"""
        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)
                self.ot_threats = [OTThreat(**item) for item in data]
            print(f"Loaded {len(self.ot_threats)} existing OT threats")
        except FileNotFoundError:
            pass
    
    def save_threats(self):
        """Save threats to JSON file"""
        with open(self.output_file, 'w') as f:
            threats_dict = [asdict(threat) for threat in self.ot_threats]
            json.dump(threats_dict, f, indent=2)
    
    def run_cycle(self):
        """Execute one complete monitoring cycle"""
        print(f"\n=== Running monitoring cycle at {datetime.now()} ===")
        
        # Step 1: Fetch new CVEs
        new_cves = self.fetcher.fetch_latest_cves(lookback_minutes=10)
        
        if not new_cves:
            print("No new CVEs found")
            return
        
        # Step 2: Analyze for OT threats
        ot_threats = self.analyzer.batch_analyze(new_cves)
        
        # Step 3: Add to list and save
        for threat in ot_threats:
            # Check if already exists
            if not any(t.cve_id == threat.cve_id for t in self.ot_threats):
                self.ot_threats.append(threat)
                print(f"✅ New OT threat detected: {threat.cve_id}")
        
        # Step 4: Save to file
        self.save_threats()
        
        print(f"Cycle complete. Total OT threats: {len(self.ot_threats)}")
    
    def run_continuous(self, interval_minutes=10):
        """Run agent continuously"""
        print(f"Starting Autonomous OT Agent (checks every {interval_minutes} minutes)")
        print("Press Ctrl+C to stop\n")
        
        # Run immediately first
        self.run_cycle()
        
        # Then run on schedule
        try:
            while True:
                time.sleep(interval_minutes * 60)
                self.run_cycle()
        except KeyboardInterrupt:
            print("\nAgent stopped by user")

if __name__ == "__main__":
    import os
    
    # Get OpenAI API key from environment variable
    api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        print("Please set it: export OPENAI_API_KEY='your-key-here'")
        exit(1)
    
    agent = AutonomousOTAgent(api_key)
    
    # Run in continuous mode
    agent.run_continuous(interval_minutes=10)