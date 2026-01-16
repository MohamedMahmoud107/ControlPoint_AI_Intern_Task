import requests
import time
import json
from datetime import datetime, timedelta
from typing import List, Dict
import schedule

class CVEFetcher:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.last_fetch_time = None
        self.processed_cves = set()
        
    def fetch_latest_cves(self, lookback_minutes=10) -> List[Dict]:
        """Fetch CVEs from NVD API from the last X minutes"""
        try:
            # Calculate time window
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=lookback_minutes)
            
            # Format dates for NVD API
            start_date = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            end_date = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            
            params = {
                "lastModStartDate": start_date,
                "lastModEndDate": end_date,
                "resultsPerPage": 100
            }
            
            response = requests.get(self.nvd_api_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vulnerability in data.get('vulnerabilities', []):
                cve_data = vulnerability.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                # Skip already processed CVEs
                if cve_id in self.processed_cves:
                    continue
                
                # Extract relevant information
                description = cve_data.get('descriptions', [{}])[0].get('value', '')
                
                # Get CVSS score if available
                metrics = cve_data.get('metrics', {})
                cvss_score = None
                
                if 'cvssMetricV31' in metrics:
                    cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'cvssMetricV30' in metrics:
                    cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                elif 'cvssMetricV2' in metrics:
                    cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                
                cve_info = {
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'published_date': cve_data.get('published', ''),
                    'last_modified': cve_data.get('lastModified', ''),
                    'references': cve_data.get('references', []),
                    'raw_data': cve_data
                }
                
                cves.append(cve_info)
                self.processed_cves.add(cve_id)
            
            print(f"[{datetime.now()}] Fetched {len(cves)} new CVEs")
            return cves
            
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            return []
    
    def continuous_fetch(self, interval_minutes=10):
        """Continuous fetching on schedule"""
        def fetch_job():
            return self.fetch_latest_cves(interval_minutes)
        
        schedule.every(interval_minutes).minutes.do(fetch_job)
        
        print(f"Starting continuous CVE fetch every {interval_minutes} minutes")
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

if __name__ == "__main__":
    fetcher = CVEFetcher()
    test_cves = fetcher.fetch_latest_cves(lookback_minutes=60)
    print(f"Test fetch found {len(test_cves)} CVEs")