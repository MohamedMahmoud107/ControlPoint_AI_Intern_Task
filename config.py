import os
from dataclasses import dataclass

@dataclass
class Config:
    # NVD API settings
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT_DELAY: float = 0.6  # seconds between requests
    
    # Agent settings
    FETCH_INTERVAL_MINUTES: int = 10
    LOOKBACK_MINUTES: int = 10
    
    # LLM settings
    OPENAI_MODEL: str = "gpt-4"
    LLM_TEMPERATURE: float = 0.3
    
    # File paths
    OUTPUT_FILE: str = "ot_threats.json"
    LOG_FILE: str = "agent.log"
    
    # Keywords for OT detection
    OT_KEYWORDS: list = [
        'SCADA', 'PLC', 'HMI', 'DCS', 'ICS', 'RTU',
        'Siemens', 'Rockwell', 'Allen-Bradley', 'Schneider', 'ABB', 'Emerson',
        'Modbus', 'DNP3', 'OPC', 'PROFINET', 'EtherNet/IP', 'BACnet',
        'industrial', 'factory', 'manufacturing', 'critical infrastructure',
        'water treatment', 'power grid', 'energy', 'oil gas', 'chemical plant',
        'OT', 'operational technology', 'industrial control', 'process control'
    ]
    
    @property
    def openai_api_key(self) -> str:
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        return key

config = Config()