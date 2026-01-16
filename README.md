# Autonomous OT/ICS Threat Intelligence Agent

## Overview
This Python-based AI agent continuously fetches new CVEs, analyzes them for OT/ICS relevance, and visualizes them on a live dashboard.

## Features
- Fetch latest CVEs from NVD API every 10 minutes
- Filter for OT-related vulnerabilities using keywords
- Analyze CVEs with OpenAI LLM
- Produce structured JSON output
- Streamlit dashboard with live refresh

## Requirements
- Python 3.12+
- Install dependencies: `pip install -r requirements.txt`

## How to Run

### Set OpenAI API key
```bash
export OPENAI_API_KEY="your-api-key"  # Linux/Mac
setx OPENAI_API_KEY "your-api-key"     # Windows
