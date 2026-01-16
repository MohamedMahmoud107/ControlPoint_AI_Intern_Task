import streamlit as st
import pandas as pd
import json
import time
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

class OTThreatDashboard:
    def __init__(self, data_file="ot_threats.json"):
        self.data_file = data_file
        st.set_page_config(
            page_title="OT/ICS Threat Monitor",
            page_icon="⚠️",
            layout="wide"
        )
    
    def load_data(self):
        """Load threat data from JSON file"""
        try:
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return []
    
    def create_dashboard(self):
        """Create Streamlit dashboard"""
        st.title("🔒 Autonomous OT/ICS Threat Monitor")
        st.markdown("""
        Real-time monitoring of Operational Technology vulnerabilities
        *Automatically detects threats to PLCs, SCADA, HMIs, and industrial control systems*
        """)
        
        # Sidebar controls
        with st.sidebar:
            st.header("Controls")
            auto_refresh = st.checkbox("Auto-refresh (30s)", value=True)
            refresh_btn = st.button("🔄 Manual Refresh")
            
            if refresh_btn:
                st.experimental_rerun()
            
            st.divider()
            st.header("Filters")
            min_cvss = st.slider("Minimum CVSS Score", 0.0, 10.0, 7.0, 0.1)
            show_resolved = st.checkbox("Show Resolved Threats", False)
        
        # Main content area
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("📋 Active OT/ICS Threats")
            
            # Load and filter data
            threats = self.load_data()
            
            if not threats:
                st.info("No OT threats detected yet. The agent is monitoring...")
            else:
                # Convert to DataFrame for display
                df = pd.DataFrame(threats)
                
                # Filter by CVSS
                if 'cvss_score' in df.columns:
                    df = df[df['cvss_score'] >= min_cvss]
                
                # Display metrics
                metrics_col1, metrics_col2, metrics_col3, metrics_col4 = st.columns(4)
                
                with metrics_col1:
                    st.metric("Total Threats", len(df))
                
                with metrics_col2:
                    high_crit = len(df[df['cvss_score'] >= 9.0]) if 'cvss_score' in df.columns else 0
                    st.metric("Critical (CVSS ≥9)", high_crit, delta=None)
                
                with metrics_col3:
                    recent_threats = len(df)  # Simplified - would filter by timestamp
                    st.metric("Last 24h", recent_threats)
                
                with metrics_col4:
                    unique_vendors = len(df['ot_keywords_found'].explode().unique()) if 'ot_keywords_found' in df.columns else 0
                    st.metric("Affected Vendors", unique_vendors)
                
                # Display threats table
                if not df.empty:
                    display_df = df[['cve_id', 'cvss_score', 'description', 'timestamp']].copy()
                    display_df.columns = ['CVE ID', 'CVSS', 'Description', 'Detected']
                    
                    # Add color coding for CVSS
                    def color_cvss(val):
                        if val >= 9.0:
                            return 'background-color: #ff4b4b; color: white'
                        elif val >= 7.0:
                            return 'background-color: #ffa500; color: white'
                        elif val >= 4.0:
                            return 'background-color: #ffff00'
                        else:
                            return 'background-color: #90ee90'
                    
                    styled_df = display_df.style.applymap(
                        lambda x: color_cvss(x) if isinstance(x, (int, float)) else '', 
                        subset=['CVSS']
                    )
                    
                    st.dataframe(styled_df, use_container_width=True)
                    
                    # Threat details expander
                    for idx, threat in enumerate(threats[:5]):  # Show first 5
                        with st.expander(f"🔍 {threat['cve_id']} - Details"):
                            st.write(f"**CVSS Score:** {threat.get('cvss_score', 'N/A')}")
                            st.write(f"**Keywords:** {', '.join(threat.get('ot_keywords_found', []))}")
                            st.write(f"**AI Analysis:**")
                            st.info(threat.get('ai_insight', 'No analysis available'))
                            
                            if threat.get('references'):
                                st.write("**References:**")
                                for ref in threat['references'][:3]:
                                    st.markdown(f"- [{ref.get('url', 'Link')}]({ref.get('url', '#')})")
                else:
                    st.warning("No threats match the current filters")
        
        with col2:
            st.subheader("📊 Threat Analysis")
            
            if threats:
                # CVSS distribution
                cvss_scores = [t.get('cvss_score', 0) for t in threats if t.get('cvss_score')]
                
                if cvss_scores:
                    fig = go.Figure(data=[go.Histogram(x=cvss_scores, nbinsx=10)])
                    fig.update_layout(
                        title="CVSS Score Distribution",
                        xaxis_title="CVSS Score",
                        yaxis_title="Count",
                        height=300
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Keyword frequency
                all_keywords = []
                for threat in threats:
                    all_keywords.extend(threat.get('ot_keywords_found', []))
                
                if all_keywords:
                    keyword_counts = pd.Series(all_keywords).value_counts().head(10)
                    fig2 = px.bar(
                        x=keyword_counts.values,
                        y=keyword_counts.index,
                        orientation='h',
                        title="Top Affected Systems/Vendors"
                    )
                    fig2.update_layout(height=300)
                    st.plotly_chart(fig2, use_container_width=True)
            
            # Last update time
            st.divider()
            st.write(f"**Last Update:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            st.caption("The AI agent checks for new vulnerabilities every 10 minutes")
        
        # Auto-refresh logic
        if auto_refresh:
            time.sleep(30)
            st.rerun()

if __name__ == "__main__":
    dashboard = OTThreatDashboard()
    dashboard.create_dashboard()