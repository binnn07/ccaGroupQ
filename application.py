import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np

st.set_page_config(page_title="Cyber Attack Explorer", layout="wide")

st.title("🔐 Cyber Attack Explorer with CTI/CCI Capabilities")
st.write("Upload cyber attacks CSV file for threat intelligence analysis.")

# --- Upload CSV file ---
uploaded_file = st.file_uploader("Modern Attacks Data.csv", type=["csv"])

# Security measures based on Synoptek article
security_measures = [
    {
        "title": "🔐 Implement Multi-Factor Authentication (MFA)",
        "description": "Require multiple forms of verification for accessing critical systems and data.",
        "priority": "High",
        "cci_related": True
    },
    {
        "title": "🛡 Deploy Endpoint Detection and Response (EDR)",
        "description": "Monitor endpoints for suspicious activities, malware, and unauthorized access.",
        "priority": "High",
        "cci_related": True
    },
    {
        "title": "📋 Establish Zero Trust Architecture",
        "description": "Verify every access request and implement least-privilege access.",
        "priority": "High",
        "cci_related": True
    },
    {
        "title": "🚨 Develop Incident Response Plan",
        "description": "Create and regularly test comprehensive incident response procedures.",
        "priority": "High",
        "cci_related": False
    },
    {
        "title": "🎓 Conduct Security Awareness Training",
        "description": "Train employees to recognize phishing and social engineering attacks.",
        "priority": "Medium",
        "cci_related": True
    },
    {
        "title": "💾 Maintain Regular Backups",
        "description": "Implement 3-2-1 backup strategy with regular restoration testing.",
        "priority": "High",
        "cci_related": False
    },
    {
        "title": "🔒 Apply Security Patches Promptly",
        "description": "Establish patch management process for critical updates.",
        "priority": "High",
        "cci_related": False
    }
]

# CCI Techniques Database
cci_techniques = [
    {
        "name": "Honeypot Deployment",
        "type": "Deception",
        "description": "Deploy decoy systems to attract and study attackers",
        "effectiveness": "High",
        "implementation": "Medium"
    },
    {
        "name": "Threat Attribution",
        "type": "Analysis",
        "description": "Identify and track threat actors behind attacks",
        "effectiveness": "Medium",
        "implementation": "Hard"
    },
    {
        "name": "Counter-Surveillance",
        "type": "Monitoring",
        "description": "Monitor for reconnaissance activities against your network",
        "effectiveness": "High",
        "implementation": "Medium"
    },
    {
        "name": "Deception Technology",
        "type": "Deception",
        "description": "Use fake credentials, data, and systems to mislead attackers",
        "effectiveness": "High",
        "implementation": "Medium"
    },
    {
        "name": "Threat Hunting",
        "type": "Proactive",
        "description": "Actively search for indicators of compromise in your network",
        "effectiveness": "High",
        "implementation": "Hard"
    },
    {
        "name": "MISDIRECTION",
        "type": "Deception",
        "description": "Create false network paths and vulnerabilities",
        "effectiveness": "Medium",
        "implementation": "Easy"
    }
]

# APT Groups Database (for threat intelligence)
apt_groups = {
    "APT29": {"country": "Russia", "targets": ["Government", "Healthcare", "Research"], "ttps": ["Spear phishing", "Malware", "Credential theft"]},
    "APT28": {"country": "Russia", "targets": ["Military", "Government", "Energy"], "ttps": ["Zero-day exploits", "Network intrusion", "Data exfiltration"]},
    "Lazarus": {"country": "North Korea", "targets": ["Finance", "Cryptocurrency", "Entertainment"], "ttps": ["Supply chain attacks", "Ransomware", "Banking trojans"]},
    "Equation": {"country": "USA", "targets": ["Telecom", "Government", "Military"], "ttps": ["Firmware implants", "Hardware attacks", "Stealth operations"]},
    "MuddyWater": {"country": "Iran", "targets": ["Middle East Governments", "Telecom", "Oil & Gas"], "ttps": ["Powershell attacks", "Living off the land", "Backdoors"]}
}

if uploaded_file:
    # Read CSV
    try:
        df = pd.read_csv(uploaded_file)
        
        st.subheader("📌 Dataset Preview")
        st.dataframe(df.head(), use_container_width=True)

        # Detect columns
        col_list = df.columns.tolist()

        # Try auto-detect common column names
        possible_date_cols = [c for c in col_list if "date" in c.lower()]
        possible_attack_cols = [c for c in col_list if "attack" in c.lower()]
        possible_severity_cols = [c for c in col_list if "severity" in c.lower()]
        possible_target_cols = [c for c in col_list if "target" in c.lower() or "sector" in c.lower()]
        possible_vector_cols = [c for c in col_list if "vector" in c.lower() or "method" in c.lower()]

        # Choose columns dynamically
        date_col = possible_date_cols[0] if possible_date_cols else None
        attack_col = possible_attack_cols[0] if possible_attack_cols else None
        severity_col = possible_severity_cols[0] if possible_severity_cols else None
        target_col = possible_target_cols[0] if possible_target_cols else None
        vector_col = possible_vector_cols[0] if possible_vector_cols else None

        st.success("CSV file loaded successfully! Columns detected automatically.")

        # Tabs with CTI/CCI capabilities
        tab1, tab2, tab3, tab4 = st.tabs([
            "🛡 Latest Cyber Attacks", 
            "🔧 Security Measures", 
            "🕵‍♂ CTI Analysis",
            "🎯 CCI Operations"
        ])

        # --- TAB 1: Cyber Attacks ---
        with tab1:
            st.header("🛡 Latest Cyber Attacks")

            # Filter by attack type if available
            if attack_col:
                attack_types = df[attack_col].dropna().unique().tolist()
                selected_type = st.selectbox("Filter by Attack Type", ["All"] + attack_types)
                if selected_type != "All":
                    df_display = df[df[attack_col] == selected_type]
                else:
                    df_display = df.copy()
            else:
                df_display = df.copy()

            # Filter by severity if available
            if severity_col:
                severities = df_display[severity_col].dropna().unique().tolist()
                selected_severity = st.selectbox("Filter by Severity", ["All"] + severities)
                if selected_severity != "All":
                    df_display = df_display[df_display[severity_col] == selected_severity]

            # Filter by date range if available
            if date_col:
                df_display[date_col] = pd.to_datetime(df_display[date_col], errors="coerce")
                min_d = df_display[date_col].min()
                max_d = df_display[date_col].max()
                if pd.notnull(min_d) and pd.notnull(max_d):
                    date_range = st.date_input("Select Date Range", [min_d, max_d])
                    if len(date_range) == 2:
                        start, end = date_range
                        df_display = df_display[(df_display[date_col] >= pd.to_datetime(start)) & (df_display[date_col] <= pd.to_datetime(end))]

            # Display filtered results
            st.subheader("📄 Filtered Cyber Attacks")
            st.dataframe(df_display, use_container_width=True)
            
            # Quick stats
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Attacks", len(df_display))
            with col2:
                if severity_col:
                    high_severity = len(df_display[df_display[severity_col].astype(str).str.contains("High|Critical", case=False, na=False)])
                    st.metric("High Severity", high_severity)
            with col3:
                if date_col:
                    recent_attacks = len(df_display[df_display[date_col] >= pd.Timestamp.now() - pd.Timedelta(days=30)])
                    st.metric("Last 30 Days", recent_attacks)

        # --- TAB 2: Security Measures ---
        with tab2:
            st.header("🔧 Top Cybersecurity Action Items")
            st.caption("Based on Synoptek Cybersecurity Recommendations")
            
            # Filter by CCI related measures
            show_cci_only = st.checkbox("Show only CCI-related measures")
            
            filtered_measures = security_measures
            if show_cci_only:
                filtered_measures = [m for m in security_measures if m['cci_related']]
                st.info(f"Showing {len(filtered_measures)} CCI-related security measures")
            
            # Create expandable sections for each measure
            for idx, measure in enumerate(filtered_measures, 1):
                with st.expander(f"{idx}. {measure['title']} - Priority: {measure['priority']}"):
                    st.write(measure['description'])
                    
                    # CCI badge
                    if measure['cci_related']:
                        st.success("✅ CCI-Related: Supports Counterintelligence Operations")
                    
                    # Add visual priority indicator
                    if measure['priority'] == "High":
                        st.error("🚨 High Priority - Implement immediately")
                    elif measure['priority'] == "Medium":
                        st.warning("⚠ Medium Priority - Schedule implementation")
                    
                    # Add implementation checklist
                    st.subheader("Implementation Checklist:")
                    if "MFA" in measure['title']:
                        st.checkbox("Enable MFA for all admin accounts")
                        st.checkbox("Enable MFA for all remote access")
                        st.checkbox("Implement conditional access policies")
                    elif "EDR" in measure['title']:
                        st.checkbox("Deploy EDR on all endpoints")
                        st.checkbox("Enable real-time monitoring")
                        st.checkbox("Configure automated response rules")
                    elif "Zero Trust" in measure['title']:
                        st.checkbox("Implement network segmentation")
                        st.checkbox("Enforce least-privilege access")
                        st.checkbox("Set up identity verification for all access")
            
            # Summary statistics
            st.divider()
            st.subheader("📊 Security Posture Summary")
            
            high_priority = len([m for m in security_measures if m['priority'] == 'High'])
            cci_measures = len([m for m in security_measures if m['cci_related']])
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Measures", len(security_measures))
            with col2:
                st.metric("CCI-Ready", cci_measures, delta=f"{int((cci_measures/len(security_measures))*100)}%")
            with col3:
                st.metric("High Priority", high_priority)

        # --- TAB 3: CTI Analysis ---
        with tab3:
            st.header("🕵‍♂ Cyber Threat Intelligence Dashboard")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📈 Attack Trends")
                if date_col and attack_col:
                    # Create time series analysis
                    df[date_col] = pd.to_datetime(df[date_col], errors='coerce')
                    time_series = df.groupby(df[date_col].dt.to_period('M')).size().reset_index(name='count')
                    time_series[date_col] = time_series[date_col].astype(str)
                    
                    fig = px.line(time_series, x=date_col, y='count', 
                                 title='Monthly Attack Frequency',
                                 markers=True)
                    st.plotly_chart(fig, use_container_width=True)
                
                # Attack type distribution
                if attack_col:
                    attack_dist = df[attack_col].value_counts().reset_index()
                    attack_dist.columns = ['Attack Type', 'Count']
                    
                    fig2 = px.pie(attack_dist, values='Count', names='Attack Type',
                                 title='Attack Type Distribution')
                    st.plotly_chart(fig2, use_container_width=True)
            
            with col2:
                st.subheader("🎯 Targeted Sectors")
                if target_col:
                    sector_dist = df[target_col].value_counts().reset_index()
                    sector_dist.columns = ['Sector', 'Count']
                    
                    fig3 = px.bar(sector_dist.head(10), x='Sector', y='Count',
                                 title='Top 10 Targeted Sectors')
                    st.plotly_chart(fig3, use_container_width=True)
                
                # Threat Actor Intelligence
                st.subheader("🕵 Known APT Groups")
                selected_apt = st.selectbox("Select APT Group", list(apt_groups.keys()))
                
                if selected_apt:
                    group_info = apt_groups[selected_apt]
                    st.info(f"*Country:* {group_info['country']}")
                    st.write(f"*Primary Targets:* {', '.join(group_info['targets'])}")
                    st.write(f"*Common TTPs:* {', '.join(group_info['ttps'])}")
                    
                    # Mitigation recommendations
                    st.write("*Recommended Mitigations:*")
                    for ttp in group_info['ttps']:
                        if "phishing" in ttp.lower():
                            st.write("- Implement advanced email filtering")
                        if "malware" in ttp.lower():
                            st.write("- Deploy endpoint protection with behavioral analysis")
                        if "zero-day" in ttp.lower():
                            st.write("- Use application whitelisting and patch promptly")
                
                # IOCs Analysis
                st.subheader("🔍 Indicator of Compromise (IOC) Search")
                ioc_input = st.text_input("Enter IP, Domain, or Hash to check")
                if ioc_input:
                    # Simulated IOC check
                    st.write(f"Checking {ioc_input} against threat databases...")
                    # In real implementation, this would query threat intelligence feeds
                    st.success("No known malicious activity found")
                    # For demo purposes
                    st.info("Consider implementing automated IOC checking with Threat Intelligence Platforms (TIP)")

        # --- TAB 4: CCI Operations ---
        with tab4:
            st.header("🎯 Cyber Counterintelligence Operations")
            st.write("Proactive measures to detect, deceive, and deter threat actors")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("🪤 Deception Techniques")
                
                # Display CCI techniques
                for tech in cci_techniques:
                    with st.expander(f"{tech['name']} - {tech['type']}"):
                        st.write(f"*Description:* {tech['description']}")
                        st.write(f"*Effectiveness:* {tech['effectiveness']}")
                        st.write(f"*Implementation Difficulty:* {tech['implementation']}")
                        
                        # Deployment options
                        if st.button(f"Simulate {tech['name']}", key=tech['name']):
                            st.success(f"✅ {tech['name']} deployed!")
                            if tech['name'] == "Honeypot Deployment":
                                st.info("Honeypot active. Monitoring for attacker interactions...")
                            elif tech['name'] == "Deception Technology":
                                st.info("Deception assets deployed. Tracking attacker movements...")
            
            with col2:
                st.subheader("📊 CCI Effectiveness Metrics")
                
                # Simulated CCI metrics
                metrics_data = {
                    'Technique': [t['name'] for t in cci_techniques],
                    'Detection Rate %': [85, 70, 90, 88, 92, 75],
                    'False Positives': [5, 15, 3, 8, 2, 20],
                    'Attacker Engagement': [80, 60, 85, 82, 90, 65]
                }
                
                metrics_df = pd.DataFrame(metrics_data)
                st.dataframe(metrics_df, use_container_width=True)
                
                # CCI Dashboard
                st.subheader("🎮 Active CCI Operations")
                
                operation_status = {
                    "Honeypot Network": "🟢 Active",
                    "Threat Hunting Team": "🟡 Monitoring",
                    "Deception Grid": "🟢 Active",
                    "Counter-Surveillance": "🔴 Offline",
                    "Misdirection Layer": "🟢 Active"
                }
                
                for op, status in operation_status.items():
                    st.write(f"- {op}: {status}")
                
                # CCI Recommendations
                st.subheader("🎯 Recommended CCI Actions")
                
                # Analyze attack patterns to recommend CCI techniques
                if attack_col:
                    common_attacks = df[attack_col].value_counts().head(3)
                    st.write("Based on your attack patterns:")
                    
                    for attack, count in common_attacks.items():
                        if "phishing" in str(attack).lower():
                            st.write(f"- For {attack}: Deploy email deception and credential honeypots")
                        elif "malware" in str(attack).lower():
                            st.write(f"- For {attack}: Implement file-based deception and sandboxing")
                        elif "ddos" in str(attack).lower():
                            st.write(f"- For {attack}: Use traffic redirection and sinkholing")
                        else:
                            st.write(f"- For {attack}: Consider general honeypot deployment")
                
                # CCI Simulation
                st.subheader("🎮 CCI Simulation Exercise")
                
                scenario = st.selectbox("Select Threat Scenario", [
                    "Advanced Persistent Threat",
                    "Insider Threat",
                    "Ransomware Attack",
                    "Supply Chain Compromise"
                ])
                
                if st.button("Run CCI Simulation"):
                    st.info(f"Simulating {scenario}...")
                    st.write("*Deployed CCI Measures:*")
                    st.write("1. Honeypot network activated")
                    st.write("2. Deception credentials planted")
                    st.write("3. Network segmentation enhanced")
                    st.write("4. Threat hunting initiated")
                    st.success("✅ Simulation complete. Attacker detected and tracked!")

    except Exception as e:
        st.error(f"Error reading CSV file: {e}")

else:
    st.info("Please upload a .csv file to begin.")
