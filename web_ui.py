# web_ui.py
import requests
import os
import streamlit as st
import pandas as pd
import time
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Configuration
API_URL = "http://127.0.0.1:5000/api"
# API_KEY = os.environ.get("DDOS_API_KEY", "change_this_to_a_secure_random_string")

# Functions to interact with the API
def get_status():
    try:
        response = requests.get(
            f"{API_URL}/status",
            # headers={"X-API-Key": API_KEY},
            timeout=5
        )
        return response.json()
    except Exception as e:
        st.error(f"Error fetching status: {str(e)}")
        return None

def get_blocked_ips():
    try:
        response = requests.get(
            f"{API_URL}/blocked",
            # headers={"X-API-Key": API_KEY},
            timeout=5
        )
        return response.json().get('blocked_ips', [])
    except Exception as e:
        st.error(f"Error fetching blocked IPs: {str(e)}")
        return []

def unblock_ip(ip):
    try:
        response = requests.post(
            f"{API_URL}/unblock/{ip}",
            # headers={"X-API-Key": API_KEY},
            timeout=5
        )
        if response.ok:
            st.success(f"IP {ip} unblocked successfully")
        else:
            st.error(f"Error unblocking IP: {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        st.error(f"Error communicating with API: {str(e)}")

def block_ip(ip):
    try:
        response = requests.post(
            f"{API_URL}/block/{ip}",
            # headers={"X-API-Key": API_KEY},
            timeout=5
        )
        if response.ok:
            st.success(f"IP {ip} blocked successfully")
        else:
            st.error(f"Error blocking IP: {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        st.error(f"Error communicating with API: {str(e)}")

# Set page title and layout
st.set_page_config(
    page_title="DDoS Defense Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Sidebar
st.sidebar.title("DDoS Defense System")
st.sidebar.info("This dashboard provides monitoring and control capabilities for the DDoS Defense System.")

# Navigation
page = st.sidebar.radio("Navigation", ["Dashboard", "Blocked IPs", "Manual Block", "System Logs"])

# Auto refresh toggle
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)
refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 5, 60, 10)

# Main content
if page == "Dashboard":
    st.title("DDoS Defense System Dashboard")
    
    # Create placeholder for metrics that will be updated
    metrics_container = st.container()
    
    # Create columns for charts
    col1, col2 = st.columns(2)
    
    # Placeholders for charts
    with col1:
        chart1_container = st.container()
    
    with col2:
        chart2_container = st.container()
    
    # Auto refresh loop
    counter = 0
    while True:
        # Get status data
        status = get_status()
        blocked = get_blocked_ips()
        
        with metrics_container:
            # Create metrics row
            metric_cols = st.columns(4)
            
            with metric_cols[0]:
                st.metric("Service Status", "Running" if status and status.get('running') else "Stopped")
            
            with metric_cols[1]:
                st.metric("Blocked IPs", len(blocked) if blocked else 0)
            
            with metric_cols[2]:
                st.metric("Suspicious IPs", status.get('suspicious_ips', 0) if status else 0)
            
            with metric_cols[3]:
                st.metric("Last Refresh", datetime.now().strftime("%H:%M:%S"))
        
        # Chart 1: Blocked IPs Over Time (dummy data for now)
        with chart1_container:
            st.subheader("Recent Blocked IPs")
            
            if not blocked:
                st.info("No IPs currently blocked")
            else:
                # Create a DataFrame from the blocked IPs data
                blocked_df = pd.DataFrame(blocked)
                
                # Show the data as a table
                st.dataframe(blocked_df)
                
                # Create a bar chart of time remaining
                if 'time_remaining' in blocked_df.columns and not blocked_df.empty:
                    fig = px.bar(
                        blocked_df, 
                        x='ip', 
                        y='time_remaining',
                        title="Block Time Remaining (seconds)",
                    )
                    st.plotly_chart(fig, use_container_width=True)
        
        # Chart 2: Attack Types (dummy data for demo)
        with chart2_container:
            st.subheader("Attack Types Detected")
            
            # In a real implementation, you would get this data from your logs or API
            # This is just demo data
            attack_data = {
                "Syn": 45,
                "UDP": 30,
                "LDAP": 15,
                "MSSQL": 5,
                "NetBIOS": 3,
                "Portmap": 2
            }
            
            # Create a DataFrame
            attack_df = pd.DataFrame(list(attack_data.items()), columns=['Attack Type', 'Count'])
            
            # Plot the data
            fig = px.pie(
                attack_df,
                values='Count',
                names='Attack Type',
                title="Distribution of Attack Types",
                hole=0.4
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Only refresh if auto refresh is enabled
        counter += 1
        if auto_refresh:
            time.sleep(refresh_interval)
            st.experimental_rerun()
        else:
            break

elif page == "Blocked IPs":
    st.title("Currently Blocked IPs")
    
    blocked = get_blocked_ips()
    
    if not blocked:
        st.info("No IPs are currently blocked")
    else:
        df = pd.DataFrame(blocked)
        
        # Add an unblock button for each IP
        df['Unblock'] = df['ip'].apply(lambda ip: f"<a href='#' id='unblock-{ip}'>Unblock</a>")
        
        # Display the DataFrame as an interactive table
        st.write(df.to_html(escape=False), unsafe_allow_html=True)
        
        # Handle unblock buttons
        for ip in df['ip']:
            if st.button(f"Unblock {ip}"):
                unblock_ip(ip)
                time.sleep(1)
                st.experimental_rerun()

elif page == "Manual Block":
    st.title("Manually Block IP")
    
    st.warning("Use this feature with caution. Make sure you don't block legitimate traffic.")
    
    ip_to_block = st.text_input("Enter IP address to block")
    
    if st.button("Block IP"):
        if ip_to_block:
            block_ip(ip_to_block)
        else:
            st.error("Please enter an IP address")

elif page == "System Logs":
    st.title("System Logs")
    
    # In a real implementation, you would fetch logs from your service
    # This is just a placeholder
    st.info("Log access not yet implemented. Check the server logs directly.")
    
    # Placeholder for future log display
    st.code("""
    2023-11-01 12:34:56 - WARNING - Potential Syn attack detected from 192.168.1.100 to 10.0.0.1 with 0.95 confidence
    2023-11-01 12:35:02 - WARNING - Potential Syn attack detected from 192.168.1.100 to 10.0.0.1 with 0.96 confidence
    2023-11-01 12:35:12 - WARNING - IP 192.168.1.100 exceeded threshold with 5 attacks. Marked for blocking.
    2023-11-01 12:35:13 - WARNING - Blocked IP 192.168.1.100 for 3600 seconds
    """)

# Add some CSS for styling
st.markdown("""
<style>
.stButton button {
    width: 100%;
}
</style>
""", unsafe_allow_html=True)