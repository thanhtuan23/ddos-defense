#!/bin/bash
# install_dependencies.sh

echo "Installing required packages..."
sudo apt-get update
sudo apt-get install -y python3-pip tcpdump iptables python3-dev libpcap-dev

echo "Installing Python libraries..."

python3 -m venv venv
source venv/bin/activate
pip3 install scikit-learn pandas numpy scapy joblib flask netfilterqueue psutil streamlit plotly

echo "Setting up log directory..."
mkdir -p logs

echo "Dependencies installed successfully!"