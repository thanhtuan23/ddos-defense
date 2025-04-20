#!/bin/bash
# install_dependencies.sh

echo "Installing required packages..."
sudo apt-get update
sudo apt-get install -y python3-pip tcpdump iptables python3-dev libpcap-dev

echo "Installing Python libraries..."
pip3 install scikit-learn pandas numpy scapy joblib flask netfilterqueue psutil

echo "Setting up log directory..."
mkdir -p logs

echo "Dependencies installed successfully!"