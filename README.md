# IT 359 Final Project: Network Enumeration & Basic Vulnerability Explanation Tool

## Video Demo
https://youtu.be/5Wb1tORQB-U 

## Team
London Morris
Ninel Benitez  

## Project Purpose

The purpose of this project is to develop a Python-based tool that scans a system for open ports and explains the associated security risks in a clear and simple way. The tool is designed to help beginners understand how exposed services can create vulnerabilities in a system.

This project also simulates how a banking or high-security environment might be evaluated for potential risks.

## Features

- Scans common ports (21, 22, 23, 80, 443, 445, 3389)  
- Identifies open ports using TCP connections  
- Provides explanations of each service  
- Performs basic risk analysis (Low, Medium, High, Critical)  
- Generates a report file (`scan_report.txt`)  

## AI-Inspired Risk Analysis

The tool includes a simple rule-based analysis that evaluates combinations of open ports and assigns a risk level. For example:

- Web services exposed to the internet result in a medium risk classification  
- SMB exposure results in a high risk classification  
- Multiple remote access services increase overall risk  

This approach helps translate technical results into meaningful security insights.

## Requirements

- Python 3  
- Standard libraries only (`socket`, `sys`)  

No additional installations are required.

## Setup and Execution

1. Clone or download the repository  
2. Open a terminal  
3. Navigate to the project folder  
4. Run the program:

```bash
python3 simple_network_scanner.py

## Example Usage

Enter target (IP or domain): scanme.nmap.org

Example output:

Port 22 OPEN → SSH – Remote access (secure but risky if exposed)
Port 80 OPEN → HTTP – Web traffic (not encrypted)

=== BANKING SYSTEM RISK ANALYSIS ===
Overall Risk Level: MEDIUM
Reason: Web services exposed to the internet
