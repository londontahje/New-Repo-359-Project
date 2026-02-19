
# IT 359 Final Project: Network Enumeration & Basic Vulnerability Explanation Tool


#video presentation
## *not avalible yet**

## Team
- London 
- Ninel

## Project Purpose
Build a beginner-friendly Python tool that:
- Pings a target to check if it's reachable
- Scans common ports (21, 22, 23, 80, 443, 445, 3389 etc.)
- Explains in simple English what each open port typically means and its risk level

Goal: Help new cybersecurity students understand open ports without complex tools.

## Features
- ICMP ping check
- TCP connect scan on selected common ports
- Plain-text risk explanations (e.g., "Port 23 Telnet: Very High risk – no encryption")

## Dependencies / Requirements
- Python 3 (standard library only: socket, time)
- No pip installs needed!

## Setup & Execution Steps
1. Clone or download this repo
2. Open a terminal/command prompt
3. Navigate to the project folder
4. Run:  
   ```bash
   python src/simple_network_scanner.py
