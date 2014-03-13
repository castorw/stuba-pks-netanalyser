stuba-pks-netanalyser
=====================

[STUBA/Y2SS/PKS] PKS Network Analyser

This tool should be able to parse tcpdump formatted packet capture PCAP file.
Analyser modules are providing tabs, which use "Frame Parsers" to create requested data constructions.
Analyser modules and Frame parsers are built inside the JAR.

**Analyser modules**
  * Frame Info - provides basic list of frames and their data
  * Basic IPv4 Stats - List of all transmitting nodes + node, that transferred biggest amount of data
  * ICMP - List of all ICMP packets + ICMP types and codes
  * ARP - List of all ARP packets + matching ARP Request/Reply pairs
  * HTTP - List of all HTTP connections and stateless packets
  * HTTPS - List of all HTTPS connections and stateless packets
  * Telnet - List of all Telnet connections and stateless packets
  * SSH - List of all SSH connections and stateless packets
  * FTP - List of all FTP data and control connections and stateless packets
  * TFTP - List of all TFTP packets
  
**Frame Parsers**
  * Ethernet Frame Parser - basic ethernet frame parser
  * ARP Packet Parser
  * IPv4 Packet Parser
  * ICMP Packet Parser
  * UDP Packet Parser
  * TCP Packet Parser

**Connection Analyser**
IPv4ConnectionAnalyser allows collection of IPv4Frame objects and reconstruct TCP connections and contain other state-less traffic.

**Screenshots**
![Frame Info Screenshot](/screenshots/01_frame_info.png?raw=true "1. Frame Info")
![IPv4 Source Stats Screenshot](/screenshots/02_ipv4_source_stats.png?raw=true "2. IPv4 Source Stats")
![ARP Screenshot](/screenshots/03_arp.png?raw=true "3. ARP")
![ICMP Screenshot](/screenshots/04_icmp.png?raw=true "4. ICMP")
![HTTP Screenshot](/screenshots/05_http.png?raw=true "5. HTTP")
![SSH Screenshot](/screenshots/06_ssh.png?raw=true "6. SSH")
![About Dialog Screenshot](/screenshots/10_about.png?raw=true "10. About Dialog")
