stuba-pks-netanalyser
=====================

[STUBA/Y2SS/PKS] PKS Network Analyser

This tool should be able to parse tcpdump formatted packet capture PCAP file.
Analyser modules are providing tabs, which use "Frame Parsers" to create requested data constructions.
Analyser modules and Frame parsers are built inside the JAR.

Analyser modules:
  * Frame Info - provides basic list of frames and their data
  * Basic IPv4 Stats - List of all transmitting nodes + node, that transferred biggest amount of data
  * ICMP - List of all ICMP packets + ICMP types and codes
  * ARP - List of all ARP packets + matching ARP Request/Reply pairs
  
Frame Parsers:
  * Ethernet Frame Parser - basic ethernet frame parser
  * ARP Packet Parser
  * IPv4 Packet Parser
  * ICMP Packet Parser
  * UDP Packet Parser
  * TCP Packet Parser

**Screenshots**
![Frame Info Screenshot](/screenshots/01_frame_info.png "1. Frame Info")
![IPv4 Source Stats Screenshot](/screenshots/02_ipv4_source_stats.png "2. IPv4 Source Stats")
![ARP Screenshot](/screenshots/03_arp.png "3. ARP")
![ICMP Screenshot](/screenshots/04_icmp.png "4. ICMP")
![About Dialog Screenshot](/screenshots/10_about.png "10. About Dialog")
