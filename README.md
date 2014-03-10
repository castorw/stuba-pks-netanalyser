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
