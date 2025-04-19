# DNS_Tunnel_Exfil

The Script will help identify DNS tunnel attempts to any domains and indicates the amount of exfilterated data in bytes. The script reads from a PCAP file and extracts DNS trffic using scapy module. Currently we need to have the pcap file in the same directory where the script will be strored and also needs to have the pcap file name modified at line 40 of the code.
