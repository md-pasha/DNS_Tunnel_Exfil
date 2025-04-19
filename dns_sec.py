from scapy.all import PcapReader,DNS,DNSQR,UDP
import tldextract

def get_dnsquery(packets):
     for pkt in packets:
          dns_qry = pkt[DNS][DNSQR].qname.decode()
          qry_names.append(dns_qry)

def data_exfil(domain_list):
    bytes = 0
    for domain,subdomain in domain_list.items():
        qry_len = sum(len(qry) for qry in subdomain)
        bytes += qry_len
        print(f'{domain} - {bytes} Bytes exfilterated')
    return bytes

def build_domains(qry_names):
    for qry_name  in qry_names:
        ext = tldextract.extract(qry_name)
        subdomain = ext.subdomain
        domain = ext.domain
        if domain not in domain_dict:
             domain_dict[domain] = set() # This is telling create a set data type for the dirctionary values where domain will act as dictionary key 
        if subdomain:
             domain_dict[domain].add(subdomain)

def dns_c2(domain_list):
    for domain in domain_list:
        if len(domain_list[domain]) > 20:
            print(f'{domain}  - Hidden DNS Tunnel')
        else:
            print(f'{domain} - Looks Good')

packets = list()
qry_names = list()
domains = set()
subdomains = list()
domain_dict = {}
def main():
    pcap = PcapReader('dnstest.pcap')
    for pkt in pcap:
        if 'DNS' in pkt and pkt[DNS].qr == 0:
            packets.append(pkt)

    get_dnsquery(packets)
    build_domains(qry_names)
    #print(domain_dict)
    data_exfil(domain_dict)     
    dns_c2(domain_dict)

if __name__ == "__main__":
     main()

