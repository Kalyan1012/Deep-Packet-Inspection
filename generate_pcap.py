from scapy.all import *

def create_pcap():
    packets = []

    # Fake "web traffic" (real TCP/IP packets)
    packets.append(
        IP(dst="142.250.190.78")/TCP(dport=443)/b"GET /youtube"
    )

    packets.append(
        IP(dst="140.82.112.4")/TCP(dport=443)/b"GET /github"
    )

    packets.append(
        IP(dst="157.240.221.35")/TCP(dport=443)/b"GET /facebook"
    )

    packets.append(
        IP(dst="142.250.190.78")/TCP(dport=443)/b"search google"
    )

    # Write REAL PCAP file
    wrpcap("test.pcap", packets)

    print("[+] Real PCAP created using Scapy: test.pcap")


if __name__ == "__main__":
    create_pcap()
