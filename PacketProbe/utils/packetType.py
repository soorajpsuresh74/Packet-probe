def determine_packet_type(bytes_data: bytes) -> str:
    """Determines the type of packet based on the Ethernet packet type field."""
    types = {
        '0800': 'IPv4',
        '0806': 'ARP',
        '8035': 'RARP',
        '86DD': 'IPv6',
        '0021': 'PPP',
        '8847': 'MPLS Unicast',
        '8848': 'MPLS Multicast',
        '8100': '802.1Q VLAN',  # VLAN Tag
        '88CC': 'LLDP',
        '888E': 'EAPOL'
    }
    frame_type = bytes_data[12:14].hex()
    return types.get(frame_type, 'Unknown')
