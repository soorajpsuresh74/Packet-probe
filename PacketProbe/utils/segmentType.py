def determine_protocol_type(bytes_data: bytes) -> str:
    """Determines the protocol type based on the IPv4 protocol field."""
    types = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        50: "ESP",
        51: "AH",
        89: "OSPF",
        132: "SCTP",
        253: "EIGRP",
        254: "IS-IS",
    }
    protocol_number = bytes_data[9]  # The protocol field is at index 9 for IPv4
    return types.get(protocol_number, 'Unknown Protocol')

def determine_protocol_type_ipv6(bytes_data: bytes) -> str:
    """Determines the protocol type based on the IPv6 Next Header field."""
    types = {
        0: "Hop-by-Hop Options",
        1: "ICMPv4",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        43: "Routing Header",
        44: "Fragment Header",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        59: "No Next Header",
        60: "Destination Options",
        135: "Mobility Header",
        139: "Host Identity Protocol",
        140: "Shim6 Protocol",
        253: "Experimentation/Testing",
        254: "Experimentation/Testing"
    }
    next_header = bytes_data[6]  # The Next Header field is at index 6 for IPv6
    return types.get(next_header, 'Unknown Protocol')