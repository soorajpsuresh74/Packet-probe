class ARP:
    """
    Arp is communication mechanism coverts the IP address in to MAC address
    A class for parsing and representing an ARP (Address Resolution Protocol) packet header.

    This class extracts fields from an ARP packet header based on the provided
    packet payload. It provides methods to access various attributes of the
    ARP header and represents the information in a readable format.

    Attributes
    ----------
    hardware_type : int
        Specifies the type of hardware address (e.g., Ethernet is 1).
    protocol_type : int
        Specifies the type of protocol address (e.g., IPv4 is 0x0800).
    hardware_length : int
        Length of the hardware address.
    protocol_length : int
        Length of the protocol address.
    opcode : int
        Specifies the operation (1 for request, 2 for reply).
    sender_mac : bytes
        The MAC address of the sender (6 bytes).
    receiver_mac : bytes
        The MAC address of the receiver (6 bytes).
    sender_ip : bytes
        The IP address of the sender (4 bytes).
    receiver_ip : bytes
        The IP address of the receiver (4 bytes).
    payload_length : int
        The length of the payload (the entire packet payload).

    Parameters
    ----------
    payload : bytes
        The raw bytes representing the entire packet containing the ARP packet.

    Raises
    ------
    ValueError
        If the provided packet payload is shorter than the minimum length required
        for an ARP header (28 bytes).

    Methods
    -------
    __str__():
        Returns a string representation of the parsed ARP header fields, formatted for readability.
    """

    def __init__(self, payload):
        self.payload_length = len(payload)
        if self.payload_length < 28:
            raise ValueError("Payload does not have the minimum length")

        self.hardware_type = int.from_bytes(payload[0:2], 'big')
        self.protocol_type = int.from_bytes(payload[2:4], 'big')
        self.hardware_length = payload[4]
        self.protocol_length = payload[5]
        self.opcode = int.from_bytes(payload[6:8], 'big')
        self.sender_mac = payload[8:14]  # MAC is 6 bytes
        self.sender_ip = payload[14:18]  # IP is 4 bytes
        self.receiver_mac = payload[18:24]  # Target MAC is 6 bytes
        self.receiver_ip = payload[24:28]  # Target IP is 4 bytes

    def __str__(self) -> str:
        sender_mac = ":".join(f"{byte:02x}" for byte in self.sender_mac)
        target_mac = ":".join(f"{byte:02x}" for byte in self.receiver_mac)
        sender_ip = ".".join(str(byte) for byte in self.sender_ip)
        target_ip = ".".join(str(byte) for byte in self.receiver_ip)
        return (f"ARP("
                f"hardware_type={self.hardware_type}, "
                f"protocol_type={self.protocol_type}, "
                f"hardware_size={self.hardware_length}, "
                f"protocol_size={self.protocol_length}, "
                f"opcode={self.opcode}, "
                f"sender_mac={sender_mac}, "
                f"sender_ip={sender_ip}, "
                f"target_mac={target_mac}, "
                f"target_ip={target_ip})")
