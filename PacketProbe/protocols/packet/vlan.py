class VLAN:
    __slots__ = ('vlan_id', 'priority', 'de', 'ethertype', 'payload')

    def __init__(self, packet: bytes):
        """Initialize the VLAN object by parsing the VLAN packet."""
        if len(packet) < 4:
            raise ValueError("Packet too short to contain VLAN header")

        # The first two bytes of the VLAN header are reserved and not used in IEEE 802.1Q
        self.de = packet[:2]  # 2 bytes of the reserved field (Drop Eligible Indicator)
        self.priority = (packet[2] & 0b11100000) >> 5  # 3 bits for priority
        self.vlan_id = int.from_bytes(packet[2:4], 'big') & 0x0FFF  # Extract the VLAN ID
        self.ethertype = int.from_bytes(packet[4:6], 'big')  # EtherType field
        self.payload = packet[6:]  # Remaining packet data after the VLAN header

    def __str__(self):
        """Return a string representation of the VLAN packet."""
        return (f"VLAN Packet:\n"
                f"  Priority: {self.priority}\n"
                f"  VLAN ID: {self.vlan_id}\n"
                f"  EtherType: 0x{self.ethertype:04X}\n"
                f"  Payload Length: {len(self.payload)} bytes\n")

