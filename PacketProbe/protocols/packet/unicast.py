class MPLSUnicast:
    def __init__(self, payload):
        """
        Initialize an MPLSUnicast object with the provided raw payload data.

        :param payload: bytes representing the raw MPLS unicast packet data.
        """
        if len(payload) < 4:
            raise ValueError("Invalid MPLS packet: MPLS header must be at least 4 bytes")

        # The MPLS header is 4 bytes (32 bits)
        mpls_header = int.from_bytes(payload[:4], byteorder='big')

        # Extract MPLS fields
        self.label = (mpls_header >> 12) & 0xFFFFF  # 20 bits for Label
        self.experimental = (mpls_header >> 9) & 0x7  # 3 bits for Experimental
        self.bottom_of_stack = (mpls_header >> 8) & 0x1  # 1 bit for Bottom of Stack
        self.ttl = mpls_header & 0xFF  # 8 bits for TTL

    def __str__(self):
        """Return a string representation of the MPLS Unicast packet."""
        return (
            f"MPLS Unicast Packet:\n"
            f"  Label: {self.label}\n"
            f"  Experimental: {self.experimental}\n"
            f"  Bottom of Stack: {self.bottom_of_stack}\n"
            f"  TTL: {self.ttl}\n"
        )

