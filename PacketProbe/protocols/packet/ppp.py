class PPP:
    def __init__(self, payload):
        """
        Initialize a PPP object with the provided raw data.

        :param payload: bytes representing the raw PPP packet data.
        """
        if len(payload) < 6:  # Minimum PPP packet length (Flag, Address, Control, Protocol, Data, FCS)
            raise ValueError("Payload is too short to be a valid PPP packet.")

        # PPP packet structure
        self.flag = payload[0]         # Expecting 0x7E (Flag)
        self.address = payload[1]      # Usually 0xFF (Broadcast Address)
        self.control = payload[2]      # Usually 0x03 (Unrestricted Control)
        self.protocol = (payload[3] << 8) | payload[4]  # Protocol is 2 bytes
        self.data = payload[5:-2]      # Data (Payload)
        self.FCS = payload[-2:]         # Frame Check Sequence (last 2 bytes)

        self.length = len(self.data)    # Length of the data payload

    def __repr__(self):
        """Return a string representation of the PPP object."""
        return (
            f"PPP(flag={hex(self.flag)}, address={hex(self.address)}, "
            f"control={hex(self.control)}, protocol={hex(self.protocol)}, "
            f"data_length={self.length}, FCS={self.FCS.hex()})"
        )

    @staticmethod
    def is_valid_flag(flag):
        """Check if the flag is valid (PPP uses 0x7E as flag)."""
        return flag == 0x7E

    def get_protocol_name(self):
        """Return a human-readable name for the encapsulated protocol."""
        if self.protocol == 0x0021:
            return "IP"
        elif self.protocol == 0x0057:
            return "IPv6"
        # Add other protocol mappings as needed
        else:
            return "Unknown Protocol"

