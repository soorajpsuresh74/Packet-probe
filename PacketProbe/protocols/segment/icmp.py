class ICMP:
    def __init__(self, transport_payload):
        self.payload_length = len(transport_payload)

        # Extract the type (1 byte)
        self.type = transport_payload[0]

        # Extract the code (1 byte)
        self.code = transport_payload[1]

        # Extract the checksum (2 bytes)
        self.checksum = int.from_bytes(transport_payload[2:4], byteorder='big')

        # Extract the identifier (2 bytes, for Echo Request/Reply)
        self.identifier = int.from_bytes(transport_payload[4:6], byteorder='big')

        # Extract the sequence number (2 bytes, for Echo Request/Reply)
        self.sequence_number = int.from_bytes(transport_payload[6:8], byteorder='big')

        # The remaining bytes are the data (if any)
        self.data = transport_payload[8:]

    def __repr__(self):
        # Provide a string representation for the ICMP object
        return (f"ICMP(Type: {self.type}, Code: {self.code}, Checksum: {self.checksum}, "
                f"Identifier: {self.identifier}, Sequence Number: {self.sequence_number}, Data: {self.data})")

    def is_echo_request(self):
        """Check if the ICMP packet is an Echo Request (Type 8)."""
        return self.type == 8

    def is_echo_reply(self):
        """Check if the ICMP packet is an Echo Reply (Type 0)."""
        return self.type == 0