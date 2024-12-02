class TCP:
    def __init__(self, transport_payload):
        self.payload_length = len(transport_payload)

        # Extract the source port (2 bytes)
        self.source_port = int.from_bytes(transport_payload[0:2], byteorder='big')

        # Extract the destination port (2 bytes)
        self.destination_port = int.from_bytes(transport_payload[2:4], byteorder='big')

        # Extract the sequence number (4 bytes)
        self.sequence_number = int.from_bytes(transport_payload[4:8], byteorder='big')

        # Extract the acknowledgment number (4 bytes)
        self.acknowledgment_number = int.from_bytes(transport_payload[8:12], byteorder='big')

        # Extract the data offset (4 bits), reserved (3 bits), and flags (9 bits)
        # The data offset is contained in the first 4 bits of the 12th byte.
        # The flags are contained in the last byte of the TCP header.
        header = transport_payload[12:16]
        self.data_offset = (header[0] >> 4)  # First 4 bits of byte 12
        self.flags = header[1]  # Remaining bits (flags) in byte 13

        # Extract the window size (2 bytes)
        self.window_size = int.from_bytes(transport_payload[14:16], byteorder='big')

        # Extract the checksum (2 bytes)
        self.checksum = int.from_bytes(transport_payload[16:18], byteorder='big')

        # Extract the urgent pointer (2 bytes)
        self.urgent_pointer = int.from_bytes(transport_payload[18:20], byteorder='big')

        # The remaining bytes are the data
        self.data = transport_payload[20:]

    def has_options(self):
        """Check if the TCP header has options."""
        return self.data_offset > 5

    def __repr__(self):
        # Provide a string representation for the TCP object
        return (f"TCP(Source Port: {self.source_port}, Destination Port: {self.destination_port}, "
                f"Sequence Number: {self.sequence_number}, Acknowledgment Number: {self.acknowledgment_number}, "
                f"Data Offset: {self.data_offset}, Flags: {self.flags}, Window Size: {self.window_size}, "
                f"Checksum: {self.checksum}, Urgent Pointer: {self.urgent_pointer}, Data: {self.data})")
