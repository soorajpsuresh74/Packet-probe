class RARP:
    """
    Reverse Address Resolution Protocol (RARP) is a networking protocol that is used to map a physical (MAC) address to
    an Internet Protocol (IP) address. It is used to obtain the IP address of a host based on its physical address.
    """

    def __init__(self, payload):
        self.payload_length = len(payload)

        # Check for minimum length
        if self.payload_length < 28:
            raise ValueError("Does not have enough length for RARP packet")

        # Extracting fields from the payload
        self.hardware_address_type = int.from_bytes(payload[0:2], byteorder='big')  # Hardware Type
        self.protocol_type = int.from_bytes(payload[2:4], byteorder='big')  # Protocol Type
        self.hardware_length = payload[4]  # Hardware Address Length
        self.protocol_length = payload[5]  # Protocol Address Length
        self.opcode = int.from_bytes(payload[6:8], byteorder='big')  # Operation Code

        # Extracting addresses
        self.sender_hardware_address = payload[8:14]  # Sender Hardware Address (6 bytes)
        self.sender_protocol_address = payload[14:18]  # Sender Protocol Address (4 bytes)
        self.target_hardware_address = payload[18:24]  # Target Hardware Address (6 bytes)
        self.target_protocol_address = payload[24:28]  # Target Protocol Address (4 bytes)

    def __str__(self):
        return (f"RARP Packet:\n"
                f"Hardware Address Type: {self.hardware_address_type}\n"
                f"Protocol Type: {self.protocol_type}\n"
                f"Hardware Address Length: {self.hardware_length}\n"
                f"Protocol Address Length: {self.protocol_length}\n"
                f"Opcode: {self.opcode}\n"
                f"Sender Hardware Address: {self.sender_hardware_address.hex()}\n"
                f"Sender Protocol Address: {self.sender_protocol_address.hex()}\n"
                f"Target Hardware Address: {self.target_hardware_address.hex()}\n"
                f"Target Protocol Address: {self.target_protocol_address.hex()}")


