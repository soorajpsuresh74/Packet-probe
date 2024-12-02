import csv


class PacketManager:
    def __init__(self):
        self.packet_info = {}

    def set_packet_info(self, packet_info):
        self.packet_info = packet_info

    def save_to_csv(self):
        """Saves the packet information to a CSV file."""
        fieldnames = self.packet_info.keys()
        with open('packet_info.csv', 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write the header only if the file is empty
            if csvfile.tell() == 0:
                writer.writeheader()

            # Write the packet information as a row
            writer.writerow(self.packet_info)
