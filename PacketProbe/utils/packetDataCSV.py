import csv
import os


def save_packet_to_csv(packet_data, filename):
    """Saves packet data to a CSV file."""
    if not packet_data:
        return  # Skip if packet data is empty

    file = f"PacketProbe/data/{filename}"

    # Check if the file already exists
    file_exists = os.path.isfile(file)

    with open(file, mode='a', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=packet_data.keys())

        # Write the header only if the file is new
        if not file_exists:
            writer.writeheader()

        writer.writerow(packet_data)
