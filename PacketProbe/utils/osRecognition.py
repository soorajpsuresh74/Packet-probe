import os

support = ['nt', 'posix']  # supported OS types


def find_os():
    current_os = None

    if os.name in support:
        current_os = os.name.lower()
        if current_os == 'nt':
            print("Using pcap for Windows.")
        elif current_os == 'posix':
            print("Using socket for Unix-like systems.")

    else:
        print("Unsupported OS type.")
    return current_os
