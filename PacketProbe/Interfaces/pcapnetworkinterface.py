import ctypes
from abc import ABC

from PacketProbe.Interfaces.interface import PCAPInterfaces


class PCAP(PCAPInterfaces, ABC):
    """
        PCAP - Class for Network Interface Selection Using PCAP Library

        This module provides a class that extends the PCAPInterfaces base class to enable
        the selection and display of network interfaces using the PCAP library. It allows
        users to choose a network interface for packet capture and provides relevant
        descriptions for each interface.

        Class:
            PCAP(PCAPInterfaces, ABC): Inherits from PCAPInterfaces and provides a concrete
                                       implementation for selecting network interfaces.

        Methods:
            __init__(): Initializes the PCAP instance, sets up the selected interface.
            interfaces_selection(): Lists all available network interfaces, allows user selection,
                                    and returns the chosen interface.

        Attributes:
            interface_selected (str): The name of the interface selected by the user.
            interfaces (list): A list of available network interfaces populated during interface
                               discovery.

        Details:
            - Uses ctypes to interact with PCAP library functions for finding and displaying
              network interfaces.
            - Prompts the user to choose an interface based on displayed IDs, validates the input,
              and sets the selected interface.
            - Handles errors related to device finding and user input.

        Usage:
            Instantiate the PCAP class and call the `interfaces_selection()` method to display
            and select a network interface for packet capture.
    """
    def __init__(self):
        super().__init__()
        self.interface_selected = None

    def interfaces_selection(self):
        alldevs = ctypes.POINTER(self.PcapIfT)()
        errbuf = ctypes.create_string_buffer(self.PCAP_ERRBUF_SIZE)

        result = self.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
        if result != 0 or not alldevs:
            print("Error finding devices:", errbuf.value.decode())
            return

        # Print available interfaces
        dev = alldevs
        i = 0
        while dev:
            name = dev.contents.name.decode()
            description = dev.contents.description.decode() if dev.contents.description else "No description"
            print(f"Interface {i}: {name} - {description}")
            self.interfaces.append(name)
            dev = dev.contents.next
            i += 1

        # Allow the user to choose an interface
        try:
            interface_id = int(input("Enter the interface ID: "))
            if 0 <= interface_id < len(self.interfaces):
                selected_interface = self.interfaces[interface_id]
                print(f"Selected interface: {selected_interface}")
                self.interface_selected = selected_interface
                return self.interface_selected
            else:
                print("Invalid interface ID.")
                return
        except ValueError:
            print("Invalid input. Please enter a number.")

