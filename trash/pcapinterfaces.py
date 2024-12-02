import ctypes
import os
import threading
from abc import ABC

from PacketProbe.Interfaces.interface import Interfaces


class PcapCapture(Interfaces, ABC):
    # Constants
    PCAP_ERRBUF_SIZE = 256
    PCAP_OPENFLAG_PROMISCUOUS = 1

    class PcapT(ctypes.Structure):
        pass

    class PcapIfT(ctypes.Structure):
        pass

    PcapIfT._fields_ = [
        ("next", ctypes.POINTER(PcapIfT)),
        ("name", ctypes.c_char_p),
        ("description", ctypes.c_char_p),
        ("addresses", ctypes.c_void_p),
        ("flags", ctypes.c_uint)
    ]

    class PcapPkthdr(ctypes.Structure):
        _fields_ = [
            ("ts", ctypes.c_long * 2),
            ("caplen", ctypes.c_uint),
            ("len", ctypes.c_uint)
        ]

    def __init__(self):
        # Initialize directories and load wpcap
        self.interface_id = None
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.parent_dir = os.path.dirname(self.current_dir)
        self.child_dir = os.path.join(self.parent_dir, 'utils')
        self.wpcap_directory = os.path.join(self.child_dir, r'wpcap/wpcap.dll')

        if not os.path.exists(self.wpcap_directory):
            raise FileNotFoundError(f"{self.wpcap_directory} not found.")
        self.wpcap = ctypes.WinDLL(self.wpcap_directory)

        # Define function prototypes
        self.pcap_findalldevs = self.wpcap.pcap_findalldevs
        self.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(self.PcapIfT)), ctypes.POINTER(ctypes.c_char)]
        self.pcap_findalldevs.restype = ctypes.c_int

        self.pcap_open_live = self.wpcap.pcap_open_live
        self.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                        ctypes.POINTER(ctypes.c_char)]
        self.pcap_open_live.restype = ctypes.POINTER(self.PcapT)

        self.pcap_next_ex = self.wpcap.pcap_next_ex
        self.pcap_next_ex.argtypes = [ctypes.POINTER(self.PcapT), ctypes.POINTER(ctypes.POINTER(self.PcapPkthdr)),
                                      ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        self.pcap_next_ex.restype = ctypes.c_int

        # Initialize interface list
        self.interfaces = []

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
                self.start_packet_capture(selected_interface)
            else:
                print("Invalid interface ID.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    def start_packet_capture(self, interface: str):
        errbuf = ctypes.create_string_buffer(self.PCAP_ERRBUF_SIZE)
        handle = self.pcap_open_live(interface.encode(), 65536, self.PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)
        if not handle:
            print("Failed to open interface:", errbuf.value.decode())
            return

        print(f"Listening on {interface} ... Press Ctrl+C to stop.")

        def capture_loop():
            packet_header = ctypes.POINTER(self.PcapPkthdr)()
            packet_data = ctypes.POINTER(ctypes.c_ubyte)()
            try:
                while True:
                    result = self.pcap_next_ex(handle, ctypes.byref(packet_header), ctypes.byref(packet_data))
                    if result == 1:  # Successful capture
                        raw_data = ctypes.string_at(packet_data, packet_header.contents.caplen)
                        print(f"Captured packet of length {packet_header.contents.caplen}")
                    elif result == 0:  # Timeout
                        continue
                    elif result == -1:  # Error
                        print("Error capturing packet")
                        break
            except KeyboardInterrupt:
                print("\nStopping packet capture.")

        capture_thread = threading.Thread(target=capture_loop, daemon=True)
        capture_thread.start()


if __name__ == "__main__":
    pcap = PcapCapture()
    print(pcap.interfaces_selection())
