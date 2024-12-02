import ctypes
import os
from abc import abstractmethod, ABC


"""
    PCAPInterfaces - Abstract Base Class for Network Interface Management with PCAP Support
    
    This module defines classes that facilitate the management and selection of network 
    interfaces, as well as packet capture using the PCAP library. It provides an abstract 
    base class for initializing PCAP-related structures, function prototypes, and error handling.
    
    Classes:
        Interfaces (ABC): An abstract base class with a prototype for interface selection.
        PCAPInterfaces (ABC): An abstract base class for managing network interfaces and 
                              initializing PCAP function prototypes and structures.
    
    Key Components:
        - PCAP_ERRBUF_SIZE: Size of the error buffer for PCAP functions.
        - PCAP_OPENFLAG_PROMISCUOUS: Flag for opening network interfaces in promiscuous mode.
        - ctypes.Structure: Used for defining C-style structures needed by PCAP functions.
        - Function Prototypes: pcap_findalldevs, pcap_open_live, pcap_next_ex for interacting with PCAP library.
    
    Attributes:
        PcapT: Structure representing a PCAP capture session.
        PcapIfT: Structure representing network interface information.
        PcapPkthdr: Structure representing packet header information.
    
    Initialization:
        The PCAPInterfaces class loads the PCAP library and verifies the presence of required DLLs.
        Function prototypes are defined for PCAP library interaction.
    
    Usage:
        Subclass PCAPInterfaces to implement interface selection and packet capture methods.
"""


class Interfaces:
    @abstractmethod
    def interface_selection(self) -> str:  # prototyping
        pass


class PCAPInterfaces(ABC):
    @abstractmethod
    def __init__(self):
        # Constants
        self.PCAP_ERRBUF_SIZE = 256
        self.PCAP_OPENFLAG_PROMISCUOUS = 1

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

        self.PcapT = PcapT
        self.PcapIfT = PcapIfT
        self.PcapPkthdr = PcapPkthdr

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

    @abstractmethod
    def interfaces_selection(self) -> str:
        pass

    @abstractmethod
    def start_packet_capture(self):
        pass
