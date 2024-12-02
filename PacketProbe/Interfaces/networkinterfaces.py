import socket
from PacketProbe.Interfaces.interface import Interfaces


class NetworkInterfaces(Interfaces):
    """
    A class to represent and manage network interfaces on the system.

    Attributes:
    ----------
    interfaces : list
        A list of tuples representing the available network interfaces,
        where each tuple contains the index and name of the interface.
    interface_selected : tuple
        The currently selected network interface.

    Methods:
    -------
    interface_selection():
        Prompts the user to select a network interface and updates the
        interface_selected attribute accordingly.

    __str__():
        Returns a string representation of the available interfaces.
    """

    def __init__(self):
        """
        Initializes the NetworkInterfaces instance by retrieving the
        available network interfaces and selecting a default interface.
        """
        self.interfaces = socket.if_nameindex()
        self.interface_selected = None
        # Add the logic for other interfaces in the future
        self.interface = self.interface_selection()

    def interface_selection(self) -> str:
        """
        Prompts the user to select a network interface by entering its
        corresponding ID. Updates the interface_selected attribute with
        the selected interface if the input is valid.
        """
        print("Interfaces\nID\t|\tname")
        for i, interface in enumerate(self.interfaces, start=1):
            print(f"{i}\t:\t{interface}")

        try:
            selected = input("Enter the interface id: ")
            if selected is None:
                self.interface_selected = self.interfaces[1]

            elif 0 < int(selected) <= len(self.interfaces):
                self.interface_selected = self.interfaces[int(selected) - 1]
            else:
                print("Invalid selection")
        except Exception as e:
            print(f"{e}: selecting default {self.interfaces[1]}")

        return self.interface_selected[1]

    def __str__(self):
        """
        Returns a string representation of the available network interfaces.

        Returns:
        -------
        str
            A string listing all available network interfaces.
        """
        return f"Available interfaces : {self.interfaces}"
