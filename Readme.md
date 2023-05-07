Packet Sniffer
This is a simple network sniffer that captures and displays network traffic on a specified interface. 
It uses the scapy library to sniff packets on the network and display information about each packet.

Requirements
To run the network sniffer, you need to have the following software installed on your computer:

Python 3.6 or later
Scapy
You can install Scapy by running the following command:
pip install scapy

Usage
To use the network sniffer, follow these steps:

Open a terminal or command prompt.

Navigate to the directory where you saved the network_sniffer.py file.

Run the following command:
python network_sniffer.py --interface <interface>
Replace <interface> with the name of the network interface you want to use for sniffing. 

You can find the name of your network interface by running the following command:
ifconfig
Look for the interface that is currently connected to the network, such as en0 on macOS or eth0 on Linux.

The packet sniffer will start capturing network traffic on the specified interface. 
You can press Ctrl+C to stop the sniffer and see the summary of captured packets. 
The captured packets will be displayed in the terminal.

Note: Running the network sniffer requires administrative privileges on your computer. 
On Windows, you may need to run the command prompt as an administrator.