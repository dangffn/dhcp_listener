#!/usr/bin/python
import socket, sys


# turn this on to show more info
VERBOSE = False


class Utils:

    @staticmethod
    def hexify(s):
        # convert string to hex
        return "".join([hex(ord(i))[2:].zfill(2) for i in s])

    @staticmethod
    def convert_ip(s):
        return ".".join([str(ord(i)) for i in s])

    @staticmethod
    def convert_mac(s):
        return ":".join([hex(ord(i))[2:].zfill(2) for i in s])


class Packet:

    ##
    #
    # decode a DHCP related UDP packet and get the important info
    #
    ##
    #
    # see DHCP info
    # https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
    #
    # see DHCP Option codes and values
    # https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
    #
    ##

    # DHCP message types
    DHCP_MESSAGE_TYPES = {
        1 : "DHCPDISCOVER",
        2 : "DHCPOFFER",
        3 : "DHCPREQUEST",
        4 : "DHCPDECLINE",
        5 : "DHCPACK",
        6 : "DHCPNAK",
        7 : "DHCPRELEASE",
        8 : "DHCPINFORM",
        9 : "DHCPFORCERENEW",
        10 : "DHCPLEASEQUERY",
        11 : "DHCPLEASEUNASSIGNED",
        12 : "DHCPLEASEUNKNOWN",
        13 : "DHCPLEASEACTIVE",
        14 : "DHCPBULKLEASEQUERY",
        15 : "DHCPLEASEQUERYDONE",
        16 : "DHCPACTIVELEASEQUERY",
        17 : "DHCPLEASEQUERYSTATUS",
        18 : "DHCPTLS"
    }

    # DHCP option codes
    DHCP_OP_HOSTNAME = 12
    DHCP_OP_REQIP = 50
    DHCP_OP_MESSAGETYPE = 53
    DHCP_OP_CLIENTMAC = 61

    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.index = 0
        self.skip(236) # disregard the first 236 bytes of the packet
        self.skip(4) # disregard the "magic cookie"
        self.options = {}

        #
        # read each of the dhcp options in the packet and add to the dict
        # dhcp options are formatted:
        # [1 byte DHCP option tag] [1 byte (N) number of following value bytes] [(N) bytes value data]
        # byte of 0xFF terminates the entire packet
        #
        while self.hasnext(): # read each of the dhcp options in the packet
            key = ord(self.next(1)) # 1 byte for the key
            if key == 0xFF: # terminating byte 0xFF == 255
                break
            length = ord(self.next(1)) # 1 byte for the length
            data = self.next(length) # (length) bytes for the value
            self.options.update({ key : data })

    def hasnext(self):
        return self.index < len(self.raw_data)

    def skip(self, n):
        self.index += n

    def next(self, n):
        s = self.raw_data[self.index:self.index+n]
        self.index += n
        return s

    def dump(self):
        for key in self.options.keys():
            h_val = Utils.hexify(self.options[key])
            print("[VERBOSE] Option:%s  Hex_Value:%s  Value:%s" % (key, h_val, self.options[key]))

    def __str__(self): # value returned when you cast a Packet object to str  ex. str(Packet())
        type_value = ord(self.options.get(self.DHCP_OP_MESSAGETYPE))
        packet_type = self.DHCP_MESSAGE_TYPES.get(type_value)
        s = ("%s Packet([%d bytes long with %d options]" % (packet_type, len(self.raw_data), len(self.options.keys())))
        for op in self.options.keys():

            # option code for clientid (mac address)
            if op == self.DHCP_OP_CLIENTMAC:
                s += " Requester's MAC: %s" % Utils.convert_mac(self.options[op][1:])

            # option code for requested ip from the client machine
            if op == self.DHCP_OP_REQIP:
                s += " Requested IP: %s" % Utils.convert_ip(self.options[op])

            # option code for hostname of client machine
            if op == self.DHCP_OP_HOSTNAME:
                s += " Requester's Hostname: %s" % str(self.options[op])

        s += ")"

        return s


def run_server():

    # create a network socket that listens for UDP traffic on port 67 (DHCP port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("",67))

    # main program loop
    while True:

        # wait until bytes are received on the socket
        try:
            message, addr = s.recvfrom(1024)
        except:
            print("Socket closed, goodbye!")
            sys.exit(0)

        # convert the raw data received to a Packet object
        packet = Packet(message)

        # print nice clean formatted string from __str__() method in Packet()
        print(str(packet))

        # show all the "DHCP Options" received from the DHCP packet
        if VERBOSE:
            packet.dump()
            print


if __name__ == "__main__": # only run if this script is started directly, and not if this script is imported into another file
    run_server()
