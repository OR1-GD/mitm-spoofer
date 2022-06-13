from threading import Thread
from scapy.all import *

class packet_sniffer(Thread):
    def __init__(self, timeout=None):
        super(packet_sniffer, self).__init__()
        print("\t[*] initializing sniffer")
        self.queue  = Queue()
        print("\t[+] initializing queue")
        self.timeout = timeout
        if self.timeout != None:
            print(f"\t[+] set timeout to {self.timeout} sec")
        self.devices = []
        print("\t[*] Finished initializing sniffer")

    def PacketHandler(self, pkt):
        """

        :param pkt:
        :return:
        """
        # find if there are any new unique mac
        if pkt.src not in self.devices:
            if not pkt.src == "ff:ff:ff:ff:ff:ff" :
                self.devices.append({"MAC":pkt.src,"IP":""})
        if pkt.dst not in self.devices:
            if not pkt.dst == "ff:ff:ff:ff:ff:ff":
                self.devices.append({"MAC":pkt.dst,"IP":""})

    def run(self):
        print('\t[!] Packet sniffer started')
        sniff(prn=self.PacketHandler, timeout=self.timeout)
        print(f"\t[!] sniffer finished running")
        # Next step: print the amount of packets sniffed
        # print(f"\t[Info] {self.queue} packets sniffed")
        # print(self.queue)

def main():
    print("[Info] Create Test sniffer")
    sniffer = packet_sniffer(10)
    sniffer.daemon = True
    sniffer.start()
    while sniffer.is_alive(): continue


if __name__ == '__main__':
    main()
