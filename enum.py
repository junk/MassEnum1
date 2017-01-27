#!/usr/bin/env python
# deze shit gaat gewoon enum4linux doen, alles naar .txt's, daarna greppen en zoeken en ordenen.

# benodigde modules importeren
import logging
import random
import threading
import time
import os
from netaddr import IPNetwork
import sys


class ActivePool(object):
    def __init__(self):
        super(ActivePool, self).__init__()
        self.active = []
        self.lock = threading.Lock()
    def makeActive(self, name):
        with self.lock:
            self.active.append(name)
            #            logging.debug('Running: %s', self.active)
    def makeInactive(self, name):
        with self.lock:
            self.active.remove(name)


def worker(s, pool, ip):
    #    logging.debug('Waiting to join the pool')
    with s:
        name = threading.currentThread().getName()
        pool.makeActive(name)
        # 	print count
        print "[+] Running enum4linux on " + ip
        os.system("enum4linux " + ip + " > $(echo '" + ip + "' | cut -d ' ' -f4).txt")
        pool.makeInactive(name)


def usage():
    print("[+]-------------------------------------------------[+]")
    print("[+] Welcome to massEnum")
    print("[+] Usage: enum.py range/file [threads]")
    print("[+] Range can given as a subnet e.g. 192.168.1.0/24")
    print("[+] Or give a path to a file containing IP's")
    print("[+] Example: enum.py hosts 10")
    print("[+]-------------------------------------------------[+]")
    exit()


def information_gathering():
    print("[+] Extracting users (method 1)")
    os.system('cat *txt | grep "user:" | cut -d "[" -f2 | cut -d "]" -f1 | sort -u > users.txt')
    print("[+] User extracted, saved as users.txt")
    print("[+] Finding domain(s)")
    os.system("cat *txt | grep 'has member' | cut -d ':' -f3 | grep '\\\\' |  cut -d '\\' -f1 |sort -u | sed 's/ //g' > domain.txt")
    print("[+] Domain(s) saved as domain.txt")
    print("[+] Saving users (method2)")
    os.system("cat *txt | grep 'has member' | cut -d ':' -f3 | grep '\\\\' |sort -u | sed 's/ //g' > users2.txt")
    print("[+] Users saved as users2.txt")


def main():
    print("[+]-------------------------------------------------[+]")
    print("[+] Welcome to massEnum")
    print("[+] ")
    print("[+] Checking ips and threads")
    print("[+] ")

    ips = []
    try:
        for ip in IPNetwork(sys.argv[1]):
            ips.append(ip)
    except:
        print("[+] ")
        print("[+] No IPrange detected...")
        print("[+] Checking if instead a file was specified")
        try:
            file = open(sys.argv[1], "r")
            print("[+] ")
            print("[+] File detected...")
            print("[+] Creating list...")
            for i in file:
                ips.append(i)
        except:
            print("[+] ")
            print("[+] IPrange detected....")
            print("[+] ")
            print("[+] Starting scans")
            print("[+] ")

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s (%(threadName)-2s) %(message)s',
                        )

    #print "Ips: ", ips

    pool = ActivePool()
    s = threading.Semaphore(int(sys.argv[2]))  # <-- aantal threads!
    count = 0

    mt = threading.currentThread()

    for i in range(len(ips)):
        ip = str(ips[int(i)]).rstrip()
        t = threading.Thread(target=worker, name=str(i), args=(s, pool, ip))
        t.start()
        time.sleep(1)

    for t in threading.enumerate():
        if t is mt:
            continue
        t.join()

    print("[+] ")
    print("[+] Enum done...")
    print("[+] Extracting usefull information")
    print("[+] ")
    print("[+] Time for some information-gathering KungFu!")
    print("[+] ")
    information_gathering()
    
    print("[+] Script done.")
    print("[+] Exiting...")
    print("[+]-------------------------------------------------[+]")
    time.sleep(1)



if __name__ == '__main__':
    try:
        arg1 = sys.argv[1]
        arg2 = sys.argv[2]
    except IndexError:
        usage()
    main()
