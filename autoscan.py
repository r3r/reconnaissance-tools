"""
    Title: Automatic Vulnerability Scanner - Command Line tool
    Description: Pings all IPs in current network then uses scanner.py to test for open vulnerabilities
    Usage: python autoscan.py -h   #for help using the tool
"""

__author__ = 'Team: Troy'
import argparse
import ipaddress
import subprocess
from scanner import Driver

def cli():
    """CLI Interface
    """

    p = argparse.ArgumentParser()
    p.add_argument("-IP", help="IP address of the current machine", default="127.0.0.1", type=str)
    p.add_argument("-s", "-subnet", help="network bits for current network", default=24, type=int)
    p.add_argument("-P", help="List of Ports to test", default=80,type=int, nargs="+")

    env  = p.parse_args()
    if type(env.P) != type([]):
        env.P = [env.P]
    driver = Driver(env.P)
    get_nodes_alive(env.IP, env.s, driver)


def get_nodes_alive(ipadd, net_bits, driver):
    network_ip = ipadd + "/" + str(net_bits)
    net = ipaddress.ip_network(network_ip, strict=False)
    num_nodes = (1 << (32 - net_bits) ) - 1
    alive = []
    for i in xrange(1, num_nodes):
        t = ping(str(net[i]))
        if t == 0:
            #print "[] Testing Ports on!: " + str(net[i])
            alive.append(str(net[i]))
            driver.add_ip(str(net[i]))
    return alive

def ping(ip):
    import platform
    arch = platform.architecture()[1]
    #print "[] pinging : " + ip
    if "Windows" in arch:
        output = subprocess.Popen("ping -n 1 "+ ip,stdout = subprocess.PIPE).communicate()[0]
    else:
        output = subprocess.Popen("ping -c 1 "+ ip,stdout = subprocess.PIPE).communicate()[0]
    if 'unreachable' in output:
        return 1
    else:
        return 0


if __name__ == "__main__":
    cli()
