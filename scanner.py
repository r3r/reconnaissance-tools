"""
    Title: Vulnerability Scanner - Command Line tool
    Description: Connects using TCP and given request banner(if well known port) to get response from given IP
    Usage: python scanner.py -h   #for help using the tool
"""
__author__ = 'Team TROY'
import threading, socket, argparse

class Scanner(threading.Thread):
    """Vulnerability Scanner
        Has a list of Well-Known Ports and their request strings and response banners for cross referencing
    """
    requests = {80 : "HEAD /hi.php HTTP/1.1\r\n\Host: localhost\r\nAccept: */*\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n",
               22 : "SSH\r\n",
               20 : "FTP\r\n",
               21 : "FTP\r\n",
               443: "HEAD /hi.php HTTP/1.1\r\n\Host: localhost\r\nAccept: */*\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n" }

    response = {80 : lambda x: ''.join([p for p in  x.split('\n') if "Server: " in p]),
                21 : lambda x: ''.join([p for p in x.split("\n")][0]),
                0 : lambda x: x}


    def __init__(self, ip, port):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.ip, self.port))
            self.sock.send(self.get_request(self.port))
            results = self.sock.recv(4096)
            print ('[+] %s:%d open!' % (self.ip, self.port)), self.resolve_banner(self.port, results)
        except:
            print '[-] %s:%d closed' % (self.ip, self.port)

    def get_request(self, port):
        if port in self.requests.keys():
            return self.requests.get(port)
        else:
            return "Unknown Test\r\n"

    def resolve_banner(self, port, response):
        if port in self.response.keys():
            return self.response.get(port)(response)
        else:
            return self.response.get(0)(response)

class Driver():
    ip = []
    ports = None
    threads = []
    def __init__(self, ports, ip = []):
        self.ip.extend(map(lambda x: [x, False], ip))
        self.ports = ports
        self.service()

    def add_ip(self, ip):
        self.ip.append([ip, False])
        self.service()

    def add_port(self, port):
        self.ports.append(port)
        self.set_all_ips(False)
        self.service()


    def service(self):
        pairs = [(x[0],y) for x in self.ip  for y in self.ports if x[1] == False]
        threads = []
        for pair in pairs:
            scanner = Scanner(pair[0], pair[1])
            threads.append(scanner)
            scanner.start()
        self.set_all_ips(True)

    def set_all_ips(self, set_val):
        for i in self.ip:
            i[1] = set_val







def cli():
    """CLI Interface

    """
    p = argparse.ArgumentParser()
    p.add_argument("-H", help="Host Name", default="127.0.0.1", type=str, nargs="+")
    p.add_argument("-P", help="List of Ports", default=80,type=int, nargs="+")
    env  = p.parse_args()
    if type(env.P) != type([]):
        env.P = [env.P]
    if type(env.H) != type([]):
        env.H = [env.H]
    driver = Driver(env.P, env.H)




if __name__ == "__main__":
    cli()


