#!/usr/bin/env python3
import re
import psutil
import socket
import playsound
from time import sleep
from threading import Thread, Event
from datetime import datetime
from pathlib import Path
from random import choices
from string import digits, ascii_lowercase
import subprocess

# ---- Functions ----
def boot_time () -> datetime:

    '''
    Returns a datetime object which contains timestamp information of the last system boot.

    ### Example
    > boot_time().strftime("%d/%m/%Y, %H:%M:%S")
    > 05/02/2025, 11:32:45 # time of last boot.
    '''

    return datetime.fromtimestamp(psutil.boot_time())

def path_clip (path: str, max_length: int) -> str:

    '''
    Cuts a path string readably to allowed max_length.
    '''

    if '\\' in path:
        path_split = path.split('\\')
    else:
        path_split = path.split('/')
    
    output = []
    
def path_rectify (path: str) -> str:

    '''
    Converts all path strings to unix-like path with '/' separators.
    '''

    return'/'.join(str(path).split('\\'))

def play (path: Path) -> None:

    playsound.playsound(path)

def place_trap_file (dir_path: Path) -> str:

    '''
    Places a file in the home directory which contains mocked critical information.
    The dir_path variable selects the directory (as a pathlib.Path object) in which 
    the file will be placed. Returns the final file path as posix string.
    '''

    file_path = dir_path.joinpath('bitcoin_wallet.txt')
    random_address = 'bc1' + ''.join(choices('0123456789abcdefghijklmnopqrstuvwxyz', k=34))
    random_password = ''.join(choices('0123456789abcdefghijklmnopqrstuvwxyz$/!-+', k=10))

    with open(file_path, 'w+') as f:
        f.write(f'wallet keys overview\nLink: https://pbs.twimg.com/media/EDJhNquU4AEaDHT.jpg\naddress: {random_address}\nPassword: {random_password}')

    return file_path.as_posix()

def log (*input, 
         header: str|None=None, 
         mode: str='info', 
         symbol: str|None=None, 
         separator: str=', ',
         log_path: str|Path|None=None,
         print_to_console: bool=True) -> str:

    # determine log color
    mode = mode.lower()
    if symbol:
        sym = symbol
    elif mode in 'error':
        sym = '🛑'
    elif mode in 'warning':
        sym = '⚠️'
    elif mode in 'success':
        sym = '✅'
    else:
        sym = '🔔'
    
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    joined_inputs = separator.join(input)
    vanilla_str = f'[{timestamp}][{header}]      {joined_inputs}'
    stdout_str = f'{sym}  {vanilla_str}'

    # print to console if enabled
    if print_to_console:
        print(stdout_str)

    # check wether to log stdout to file
    if log_path:
        log_str = f'[{timestamp}][{header}]   {joined_inputs}'
        if not type(log_path) is Path:
            log_path = Path(log_path)
        with open(log_path, 'a+') as f:
            f.write(log_str + '\n')

    return vanilla_str

def timestamp () -> float:

    return datetime.now().timestamp()

def timestamp_to_string (timestamp: float) -> str:

    return datetime.fromtimestamp(timestamp).strftime("%d/%m/%Y %H:%M")

# ---- network ----
class NetworkScanner:

    '''
    A private network scanner which scans all sub addresses in the 
    local host's subnet address range, and updates the instance ips list. 
    '''

    def __init__(self):

        # Parameters
        self.timeout = 50
        self.count = 4

        self.ips: list[str] = []
        
        # Determine the host and subnet part
        self.host: str = get_host_ip()
        self.subnet: str = '.'.join(self.host.split('.')[:3])
    
    def __call__(self, num_start: int=0, num_stop: int=255) -> list[str]:

        '''
        Alias for scan_range.
        '''

        return self.scan_range(num_start, num_stop)

    def scan_range (self, num_start: int=0, num_stop: int=255) -> list[str]:

        '''
        An accelerated ip scanning algorithm. 
        Scans all sub addresses concurrently, within the local hosts subnet address range,
        and overrides the instance ips list. 
        Example: if the host is 192.168.178.24 -> 192.168.178 will be the subnet.
        The scan will run in a range 192.168.178.num_start - 192.168.178.num_stop.

        [Return]
        
        Returns the ips list.
        '''

        pings = {}

        for num in range(num_start, num_stop):

            ip = f'{self.subnet}.{num}'
            process = subprocess.Popen(['ping', '-n', str(self.count), '-w', str(self.timeout), ip], 
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
            pings[ip] = process
        
        # Wait for all processes to complete and collect their output
        active_ips = []
        for ip, process in pings.items():
            process.wait()  # Wait for the process to complete
            # denote ip on ping success
            if process.returncode == 0:
                active_ips.append(ip)
        
        # Override the ips object
        self.ips = active_ips

        return active_ips
    
def show_all_interfaces () -> None:
    interfaces = psutil.net_if_addrs()
    for if_name, interface_addresses in interfaces.items():
        print(f'Interface "{if_name}"')
        for address in interface_addresses:
            print('\t', 'address:', address.address)
            print('\t', 'netmask:', address.netmask)
            print('\t', 'AF', address.family, '\n')

def get_host_ip () -> str:

    return socket.gethostbyname(socket.gethostname())

def get_mac(ip) -> str|None:

    '''
    Returns the MAC address for provided IP.
    '''

    try:

        # Execute the arp command
        output = subprocess.check_output(['arp', '-a', ip]).decode('utf-8')

        # Use regex to find the MAC address, group to a string and transform to MAC standard.
        mac_address = ':'.join( (re.search(r'([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2}', output).group()).split('-') )

        return mac_address
    
    except Exception as e:

        return

def get_subnet_mask (local_ip: str) -> str:
    
    '''
    Determines the subnet mask for given local ip.
    '''

    interfaces = psutil.net_if_addrs()
    for interface_addresses in interfaces.values():
        for address in interface_addresses:
            if address.address == local_ip:
                return address.netmask

def get_local_ips () -> list[str]:

    '''
    Returns all local ips in provided subnet.
    Alias for NetworkScanner().scan_range().
    '''

    return NetworkScanner().scan_range()


# Detect function using regex patterns
# Define regex patterns
ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b"
# Updated file path pattern supporting both Windows and Unix paths
path_pattern = r"^(?:[A-Za-z][\\/]|/)[^\0]+([\\/][^\0]+)*$"

def detect_pattern (string: str) -> str:

    if re.match(ipv4_pattern, string):
        return "IPv4"
    elif re.match(ipv6_pattern, string):
        return "IPv6"
    elif re.match(path_pattern, string):
        return "Posix"
    else:
        return "Text"

# ---- Objects ----
class thread (Thread):

    '''
    [MODULE]

    The activity of this thread is bound to the termination state of the controller.
    '''

    def __init__ (self, function, wait, *args):

        self.wait = wait
        Thread.__init__(self)
        self.func = function
        self.args = args
        self.stop_request = Event()

    def run (self, freq=10, repeat=True):

        while not self.stop_request.isSet():
            try: # important during init, otherwise crash
                self.func(*self.args)
                if not repeat:
                    return
                # listen frequently during waiting
                for _ in range(freq * self.wait):
                    if self.stop_request.isSet():
                        break
                    sleep(1/freq)
            except:
                pass

    def stop (self, timeout = None):

        self.stop_request.set()
        super(thread, self).join(timeout)