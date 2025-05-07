#!/usr/bin/env python3
import json
import socket

from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scapy.all import ARP, Ether, srp
from traceback import format_exc, print_exc
from pathlib import Path

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

from utils import *

class FileSystemListener (FileSystemEventHandler):

    '''
    Tracks every movement through the file system via GUI or console, 
    with commands like cd, mkdir, touch, and ls, modify the state of files and or directories. 
    Each modification will be located and logged.
    '''

    def __init__ (self, ignore_paths: list[str]|None=None, verbose: bool=True):
        
        super().__init__()

        self.active = False

        self.root_path = Path(__file__).resolve().parent
        self.log_path = self.root_path.joinpath('logs/files.log')

        self.observer = Observer()

        self.max_path_length = 80

        # cache
        self.track_length = 100
        self.changes = [] # track changes
        self.stdout: list[str] = list()
        self.verbose: bool = verbose
        
        # collect all paths which should be ignored
        with open(self.root_path.joinpath('paths.ignore')) as f:
            ignore_from_file = f.read().split('\n')
            if '' in ignore_from_file:
                ignore_from_file.remove('')
        self.ignore_list = [ 
            self.root_path.joinpath('logs/').as_posix(), 
            self.root_path.joinpath('cache/').as_posix() ] + ignore_from_file
        if ignore_paths:
            self.ignore_list = self.ignore_list + ignore_paths

    def enable (self) -> None:

        '''
        Enables the listener - the thread will stay alive.
        '''

        self.active = True
    
    def disable (self) -> None:

        '''
        Disables the listener to IDLE - this will keep the thread alive.
        '''

        self.active = False

    def ignore (self, path) -> bool:

        '''
        Checks if the provided string path can be ignored by comparing to ignore list.
        '''
        
        for exp in self.ignore_list:
            if exp in path:
                return True
        return False

    def get_logs (self) -> list[str]:

        logs = []
        
        for timestamp, log in self.event_log.items():
            line = timestamp_to_string(timestamp) + '\t' + log
            logs.append(line)
        
        return logs

    def listen (self, path: str) -> None:

        '''
        The listen method utilizes the asynchronicity of the underlying observer method - no separate thread is needed. 
        '''

        self.observer.schedule(self, path, recursive=True)
        self.observer.start()

    def on_modified (self, event):
        
        path = path_rectify(event.src_path)
        self.update_cache_routine(f"File has been modified: {path}", path)    

    def on_created (self, event):

        path = path_rectify(event.src_path)
        self.update_cache_routine(f"File has been created: {path}", path)

    def on_deleted (self, event):

        path = path_rectify(event.src_path)
        self.update_cache_routine(f"File has been deleted: {path}", path)

    def on_moved (self, event) -> None:
        
        path = path_rectify(event.src_path)
        self.update_cache_routine(f"File {event.src_path} has been moved to {event.dest_path}", path)
    
    def trim_cache (self) -> None:

        '''
        Trims the stdout cache to allowed tracking length.
        '''

        if len(self.stdout) > self.track_length:
            self.stdout = self.stdout[-self.track_length:] 

    def update_cache_routine (self, message: str, path: str) -> None:

        '''
        This routine catches all file events for modified, created, deleted or moved files
        and adds the corresponding message and file path to cache and stdout.
        '''

        if not self.active:
            return
        
        if self.ignore(path):
            return
        
        # output to console
        stdout_string = log(message, symbol='📃', header='FileSys', log_path=self.log_path, print_to_console=self.verbose)
        self.stdout.append(stdout_string)

        # add the path to changes cache
        self.changes.append(path)

        # trim the cache back to allowed size
        if len(self.changes) > self.track_length:
            self.changes = self.changes[-self.track_length:]
        
        # trim stdout cache
        self.trim_cache()

    def stop (self) -> None: 

        '''
        Alias for stopping the service thread.
        '''

        self.observer.stop()

class ProcessListener:

    def __init__ (self, ignore_prc: list[str]=[], verbose: bool=True) -> None:

        self.active = False

        self.root_path = Path(__file__).resolve().parent
        self.log_path = self.root_path.joinpath('logs/process.log')

        self.initialized: bool = False
        
        self.id_set: set[int] = set()
        self.names: dict[str, set[int]] = dict()           
        self.processes: dict[int, psutil.Process] = dict()
        self.network_activity: dict[int, dict] = dict()
        self.ignore_prc = [prc.lower() for prc in ignore_prc]

        # track the stdout in cache
        self.track_length = 100
        self.stdout: list[str] = list()
        self.verbose: bool = verbose

        # update the processes once
        self.update_processes()
        self.initialized = True

        # setup a listen thread which can be enabled/disabled
        self.listen_thread = thread(self.listener_loop, .1)
    
    def enable (self) -> None:

        '''
        Enables the listener - the thread will stay alive.
        '''

        self.active = True
    
    def disable (self) -> None:

        '''
        Disables the listener to IDLE - this will keep the thread alive.
        '''

        self.active = False

    def get_name (self, id: int) -> str:

        return self.processes[id].info['name']

    def kill_app (self, identifier: str) -> None:

        '''
        identifier :        The sub string which should be included in process names.
                            Every process including the identifier in their name will be deleted.
        '''

        log(f'kill application "{identifier}" ...', header='kill')
        
        for name, pids in self.names.items():
            if identifier.lower() in name.lower():
                for pid in pids:
                    self.kill(pid, verbose=False)
                    print(f'\t↳ killed {pid} ({name})')
        
        string = f'killed application "{identifier}" and all child processes.'
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

        self.stdout[timestamp] = string

        log(string, header='kill', mode='s')

    def kill (self, pid: int, verbose: bool=True) -> None:

        '''
        Kills the current process with PID.
        '''

        name = self.processes[pid].info['name']
        self.processes[pid].kill()

        string = f'killed process {pid} ({name})'
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

        self.stdout[timestamp] = string

        log(string, header='kill') if verbose else None

    def listen (self) -> None:

        '''
        Starts the listener thread which runs the listener loop in the background.
        '''

        if not self.listen_thread.is_alive():
            self.listen_thread.start()

    def listener_loop (self) -> None:

        try:
            if not self.active:
                return
            self.update_processes()
            self.trim_cache()
        except:
            log(format_exc(), mode='e')
        
    def ps (self) -> None:

        '''
        Bash-like alias for show_processes.
        '''

        self.show_processes()

    def show_processes (self) -> None:
        
        '''
        Prints all PIDs and corr. process names in alphabetical order.
        '''

        print('PID\t\tAPP','\n----------------------------')
        sorted_names = {k: v for k, v in sorted(self.names.items(), key=lambda item: item[0])}
        for name, ids in sorted_names.items():
            for id in ids:
                print(f'{id}\t\t{name}')

    def stop (self) -> None:

        '''
        Alias for stopping the service thread.
        '''

        self.listen_thread.stop()

    def trim_cache (self) -> None:
        
        '''
        Trims the stdout cache to allowed tracking length.
        '''

        if len(self.stdout) > self.track_length:
            self.stdout = self.stdout[-self.track_length:] 

    def update_processes (self) -> None:
        
        '''
        Updates the processes object with currently active processes only.
        '''

        # Get all processes each with a list of selected attributes
        process_list = psutil.process_iter(['pid', 'name', 'connections'])

        # track only active IDs which will help to identify deprecated processes
        active_ids = set()

        # Iterate over all processes
        for proc in process_list:

            id = proc.info['pid']
            name = proc.info['name']

            if name.lower() in self.ignore_prc:
                continue

            # create id pointer to proc in processes list
            self.processes[id] = proc

            # denote the id in current id set and active set
            active_ids.add(id)
            
            # check if the pid is unknown
            if id not in self.id_set:
                self.id_set.add(id)
                if self.initialized:
                    stdout_string = log(f'New process "{name}" started.', header=id, mode='w', log_path=self.log_path)
                    self.stdout.append(stdout_string)

            # add a name mapping if not exists
            if name not in self.names:
                self.names[name] = set()

            # add the process id to process name map
            self.names[name].add(id)

        # remove all deprecated ids
        deprecated_ids = self.id_set.difference(active_ids)
        for id in deprecated_ids:

            name = self.get_name(id)
            if name.lower() in self.ignore_prc:
                continue
            
            # create stdout and add to stdout cache
            stdout_string = log(f'"{name}" terminated.', header=str(id), mode='e', log_path=self.log_path)
            self.stdout.append(stdout_string)

            # remove the id from all caching objects
            self.id_set.remove(id)
            self.processes.pop(id)
            self.names[name].remove(id)
            if not self.names[name]:
                self.names.pop(name)

class LocalNetworkListener:

    '''
    Manages connections of all processes running on local host to all remote domains.
    
    [Parameter]

    process_monitor :       the processListener instance

    verbose :               if enabled will print stdout directly from the object itself.
                            in any case the whole stdout will be stored in self.stdout.
    '''

    def __init__ (self, process_monitor: ProcessListener, verbose: bool) -> None:
        
        self.active = False

        self.root_path = Path(__file__).resolve().parent
        self.log_path = self.root_path.joinpath('logs/network.log')

        self.process_monitor = process_monitor
        self.network_activity: dict[int, dict] = dict()

        self.local_domains = ['127.0.0.1']

        # stdout cache
        self.track_length = 100
        self.stdout: list[str] = list()
        self.verbose: bool = verbose

        # setup a listen thread which can be enabled/disabled
        self.listen_thread = thread(self.listener_loop, .1)
    
    def enable (self) -> None:

        '''
        Enables the listener.
        '''

        self.active = True
    
    def disable (self) -> None:

        '''
        Disables the listener to IDLE - this will keep the thread alive.
        '''

        self.active = False

    def listen (self) -> None:

        '''
        Starts the listener thread which runs the listener loop in the background.
        '''

        if not self.listen_thread.is_alive():
            self.listen_thread.start()

    def listener_loop (self) -> None:

        try:
            if not self.active:
                return
            self.update_network_activity()
            self.trim_cache()
        except:
            log(format_exc(), mode='e')

    def show_connections (self, remote_only: bool=True) -> None:

        '''
        Shows all connections of all processes in console. 
        Process names, their corresponding remote domain connection and dns name. 
        '''

        for name in self.process_monitor.names:
            pids = self.process_monitor.names[name]
            for pid in pids:
                if not pid in self.network_activity:
                    continue
                connections = self.network_activity[pid]['connections']
                for conn in connections:
                    if remote_only and conn["domain"] in self.local_domains:
                        continue
                    string = f'{name} <---> {conn["remote_addr"]}'
                    log(string, header='activity', log_path=self.log_path)

    def stop (self) -> None:

        '''
        Alias for stopping the service thread.
        '''

        self.listen_thread.stop()

    def trim_cache (self) -> None:

        '''
        Trims the stdout cache to allowed tracking length.
        '''

        if len(self.stdout) > self.track_length:
            self.stdout = self.stdout[-self.track_length:] 

    def update_network_activity (self, clean_artifacts: bool=True, remote_only: bool=True) -> None:

        '''
        Updates the network activity object by looking up 
        all remote endpoint connections associated with each process.
        '''

        active_ids = set()

        # make a pid snapshot
        PIDs = list(self.process_monitor.id_set)

        for id in PIDs:
            
            try:

                proc = self.process_monitor.processes[id]
                name = proc.info['name']
                connections = proc.info['connections']
                
                # denote the network information for the pid
                # if not known yet.
                if not id in self.network_activity:
                    self.network_activity[id] = {
                        'name': name,
                        'connections': []
                    }

                # accumulate only necessary info from connections
                current_connections = []

                for conn in connections:
                    
                    if conn.status == psutil.CONN_ESTABLISHED:

                        # add id to active id set
                        active_ids.add(id)

                        remote_domain = f"{conn.raddr.ip}"
                        local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
                        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"
                        
                        if remote_only and remote_domain in self.local_domains:
                            continue

                        # new connection package format
                        connection = {
                            'domain': remote_domain,
                            'local_addr': local_address,
                            'remote_addr': remote_address
                        }

                        # skip this cycle to prevent double occurrences in final list
                        if connection in current_connections:
                            continue

                        # append activity to stdout log
                        if connection not in self.network_activity[id]['connections']:
                            self.stdout.append(log(f'{name} <---> {remote_address}', header='conn'))

                        # otherwise append connection
                        current_connections.append(connection)

                # finally override remote addresses
                self.network_activity[id]['connections'] = current_connections
            
            except KeyError:
            
                log(f'the process {id} is an artifact, will skip network analysis ...', mode='w', header='LocalNetworkListener', print_to_console=self.verbose)
                continue

        # clean artifact processes i.e. processes which have no connection
        if clean_artifacts:
            deprecated_ids = set(self.network_activity.keys()).difference(active_ids)
            for id in deprecated_ids:
                self.network_activity.pop(id)

class PrivateNetworkListener ():

    '''
    A listener for the private network which tracks all devices,
    their IP and MAC addresses as well as DNS for device names etc.
    '''

    def __init__(self, mac_only: bool=False, verbose: bool=True):

        self.active = False

        self.root_path = Path(__file__).resolve().parent
        self.log_path = self.root_path.joinpath('logs/devices.log')
        self.mac_path = self.root_path.joinpath('cache/mac.json')

        # init cache, if none exists create it
        for path in [self.mac_path]:
            if not path.exists():
                with open(self.mac_path, 'w+') as f:
                    json.dump({}, f)
        
        # Initialize network scanner.
        self.scanner = NetworkScanner()
        self.scan_range_lim = (0, 255)

        self.host_ip = get_host_ip()
        self.subnet_mask = get_subnet_mask(self.host_ip)
        
        # map mac addresses to device names.
        self.mac: dict[str, str] = dict()
        self.mac_load()
        self.mac_only = mac_only

        # stdout cache
        self.track_length = 100
        self.stdout: list[str] = list()
        self.verbose: bool = verbose

        # map IPs to MAC addresses
        self.ip_to_mac: dict[str, str] = dict()
        self.active_devices: set[str] = set()

        self.listen_thread = thread(self.listener_loop, 1)

    def enable (self) -> None:

        '''
        Enables the listener - the thread will stay alive.
        '''

        self.active = True
    
    def disable (self) -> None:

        '''
        Disables the listener to IDLE - this will keep the thread alive.
        '''

        self.active = False

    def listen (self) -> None:

        self.listen_thread.start()

    def listener_loop (self) -> None:

        try:

            if not self.active:
                return
            self.update_devices()
            self.trim_cache()
        
        except Exception as e:

            log(format_exc(), mode='e')

    def mac_dump (self) -> None:

        '''
        Dump the current MAC DNS list.
        '''

        with open(self.mac_path, 'w+') as f:
            json.dump(self.mac, f)

    def mac_load (self) -> None:

        '''
        Load MAC DNS list.
        '''

        with open(self.mac_path, 'r+') as f:
            self.mac = json.load(f)
    
    def show_devices (self) -> None:

        return
        # for ip in ips:
        #     mac = get_mac(ip)
        #     print(ip, 'mac', mac)

    def stop (self) -> None:

        '''
        Alias for stopping the service thread.
        '''

        self.listen_thread.stop()

    def trim_cache (self) -> None:

        '''
        Trims the stdout cache to allowed tracking length.
        '''

        if len(self.stdout) > self.track_length:
            self.stdout = self.stdout[-self.track_length:] 

    def update_devices (self) -> None:

        '''
        Updates all devices visible in the current network.
        '''

        # snapshot the tracked ips
        tracked_ips = self.active_devices.copy()

        # find all ips in subnet
        active_ips = set(self.scanner.scan_range(*self.scan_range_lim))
        
        # determine all deprecated ids
        deprecated_ips = tracked_ips.difference(active_ips)

        # new IPs
        new_ips = active_ips.difference(tracked_ips) 

        # iterate first over the newly found ips and add them to the corr. maps
        for ip in new_ips:

            # determine mac
            mac = get_mac(ip)
            mac = mac if mac else 'unknown'

            # add ip to active devices
            if ip == self.host_ip:
                name = 'localhost'
            else:
                name = self.mac[mac] if mac and mac in self.mac else ip
            
            # skip unknown macs if mac_only is enabled
            if self.mac_only and name != 'localhost' and mac == 'unknown':
                continue

            # add to active devices
            self.active_devices.add(ip)

            # determine if the new IP is known by MAC DNS
            if mac != 'unknown' and not mac in self.mac:
                stdout_string = log(f'unknown "{name}" | IP:{ip}, MAC: {mac}', header='device', symbol='⚠️', log_path=self.log_path, print_to_console=self.verbose)
                self.mac[mac] = name
            else:
                stdout_string = log(f'connected "{name}" | IP: {ip}, MAC: {mac}', header='device', symbol='💻', log_path=self.log_path, print_to_console=self.verbose)
            
            # save in stdout cache
            self.stdout.append(stdout_string)

            # sort in the new info
            self.ip_to_mac[ip] = mac
        
        # remove all deprecated ips (only from the active devices, 
        # as other mappings are useful and should stay persistent)
        for ip in deprecated_ips:
            if not ip in self.active_devices:
                continue
            self.stdout.append(log(f'lost connection to "{self.mac[self.ip_to_mac[ip]]}" ({ip})', header='scan', symbol='💻', log_path=self.log_path, print_to_console=self.verbose))
            self.active_devices.remove(ip)

        # finally dump the new mac
        self.mac_dump()

# ---- end-points ----            
class DnsEndPoint:

    def __init__(self, verbose: bool=True):

        self.active = False

        self.root_path = Path(__file__).resolve().parent
        self.log_path = self.root_path.joinpath('logs/network.log')
        self.dns_path = self.root_path.joinpath('cache/dns.json')

        for path in [self.log_path, self.dns_path]:
            if not path.exists():
                with open(path, 'w+') as f:
                    f.write("{}")

        # dns lookup
        self.local_domains = ['127.0.0.1']
        self.dns: dict[str, dict] = dict() # ip -> whois information

        # the stack aggregates domains for queued lookups 
        self.stack = []
        
        # stdout cache
        self.track_length = 100
        # self.stdout: dict[str, str] = {}
        self.stdout: list[str] = list()
        self.verbose: bool = verbose

        # load DNS list
        self.dns_load()

        # set dns service thread
        self.service_thread = thread(self.dns_service, 5)

    def enable (self) -> None:

        '''
        Enables the listener - the thread will stay alive.
        '''

        self.active = True
    
    def disable (self) -> None:

        '''
        Disables the listener to IDLE - this will keep the thread alive.
        '''

        self.active = False
    
    def dns_service (self) -> None:

        '''
        DNS service for processing the stack. 
        '''

        if not self.active:
            return

        # stop if the stack is empty
        if not self.stack:
            return
        
        try:

            # remove next domain from stack
            domain = self.stack.pop(0)

            # perform whois lookup
            self.dns[domain] = self.who_is(domain)
            
            # resolve 
            stdout_string = log(f'"{domain}" resolved as {self.dns[domain]["asn_description"]}', symbol='📍', header='dns', log_path=self.log_path, print_to_console=self.verbose)
            
            # dump the new dns map
            self.dns_dump()

            # trim the cache
            self.trim_cache()

        except IPDefinedError:
            
            stdout_string = log(f'{domain} is a local domain.', symbol='🔍', header='dns', log_path=self.log_path, print_to_console=self.verbose)
            self.local_domains.append(domain)
            return
        
        except:
        
            print_exc()
        
        finally:

            # append stdout to cache
            self.stdout.append(stdout_string)

    def dns_add (self, domain: str) -> None:

        '''
        Will add the domain to the dns stack.
        '''

        self.stack.append(domain)

    def dns_dump (self) -> None:

        with open(self.dns_path, 'w+') as f:
            json.dump(self.dns, f)

    def dns_load (self) -> None:

        with open(self.dns_path, 'r+') as f:
            self.dns = json.load(f)
    
    def dns_resolved (self, domain: str) -> bool:

        '''
        Returns boolean indicating wether a domain was received already.
        '''

        if domain in self.stack or domain in self.dns or domain in self.local_domains:

            return True
        
        return False
    
    def who_is (self, domain: str) -> dict:

        '''
        domain :        domain is an IP or URL
        '''

        log(f'lookup information for "{domain}" ...', header='dns', print_to_console=self.verbose)
        return IPWhois(domain).lookup_whois()

    def start (self) -> None:
        
        self.service_thread.start()
    
    def stop (self) -> None:
        
        '''
        Alias for stopping the service thread.
        '''

        self.service_thread.stop()

    def trim_cache (self) -> None:

        '''
        Trims the stdout cache to allowed tracking length.
        '''

        if len(self.stdout) > self.track_length:
            self.stdout = self.stdout[-self.track_length:] 

class DnsWatchdog:

    '''
    Watches all TCP/UDP connections of every process and resolves the corr. whois information via the dns end-point.
    '''

    def __init__(self, networkListener: LocalNetworkListener, dnsEndpoint: DnsEndPoint):
        
        self.active = False

        self.network = networkListener
        self.dns = dnsEndpoint

        # set service thread
        self.service_thread = thread(self.service, .1)

    def enable (self) -> None:

        '''
        Enables the listener - the thread will stay alive.
        '''

        self.active = True
    
    def disable (self) -> None:

        '''
        Disables the listener to IDLE - this will keep the thread alive.
        '''

        self.active = False

    def start (self) -> None:

        self.service_thread.start()

    def stop (self) -> None:

        self.service_thread.stop()

    def service (self) -> None:

        try:
            
            if not self.active:
                return
            
            # pid activity snapshot
            pid_activities = list(self.network.network_activity.values())

            # analyze all gathered connections
            for activity in pid_activities:
                
                process_name = activity['name']
                connections = activity['connections']

                for conn in connections:

                    domain = conn['domain']
                    
                    # skip if the domain is known
                    if self.dns.dns_resolved(domain):
                        continue

                    # otherwise perform a lookup
                    log(f'New connection detected "{process_name}" <---> "{domain}"', mode='w', header='core')
                    self.dns.dns_add(domain)  

        except KeyError:

            pass

        except:

            log(format_exc(), mode='e')