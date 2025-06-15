#!/usr/bin/env python3 
from multiprocessing import Process, Event
from typing import Callable

from listeners import *

class Core:

    def __init__(self, root_path, ignore_directories: list[str]|None=None):

        '''
        [Parameter]

        root_path :             The root path to search from.

        ignore_directories :    Which directories or branches to ignore.
        '''

        # set the root file system path which should be watched
        self.root_path = Path(__file__).resolve().parent
        self.log_path = self.root_path.joinpath('logs/')
        self.sound_path = self.root_path.joinpath('sound/')
        self.trap_path = Path.home()
        self.file_system_path = root_path
        
        # Load listener services.
        self.fs = FileSystemListener(ignore_directories)
        self.process = ProcessListener(ignore_prc=['ping.exe'])
        self.network = LocalNetworkListener(self.process)
        self.private = PrivateNetworkListener(mac_only=True)

        self.dns = DnsEndPoint()
        self.delay = 0.5
        self.core_thread = thread(self.main_sequence, self.delay)

        # std output aggregation
        self.stdout = {}

        # Prepare a random trap file in home dir
        self.trap_active = True
        self.trap_file_path = place_trap_file(self.trap_path)

        self.sound_path

    def alert (self) -> None:

        '''
        Plays an alert sound (once).
        '''

        play(self.sound_path.joinpath('open_alert.mp3').as_posix())

    def purge_logs (self) -> None:

        '''
        Will reset all log files.
        '''

        for sub in ['files', 'network', 'process', 'devices']:
            with open(self.log_path.joinpath( sub + '.log' ), 'w+') as f:
                f.write('')

    def main_sequence (self) -> None:

        '''
        Main sequence for the core thread.
        '''

        try:
            
            # pid activity snapshot
            pid_activities = list(self.network.network_activity.values())

            # analyze all gathered connections
            for activity in pid_activities:
                
                process_name = activity['name']
                connections = activity['connections']
                # print('prc', process_name, connections)
                for conn in connections:

                    domain = conn['domain']
                    
                    # skip if the domain is known
                    if self.dns.dns_resolved(domain):
                        continue

                    # otherwise perform a lookup
                    log(f'New connection detected "{process_name}" <---> "{domain}"', mode='w', header='core')
                    self.dns.dns_add(domain)

            # check for trap file
            if self.trap_file_path in self.fs.changes:
                while self.trap_active:
                    log('Trap was triggered. The system could be compromised!', mode='e')
                    self.alert()
                self.trap_active = True
                while self.trap_file_path in self.fs.changes:
                    self.fs.changes.remove(self.trap_file_path)     
        
        except KeyboardInterrupt:

            # stop all services
            self.fs.stop()
            self.process.stop()
            self.network.stop()
            self.private.stop()

            self.core_thread.stop()

            return

        except KeyError:

            pass

        except:

            log(format_exc(), mode='e')

    def start (self) -> None:

        # start all listener services
        self.fs.listen(self.file_system_path)
        self.process.listen()
        self.network.listen()
        self.private.listen()

        # end point service threads
        self.dns.start()

        # start the core thread
        self.core_thread.start()
    
    def stop (self) -> None:

        '''
        Alias for stopping all service threads.
        '''

        # stop all listener services
        self.fs.stop()
        self.process.stop()
        self.network.stop()
        self.private.stop()

        # end point service threads
        self.dns.stop()

        # stop core thread
        self.core_thread.stop()

class Core3:

    def __init__(self, search_path, ignore_directories: list[str]|None=None, verbose: bool=True):

        '''
        [Parameter]

        root_path :             The root path to search from.

        ignore_directories :    Which directories or branches to ignore.
        '''

        # Set the root file system path which should be watched
        self.root_path = Path(__file__).resolve().parent
        self.log_path = self.root_path.joinpath('logs/')
        self.sound_path = self.root_path.joinpath('sound/')
        self.trap_path = Path.home().joinpath('bitcoin_wallet.txt')
        self.file_system_path = search_path

        # Load listeners
        self.fs      = FileSystemListener(ignore_directories, verbose=verbose)
        self.process = ProcessListener(ignore_prc=['ping.exe'], verbose=verbose)
        self.network = LocalNetworkListener(self.process, verbose=verbose)
        self.private = PrivateNetworkListener(mac_only=True, verbose=verbose)

        # Load DNS modules
        self.dns = DnsEndPoint()
        self.watchdog = DnsWatchdog(self.network, self.dns)

    def run (self) -> None:

        '''
        Run orchestration.
        '''

        self.fs.listen(self.file_system_path)
        self.process.listen()
        self.network.listen()
        self.private.listen()
        
        self.dns.start()
        self.watchdog.start()

        # enable all services
        self.fs.enable()
        self.process.enable()
        self.network.enable()
        self.private.enable()

        self.dns.enable()
        self.watchdog.enable()

    def start (self) -> None:

        '''
        Start run orchestration.
        '''

        self.run()

    def stop (self) -> None:

        '''
        Stop all services.
        '''

        self.fs.stop()
        self.process.stop()
        self.network.stop()
        self.private.stop()

        self.dns.stop()
        self.dns.stop()

# ----------- Execute ------------
if __name__ == '__main__':

    if 0:
        c = Core('C:/Users/weezl/')
        c.start()
        while True:
            try:
                sleep(1)
            except KeyboardInterrupt:
                c.stop()
                exit()

    if 0:
        p = PrivateNetworkListener(mac_only=True)
        p.listen()

    if 1:
        Core3('C:/Users/weezl/').run()