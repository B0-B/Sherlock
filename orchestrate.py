#!/usr/bin/env python3 
from time import sleep
from pathlib import Path
from typing import Callable
from traceback import format_exc
from multiprocessing import Process, Event


from utils import log

class CronDog:

    '''
    A simple job dispatcher.
    '''

    def __init__(self):

        # set the root file system path which should be watched
        self.root_path = Path(__file__).resolve().parent

        # Jobs
        self.jobs: dict[str, Process] = dict()
        self.stop_events: dict[str, "event"] = dict()

    def add_job (self, name: str, target: Callable, repeat: bool=True, delay: int=1, args:tuple=(), kwargs:dict={}) -> Process:
        
        '''
        [Parameter]

        name :          Unique job name or identifier.

        target :        Target function to call.

        repeat :        Toggle if the job should repeat.

        delay :         Only needed for repeating jobs.
                        Sets the delay in seconds. Default is 1.
        '''

        # add stop event for the job
        stop_event = Event()
        self.stop_events[name] = stop_event

        # Repeating jobs demand a loop wrapper
        if repeat:
            
            # build wrapper
            def loop_wrap ():
                while not stop_event.is_set():
                    try:
                        target(*args, **kwargs)
                    except:
                        log(format_exc(), header=f'job "{name}"]', mode='e')
                    finally:
                        sleep(delay)
            
            _target = loop_wrap
            _args = ()
            _kwargs = {}
        
        else:

            _target = target
            _args = ()
            _kwargs = {}

        # setup process
        self.jobs[name] = Process(name=name, target=_target, args=_args, kwargs=_kwargs)

    def get_job (self, name: str) -> Process:

        return self.jobs[name]

    def job_active (self, name: str) -> bool:

        '''
        Returns boolean indicating if a job is active.
        '''

        return not self.stop_events[name].is_set()

    def start_all_jobs(self) -> None:

        '''
        Starts all jobs.
        '''

        for job in self.jobs.values():
            job.start()

    def start_job (self, name: str) -> None:

        '''
        Starts the job as a process.
        '''

        self.jobs[name].start()

    def stop_all_jobs(self) -> None:

        for event in self.stop_events.values():
            event.set()

    def stop_job (self, name: str) -> None:

        self.stop_events[name].set()