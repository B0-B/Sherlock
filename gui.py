#!/usr/bin/env python3 
import tkinter as tk
from pathlib import Path
from core import Core3
from utils import *
from utils import thread
from traceback import print_exc
import ctypes
from typing import Callable

class GUI (tk.Tk):

    __about__ = {
        "name": "Sherlock"
    }

    def __init__ (self) -> None:
        
        # ---- GUI parameters ----
        # Geometry and Layout
        self.size = (1200, 900)
        self.layout_geometry = (2, 6)
        self.layout_content_position = {
            'filesystem': (0, 1),
            'process': (1, 1),
            'network': (0, 3),
            'private': (1, 3),
            'dns': (0, 5)}
        self.stdout_text_fields: dict[str, tk.Text] = {
            'filesystem': None,
            'process': None,
            'network': None,
            'private': None,
            'dns': None}
        self.running = False
        self.log_lines = 20
        self.log_line_length = 100
        self.padx = 10
        self.pady = 10
        
        # Style
        self.root_background = '#383838'
        self.stdout_background = '#15151c'
        self.stdout_foreground = '#ffffff'
        self.label_font = ('Arial', 10)
        self.stdout_font = ('Courier New', 8)

        # ---- Backend Parameter ----
        self.stdout_lines = 100
        search_path = Path.home().as_posix()
        verbose: bool = True

        # Initialize tkinter window
        super().__init__(GUI.__about__["name"])

        # Build the interface.
        self.screen_width = self.winfo_screenwidth()
        self.screen_height = self.winfo_screenheight()
        print(f'Detected Screen Resolution: {self.screen_width}x{self.screen_height}')
        if self.screen_width < 2560:
            self.size = (900, 600)
        else:
            self.size = (1200, 900)
        self.build()

        # initialize core
        self.core = Core3(search_path, verbose=verbose)
        self.listeners: dict[str, "Listener"] = {
            'filesystem': self.core.fs,
            'process': self.core.process,
            'network': self.core.network,
            'private': self.core.private,
            'dns': self.core.dns}

        # initialize interface
        self.interface_update_time = .3
        self.interface_thread = thread(self.interface_routine, self.interface_update_time)

    def build (self) -> None:

        '''
        Builds the interface.
        '''

        # Set title and window boundaries.
        self.title(GUI.__about__["name"])
        self.geometry("{}x{}".format(*self.size))

        # Apply style
        self.configure(background=self.root_background)

        # -------- Build Terminals Page --------

        # Configure the grid layout to keep elements aligned.
        for col in range(self.layout_geometry[0]):
            self.columnconfigure(col, weight=1)
        for row in range(self.layout_geometry[1]):
            self.rowconfigure(row, weight=1)

        # Add the stdout text fields to the grid
        for label_text in self.layout_content_position.keys():

            # Initialize text fields for stdout
            self.stdout_text_fields[label_text] = tk.Text(self,
                                                          height=self.log_lines, 
                                                          width=self.log_line_length, 
                                                          background=self.stdout_background, 
                                                          foreground=self.stdout_foreground, 
                                                          font=self.stdout_font)

            pos = self.layout_content_position[label_text]
            text_field = self.stdout_text_fields[label_text]
            
            # build a label
            label_field = tk.Label(self, text=label_text.upper(), font=self.label_font, background=self.root_background, foreground='white')

            label_field.grid(column=pos[0], row=pos[1]-1)
            text_field.grid(column=pos[0], row=pos[1], padx=self.padx, pady=self.pady)
        
    def insert_text (self, text: str, field: tk.Text) -> None:
        
        '''
        Insert text by appending to current content.
        '''

        # field.delete("1.0", "end")
        field.insert(tk.END, text)
        # If scrolled to bottom keep up-to-date with auto scrolling
        self.scroll_to_end(field)
        self.update()

    def insert_link (self, text: str, field: tk.Text, callback: Callable) -> None:

        field.tag_config("tag", foreground="orange")
        field.tag_bind("tag", "<Button-1>", callback)
        field.insert(tk.END, text, "tag")

    def interface_routine (self) -> None:

        try:

            # ---- update stdout ----
            s = ' ' # separator string
            string = ''
            for label, field in self.stdout_text_fields.items():

                listener_module = self.listeners[label]
                stdout_lines = listener_module.stdout[-self.stdout_lines:]

                # decide how to process the stdout by label
                if False and label in ['filesystem', 'network']:

                    # analyze line by line to insert hyperlinks
                    for line in stdout_lines:
                        

                        line_list = line.split(s)
                        
                        for chunk in line_list:
                            if detect_pattern(chunk) == 'Text':
                                string += s + chunk
                            else:
                                if string:
                                    self.insert_text(string, field)
                                    string = ''
                                self.insert_link(s + chunk, field, self.search)
                        if string:
                            self.insert_text(string, field)
                            string = ''
                        self.insert_text('\n', field)
                            
                    # if label == 'filesystem':
                    #     line_list = line.split(s)
                    #     text = s.join(line_list[:-1]) + s
                    #     link = line_list[-1]+'\n'
                    # self.insert_text(text, field)
                    # self.insert_link(link, field, self.search)
                else:
                    text = '\n'.join(listener_module.stdout[-self.stdout_lines:]) + '\n'
                    self.insert_text(text, field)
        
        except:

            print_exc()
    
    def is_scrolled_to_end (self, field: tk.Text) -> bool:

        return field.yview()[1] == 1.0
    
    def search (self, event):

        print('event:', event)

    def scroll_to_end (self, field: tk.Text) -> None:

        field.see('end') # scroll to bottom

    def run (self, *args, **kwargs) -> None:

        '''
        Starts the app.
        '''

        # Start core and interface thread
        self.core.start()
        self.interface_thread.start()

        # run
        try:
            self.running = True
            # self.insert_text('Hello WOrld!', self.stdout_text_fields['filesystem'])
            self.mainloop(*args, **kwargs)
        finally:
            self.running = False

if __name__ == '__main__':
    app = GUI()
    app.run()