# clamav-gui
A graphical interface for scanning and managing ClamAV antivirus definitions.
#!/usr/bin/env python3



 import tkinter as tk
 from tkinter import simpledialog, filedialog, messagebox,ttk
 import subprocess
 import threading
 import getpass
 import os
 import platform
 import signal
 import logging
 import pexpect
 import re
 import pathlib
 from PIL import Image, ImageTk
 #Set up logging
 logging.basicConfig(level=logging.INFO, format=' %(asctime)s - %(levelname)s - %(message)s')

class ClamAVGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("ClamAV GUI")
        self.window.geometry('1020x650') # Set res.
        self.window.resizable(width=False, height=False)
        self.scan_in_progress = False
                
        # Main Frame
        self.frame = tk.Frame(self.window, bg='#f1f3f3')
        self.frame.pack(fill=tk.BOTH, expand=False)

        # Bottom frame for ClamAV info
        self.top_frame = tk.Frame(self.window,bg='#f1f3f3',borderwidth=2, relief="groove", padx=2, pady=2)
        self.top_frame.pack(fill=tk.X,expand=False, padx=0, pady=0)
        
        # Left Frame for buttons
        self.left_frame = tk.Frame(self.frame,bg='#f1f3f3',padx=0, pady=0)
        self.left_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Load the image
        try:
            self.image = tk.PhotoImage(file="~/clamav-gui/clam2.png")
        except Exception as e:
            print(f"Error loading image: {e}")  # Handle potential image loading errors
            self.image = None # Set to None so we don't try to use it later

        # Add the image to the window
        if self.image:
            self.label = tk.Label(self.left_frame, image=self.image,)  # Place on top_frame
            self.label.place(relx=0.0, rely=1.1, anchor="sw",) # Bottom-left corner


        # Right Frame for output
        self.right_frame = tk.Frame(self.frame,bg='#f1f3f3')
        self.right_frame.pack(side=tk.RIGHT, fill=tk.Y, expand=False)

        # Right Top Frame
        self.right_top_frame = tk.Frame(self.right_frame,bg='#f1f3f3')
        self.right_top_frame.pack(side=tk.TOP, fill=tk.X, expand=False)

        # Right Bottom Frame
        self.right_bottom_frame = tk.Frame(self.right_frame,bg='#f1f3f3')
        self.right_bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=False)

        # Create Buttons
        self.update_button = tk.Button(self.left_frame, text="Update Database", command=self.update_db, height=1, width=15, bg='#f69e9e',borderwidth=0)
        self.update_button.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)

        self.scan_directory_button = tk.Button(self.left_frame, text="Scan Directory", command=self.scan_directory, height=1, width=15, bg='#9cbbe5',borderwidth=0)
        self.scan_directory_button.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)

        self.scan_file_button = tk.Button(self.left_frame, text="Scan File", command=self.scan_file, height=1, width=15, bg='#9cbbe5',borderwidth=0)
        self.scan_file_button.pack(side=tk.TOP, fill=tk.X, padx=20, pady=5)

        self.cancel_button = tk.Button(self.left_frame, text="Cancel", command=self.cancel_scan, state=tk.DISABLED, height=1, width=15, bg='#9cbbe5',borderwidth=0)
        self.cancel_button.pack(side=tk.TOP,fill=tk.X, padx=20, pady=5)
        
        self.open_log_button = tk.Button(self.left_frame, text="Open Log", command=self.open_clamav_log, height=1, width=15, bg="#a3a3a3", fg="white", relief=tk.RAISED, borderwidth=0)
        self.open_log_button.pack(side=tk.TOP,fill=tk.X, padx=20, pady=5)

        self.quit_button = tk.Button(self.left_frame, text="Quit", command=self.window.destroy, height=1, width=15, bg='#a3a3a3', fg="white", borderwidth=0)
        self.quit_button.pack(side=tk.TOP,fill=tk.X, padx=20, pady=5)

        self.quarantine_infected_checkbox = tk.BooleanVar()
        self.quarantine_infected_checkbox.set(False)
        self.delete_infected_checkbox = tk.BooleanVar()
        self.delete_infected_checkbox.set(False)
        self.leave_it_checkbox = tk.BooleanVar()
        self.leave_it_checkbox.set(True)
        self.alarm_bell_checkbox = tk.BooleanVar()
        self.alarm_bell_checkbox.set(True)
        self.log_checkbox = tk.BooleanVar()
        self.log_checkbox.set(True)
        
        # Black frame around checkboxes
        self.action_frame = tk.Frame(self.left_frame, borderwidth=2, relief="groove",height=50, width=200)
        self.action_frame.pack(side=tk.TOP, padx=10, pady=20)

        # Black frame around Bell/Log checkbox
        self.alarm_frame = tk.Frame(self.left_frame, borderwidth=2, relief="groove",height=50, width=200)
        self.alarm_frame.pack(side=tk.TOP, padx=10, pady=20)

        # Add "Action" label above checkboxes
        self.action_label = tk.Label(self.action_frame, text="Action", font=("Arial", 15),)
        self.action_label.pack()
        
        # Add "Alarm/Log" label above Bell checkboxes
        self.alarm_label = tk.Label(self.alarm_frame, text="Alarm/Log", font=("Arial", 15))
        self.alarm_label.pack()
      
        # Checkboxes selections (when clamav starts) 
        self.quarantine_infected_checkbox = tk.BooleanVar()
        self.quarantine_infected_checkbox.set(False)
        self.delete_infected_checkbox = tk.BooleanVar()
        self.delete_infected_checkbox.set(False)
        self.leave_it_checkbox = tk.BooleanVar()
        self.leave_it_checkbox.set(True)
        self.alarm_bell_checkbox = tk.BooleanVar()
        self.alarm_bell_checkbox.set(True)
        self.log_checkbox = tk.BooleanVar()
        self.log_checkbox.set(True)
       	
	    # Checkboxes Quarantine/Delete/No Action
        self.quarantine_infected_checkbox_button = tk.Checkbutton(self.action_frame, text="Quarantine   ", variable=self.quarantine_infected_checkbox, command=self.quarantine_infected_checkbox_callback)
        self.quarantine_infected_checkbox_button.pack(side=tk.TOP, padx=5, pady=5)
       
        self.delete_infected_checkbox_button = tk.Checkbutton(self.action_frame, text="Delete             ", variable=self.delete_infected_checkbox, command=self.delete_infected_checkbox_callback)
        self.delete_infected_checkbox_button.pack(side=tk.TOP, padx=5, pady=5)

        self.leave_it_checkbox_button = tk.Checkbutton(self.action_frame, text="No Actions !!!", fg='#FF0000', variable=self.leave_it_checkbox, command=self.leave_it_checkbox_callback)
        self.leave_it_checkbox_button.pack(side=tk.TOP,padx=5, pady=5)
        
        # Checkboxes Alarm/Log
        self.alarm_bell_checkbox_button = tk.Checkbutton(self.alarm_frame, text="Bell !!              ", variable=self.alarm_bell_checkbox, command=self.alarm_bell_checkbox_callback)
        self.alarm_bell_checkbox_button.pack(side=tk.TOP,padx=5, pady=5)
        
        self.log_checkbox_button = tk.Checkbutton(self.alarm_frame, text="Log                   ", variable=self.log_checkbox, command=self.log_checkbox_callback)
        self.log_checkbox_button.pack(side=tk.TOP,padx=5, pady=5)
                
        # Output Window (Text widget)
        self.output_window = tk.Text(self.right_frame, height=30, width=97, bg='#e7e7e7')  # Reduced width for text area
        self.output_window.pack(side=tk.LEFT, fill=tk.X, pady=(10, 0)) # Left
        self.output_window.bind("<Key>", lambda event: "break")

        # Scrollbar for output window
        self.scrollbar = tk.Scrollbar(self.right_frame, orient=tk.VERTICAL, command=self.output_window.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=(10, 0))  # Right

        # Connect Text Widget to Scrollbar
        self.output_window['yscrollcommand'] = self.scrollbar.set
 
        # Bind hover event to show a tooltip (info)
        self.quarantine_infected_checkbox_button.bind("<Enter>", lambda event: self.show_tooltip(event, "ClamAV will move infected files to the Trash"))
        self.quarantine_infected_checkbox_button.bind("<Leave>", lambda event: self.hide_tooltip())
        self.delete_infected_checkbox_button.bind("<Enter>", lambda event: self.show_tooltip(event, "ClamAV will automatically remove infected files."))
        self.delete_infected_checkbox_button.bind("<Leave>", lambda event: self.hide_tooltip())
        self.leave_it_checkbox_button.bind("<Enter>", lambda event: self.show_tooltip(event, "ClamAV will only detect infected files; no actions will be taken."))
        self.leave_it_checkbox_button.bind("<Leave>", lambda event: self.hide_tooltip())
        self.alarm_bell_checkbox_button.bind("<Enter>", lambda event: self.show_tooltip(event, "Sound an alarm upon finding infected files."))
        self.alarm_bell_checkbox_button.bind("<Leave>", lambda event: self.hide_tooltip())
        self.log_checkbox_button.bind("<Enter>", lambda event: self.show_tooltip(event, "Enable scan logging to save details in clamav_log.txt."))
        self.log_checkbox_button.bind("<Leave>", lambda event: self.hide_tooltip())
                
        self.check_clamav_installed() #Call Function to checks if ClamAV is installed
        
    def check_clamav_installed(self): #Checks if ClamAV is installed
        try:
            command = "compgen -c | grep clamscan"  # String command
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if  result.stdout.strip():
                self.update_output("Welcome to ClamAV!")
                # Get ClamAV version
                self.clamav_version = subprocess.run("clamscan -V", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().splitlines()[0]

                # Create ClamAV info label
                self.version_label = tk.Label(self.top_frame, text="ClamAV Version: " + self.clamav_version, font=("Arial", 16),bg='#f1f3f3')
                self.version_label.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10, expand=False)
            else:
                self.update_output("ClamAV components 'clamscan' and 'freshclam' are missing.")
                self.update_output("Please install 'clamav' and restart the ClamAV GUI application.")
                self.scan_file_button.config(state='disabled')
                self.update_button.config(state='disabled')
                self.scan_directory_button.config(state='disabled')
                self.open_log_button.config(state='disabled')
                self.quarantine_infected_checkbox_button.config(state='disabled')
                self.delete_infected_checkbox_button.config(state='disabled')
                self.leave_it_checkbox_button.config(state='disabled')
                self.alarm_bell_checkbox_button.config(state='disabled')
                self.log_checkbox_button.config(state='disabled')
        except FileNotFoundError:
                self.update_output("Error app cant handle 'compgen' or 'grep' ")  # In the case where 'compgen' or 'grep' are missing or whatever
      
    def show_tooltip(self, event, text):
        x, y = self.window.winfo_pointerx(), self.window.winfo_pointery()
        if x != None and y != None:
            self.tooltip_window = tk.Toplevel(self.window)
            self.tooltip_window.wm_overrideredirect(True)
            self.tooltip_window.wm_geometry(f"+{x+10}+{y+10}")  # Position the tooltip window below the widget
            label = tk.Label(self.tooltip_window, text=text, bg="lightyellow", relief="solid", borderwidth=1)
            label.pack()

    def hide_tooltip(self):
        if hasattr(self, 'tooltip_window'):
            self.tooltip_window.destroy()

        
    def update_db(self):
        password = simpledialog.askstring("Enter Sudo Password", "Sudo password needed to update the ClamAV virus definitions.")
        if password is not None:
            self.update_output("--------------------")
            self.update_output("Updating database...")
            try:
                p = subprocess.Popen(f"echo '{password}' | sudo -S -k freshclam && exit", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = p.communicate()
                if p.returncode != 0:
                    self.update_output("Error updating database: wrong sudo password")
                    logging.error("Error updating database: wrong sudo password")
                else:
                    self.update_output("Database updated successfully")
                    result = subprocess.run("clamscan -V", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.clamav_version = result.stdout.decode().splitlines()[0]
                    self.version_label.config(text="ClamAV Version: " + self.clamav_version) 
                    logging.info("Database updated successfully")
            except subprocess.CalledProcessError as e:
                self.update_output(f"Error updating database: {e}")
                logging.error(f"Error updating database: {e}")
            except Exception as e:
                self.update_output(f"Error updating database: {e}")
                logging.error(f"Error updating database: {e}")

    def scan_directory(self):
        self.scan_in_progress = True
        self.cancel_button.config(state=tk.NORMAL)
        trash_directory = os.path.expanduser("~/.local/share/Trash/files")
        clamav_directory = os.path.expanduser("~/clamav-gui")
        self.update_output("--------------------")
        self.update_output("Scanning directory..")
        directory = filedialog.askdirectory()
        if not directory: # User cancelled
            self.scan_in_progress = False
            self.update_output("Scan canceled..")
            self.cancel_button.config(state=tk.DISABLED)
            return
        quoted_dir = f'"{directory}"'
        log_option = f'--log="{clamav_directory}/clamav_log.txt"' if self.log_checkbox.get() else ""
        if self.quarantine_infected_checkbox.get():
            self.process = subprocess.Popen(f"clamscan -r {log_option} --move={trash_directory} {quoted_dir}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif self.delete_infected_checkbox.get():
            self.process = subprocess.Popen(f"clamscan -r {log_option} --remove {quoted_dir}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            self.process = subprocess.Popen(f"clamscan -r {log_option} {quoted_dir}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        scan_summary = False
        while self.scan_in_progress:
            try:
                line = self.process.stdout.readline().decode('utf-8').strip()
                if line:
                    if line.startswith("----------- SCAN SUMMARY -----------"):
                        scan_summary = True
                        self.update_output(line)
                    else:
                        self.update_output(line)
            except:
                pass
            if scan_summary:
                count = 0
                while True:
                    try:
                        line = self.process.stdout.readline().decode('utf-8').strip()
                        if not line:
                            break
                        if line.startswith("----------- SCAN SUMMARY -----------"):
                            break
                        self.update_output(line)
                        count += 1
                        if count == 10:
                            break
                    except:
                        pass
            self.window.update()
            self.window.after(100)
        self.window.update()
        self.window.after(100)
        
    def scan_file(self):
        self.scan_in_progress = True
        self.cancel_button.config(state=tk.NORMAL)
        self.update_output("--------------------")
        self.update_output("Scanning file...")
        trash_directory = os.path.expanduser("~/.local/share/Trash/files")
        clamav_directory = os.path.expanduser("~/clamav-gui")
        file = filedialog.askopenfilename()
        if not file: # User cancelled
            self.scan_in_progress = False
            self.update_output("Scan canceled..")
            self.cancel_button.config(state=tk.DISABLED)
            return
        quoted_file = f'"{file}"'
        log_option = f'--log="{clamav_directory}/clamav_log.txt"' if self.log_checkbox.get() else ""
        if self.quarantine_infected_checkbox.get():self.process = subprocess.Popen(f"clamscan {log_option} --move={trash_directory} {quoted_file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif self.delete_infected_checkbox.get():self.process = subprocess.Popen(f"clamscan {log_option} --remove {quoted_file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:self.process = subprocess.Popen(f"clamscan {log_option} {quoted_file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        scan_summary= True
        while self.scan_in_progress:
            try:
                line = self.process.stdout.readline().decode('utf-8').strip()
                if line:
                    if line.startswith("----------- SCAN SUMMARY -----------"):
                        scan_summary = True
                        self.update_output(line)
                    else:
                        self.update_output(line)
            except:
                pass
            if scan_summary:
                count = 0
                while True:
                    try:
                        line = self.process.stdout.readline().decode('utf-8').strip()
                        if not line:
                            break
                        if line.startswith("----------- SCAN SUMMARY -----------"):
                            break
                        self.update_output(line)
                        count += 1
                        if count == 10:
                            break
                    except:
                        pass
            self.window.update()
            self.window.after(100)
        self.window.update()
        self.window.after(100)
        
    def cancel_scan(self):
        if self.process and self.scan_in_progress:
            self.update_output("Canceling scan...")
            self.process.terminate()  # Use terminate instead of kill
            self.scan_in_progress = False
            self.cancel_button.config(state=tk.DISABLED)
            self.update_output("Scan cancelled")
            
    def update_output(self, output):
        self.output_window.insert(tk.END, output + '\n')
        self.output_window.see(tk.END)
        if self.alarm_bell_checkbox.get():
            if re.search("FOUND", output):
                self.window.after(100)
                bell = os.path.expanduser("~/clamav-gui/bell.wav")
                self.output_window.tag_configure("red_alert", foreground="#FF0000")  # Define a tag
                self.output_window.insert(tk.END, "ALERT !!! ", "red_alert") # Insert with the tag
                self.update_output("")
                os.system("aplay {}".format(bell))

    def quarantine_infected_checkbox_callback(self):
        if self.quarantine_infected_checkbox.get():
            self.delete_infected_checkbox.set(False)
            self.leave_it_checkbox.set(False)
        else:
            self.delete_infected_checkbox.set(False)
            self.leave_it_checkbox.set(False)
            self.quarantine_infected_checkbox.set(True)

    def delete_infected_checkbox_callback(self):
        if self.delete_infected_checkbox.get():
            self.quarantine_infected_checkbox.set(False)
            self.leave_it_checkbox.set(False)
        else:
            self.quarantine_infected_checkbox.set(False)
            self.leave_it_checkbox.set(False)
            self.delete_infected_checkbox.set(True)

    def leave_it_checkbox_callback(self):
        if self.leave_it_checkbox.get():
            self.quarantine_infected_checkbox.set(False)
            self.delete_infected_checkbox.set(False)
        else:
            self.quarantine_infected_checkbox.set(False)
            self.delete_infected_checkbox.set(False)
            self.leave_it_checkbox.set(True)

    def alarm_bell_checkbox_callback(self):
        if self.alarm_bell_checkbox.get():
            self.update_output("Alarm bell is enable")
        else:
            self.update_output("Alarm bell is disable")
            
    def log_checkbox_callback(self):
        if self.log_checkbox.get():
            self.update_output("Log is enable")
        else:
            self.update_output("Log is disable")
    
    def open_clamav_log(self):
        log_file_path = os.path.expanduser("~/clamav-gui/clamav_log.txt")

        if not os.path.exists(log_file_path):
            self.update_output("ClamAV log file not found!")
            return  # Exit

        try:
            if os.name == 'posix':  # Linux
                os.system(f"xdg-open '{log_file_path}'") # Use xdg-open for cross-platform compatibility
        except Exception as e:
            self.update_output(f"Could not open log file: {e}")
        

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = ClamAVGUI()
    app.run()
