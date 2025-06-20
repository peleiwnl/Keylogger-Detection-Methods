"""
apihooking.py

an api-hooking module that injects Frida code into running processes
to capture Windows API calls. Comes with an implemented GUI.

"""

import sys
import os
import frida
import psutil
import pyautogui
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from threading import Thread
import time

class FridaMonitorGUI:
    def __init__(self, root):

        # GUI Components

        self.root = root
        self.root.title("API-Hook Monitoring")
        self.root.geometry("800x600")
        
        self.light_blue = "#e6f2ff"  
        self.lighter_blue = "#f0f8ff"  
        self.scrollbar_bg = "#b3d9ff"  
        self.scrollbar_fg = "#3399ff"  
        
        self.root.configure(bg=self.light_blue)
        
        self.session = None
        self.script = None
        self.monitoring = False
        self.detected_malicious = False
        self.current_pid = None
        
        self.style = ttk.Style()
        self.style.configure("TFrame", background=self.light_blue)
        self.style.configure("TLabelframe", background=self.light_blue)
        self.style.configure("TLabelframe.Label", background=self.light_blue)
        self.style.configure("TLabel", background=self.light_blue)
        
        self.style.configure("Custom.Vertical.TScrollbar", 
                             background=self.scrollbar_bg, 
                             arrowcolor=self.scrollbar_fg,
                             troughcolor=self.light_blue)
        
        main_frame = ttk.Frame(root, style="TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        left_frame = ttk.LabelFrame(main_frame, text="Process List", style="TLabelframe")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.process_tree = ttk.Treeview(left_frame, columns=("PID", "Name"), show="headings")
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Process Name")
        self.process_tree.column("PID", width=70)
        self.process_tree.column("Name", width=200)
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.process_tree.configure(style="Custom.Treeview")
        self.style.configure("Custom.Treeview", 
                             background=self.lighter_blue,
                             fieldbackground=self.lighter_blue)
        
        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", 
                                 command=self.process_tree.yview,
                                 style="Custom.Vertical.TScrollbar")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        right_frame = ttk.Frame(main_frame, style="TFrame")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        control_frame = ttk.LabelFrame(right_frame, text="Controls", style="TLabelframe")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        button_frame = ttk.Frame(control_frame, style="TFrame")
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.refresh_btn = ttk.Button(button_frame, text="Refresh Processes", command=self.refresh_processes)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.inject_btn = ttk.Button(button_frame, text="Inject Selected Process", command=self.inject_process)
        self.inject_btn.pack(side=tk.LEFT, padx=5)
        
        self.detach_btn = ttk.Button(button_frame, text="Detach", command=self.detach_process, state=tk.DISABLED)
        self.detach_btn.pack(side=tk.LEFT, padx=5)
        
        self.kill_btn = ttk.Button(button_frame, text="Kill Process", command=self.kill_process, state=tk.DISABLED)
        self.kill_btn.pack(side=tk.LEFT, padx=5)
        
        status_frame = ttk.Frame(right_frame, style="TFrame")
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: Ready", style="TLabel")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, padx=5)
        
        self.warning_label = ttk.Label(status_frame, text="MALICIOUS ACTIVITY DETECTED!", 
                                      foreground="red", font=("Arial", 12, "bold"), 
                                      background=self.light_blue)
        
        output_frame = ttk.LabelFrame(right_frame, text="Output Log", style="TLabelframe")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        output_text_frame = ttk.Frame(output_frame, style="TFrame")
        output_text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = tk.Text(output_text_frame, wrap=tk.WORD, bg=self.light_blue)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        output_scrollbar = tk.Scrollbar(output_text_frame, orient="vertical", 
                                        command=self.output_text.yview,
                                        bg=self.scrollbar_bg,
                                        troughcolor=self.light_blue,
                                        activebackground=self.scrollbar_fg)
        output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.configure(yscrollcommand=output_scrollbar.set)
        
        self.output_text.tag_configure("warning", foreground="red", font=("Arial", 10, "bold"))
        
        # populate the process list on startup
        self.refresh_processes()
    
    def log(self, message, warning=False):
        """add message to the output log"""
        if warning:
            # insert with warning tag for highlighting
            self.output_text.insert(tk.END, message + "\n", "warning")
            
            # if we detect malicious activity, show the warning label and enable kill button
            if not self.detected_malicious:
                self.detected_malicious = True
                self.warning_label.pack(side=tk.RIGHT, padx=5)
                self.kill_btn.config(state=tk.NORMAL)
                
                # show a popup with an option to kill the process
                self.warning_tab()
        else:
            self.output_text.insert(tk.END, message + "\n")
            
        self.output_text.see(tk.END)
    
    def warning_tab(self):
        """show a custom warning dialog with an option to kill the process"""
        if not self.current_pid:
            return
            
        try:
            process = psutil.Process(self.current_pid)
            process_name = process.name()
            
            warning_dialog = tk.Toplevel(self.root)
            warning_dialog.title("Malicious Activity Warning")
            warning_dialog.geometry("400x200")
            warning_dialog.grab_set()
            warning_dialog.configure(bg=self.light_blue)
            
            # warning icon and message
            frame = ttk.Frame(warning_dialog, padding=20, style="TFrame")
            frame.pack(fill=tk.BOTH, expand=True)
            icon_label = ttk.Label(frame, text="⚠️", font=("Arial", 24), style="TLabel")
            icon_label.pack(pady=10)
            msg_label = ttk.Label(frame, 
                text=f"WARNING: Process {process_name} (PID: {self.current_pid}) is using keyboard monitoring APIs!\n" +
                     f"This could be a keylogger or other malicious software.",
                wraplength=350, justify="center", style="TLabel")
            msg_label.pack(pady=10)
            
            btn_frame = ttk.Frame(frame, style="TFrame")
            btn_frame.pack(pady=10)
            
            kill_btn = ttk.Button(btn_frame, text="Kill Process", 
                command=lambda: [self.kill_process(), warning_dialog.destroy()])
            kill_btn.pack(side=tk.LEFT, padx=10)
            
            continue_btn = ttk.Button(btn_frame, text="Continue Monitoring", 
                command=warning_dialog.destroy)
            continue_btn.pack(side=tk.LEFT, padx=10)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            messagebox.showwarning("Warning", "Malicious activity detected but process information is no longer available.")
    
    def kill_process(self):
        """kill the currently monitored process"""
        if not self.current_pid:
            return
            
        try:
            # get the process
            process = psutil.Process(self.current_pid)
            process_name = process.name()
            
            # detach the script from the process and kill it
            if self.session:
                self.detach_process()
            process.kill()
            
            self.log(f"[!] Process {process_name} (PID: {self.current_pid}) has been terminated.", warning=True)
            self.current_pid = None
            self.kill_btn.config(state=tk.DISABLED)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            messagebox.showerror("Error", f"Could not kill process: {e}")
    
    def refresh_processes(self):
        """refresh the list of running processes"""
        # clearing existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # adding all running processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.process_tree.insert("", tk.END, values=(proc.info['pid'], proc.info['name']))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    
    def on_message(self, message, data):
        """callback for messages from Frida script"""
        if message['type'] == 'send':
            payload = message['payload']
            
            if "WARNING:" in payload:
                parts = payload.split("WARNING:")
                self.log("[*] " + parts[0])
                self.log("[!] WARNING:" + parts[1], warning=True)
            else:
                self.log("[*] " + payload)
                
        elif message['type'] == 'error':
            self.log("[!] " + message['stack'], warning=True)
    
    def inject_process(self):
        """inject the selected process with Frida"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to inject")
            return
        
        pid = int(self.process_tree.item(selection[0])['values'][0])
        process_name = self.process_tree.item(selection[0])['values'][1]
        
        try:
            # detach if already attached
            if self.session:
                self.detach_process()
            
            # reset malicious detection flag
            self.detected_malicious = False
            if self.warning_label.winfo_ismapped():
                self.warning_label.pack_forget()
            
            # store current PID for kill functionality
            self.current_pid = pid
            
            # attach to the target process
            self.session = frida.attach(pid)
            self.log(f"[*] Attached to process {process_name} (PID: {pid})")
            
            # read the hook script from file
            try:
                with open("hook.js", "r") as f:
                    script_code = f.read()
            except FileNotFoundError:
                messagebox.showerror("Error", "hook.js file not found in the current directory!")
                self.detach_process()
                return
            
            # create and load the script into the process
            self.script = self.session.create_script(script_code)
            self.script.on("message", self.on_message)
            self.script.load()
            self.log("[*] Hook injected. Monitoring API calls...")
            
            # update button states and status
            self.monitoring = True
            self.inject_btn.config(state=tk.DISABLED)
            self.detach_btn.config(state=tk.NORMAL)
            self.kill_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Status: Injected - Monitoring")
            
            self.root.after(1000, self.simulate_key_presses)
            
        except frida.ProcessNotFoundError:
            messagebox.showerror("Error", f"Process with PID {pid} not found!")
        except frida.InvalidOperationError as e:
            messagebox.showerror("Error", f"Invalid operation: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to inject process: {e}")
    
    def detach_process(self):
        """detach from the current process"""
        if self.session:
            self.session.detach()
            self.session = None
            self.script = None
            self.monitoring = False
            self.log("[*] Detached.")
            
            self.inject_btn.config(state=tk.NORMAL)
            self.detach_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Status: Ready")
    
    def simulate_key_presses(self):
        """simulate a single key press to check for API hooks"""
        if not self.monitoring:
            return
        
        # creating a separate thread for key simulation to avoid UI freezing
        def simulate_keys():
        
            self.log("[*] Starting automatic key press simulation...")
            self.status_label.config(text="Status: Simulating key press")
            
            # short delay before starting
            time.sleep(1)
            
            # test the 'a' key
            self.log("[*] Simulating key press: a")
            pyautogui.press('a')
            
            self.log("[*] Key simulation completed")
            self.log("[*] Monitoring complete")
            self.status_label.config(text="Status: Monitoring complete")
        
        # start the simulation thread
        Thread(target=simulate_keys, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = FridaMonitorGUI(root)
    root.mainloop()