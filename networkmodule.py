import sys
import time
import json
import psutil
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, StringVar, IntVar

class KeyloggerDetector:
    def __init__(self, root):

        # GUI components

        self.root = root
        self.root.title("Keylogger Network Detector")
        self.root.geometry("800x600")
        
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.process_monitor_tab = ttk.Frame(self.tabs)
        self.ip_port_monitor_tab = ttk.Frame(self.tabs)
        self.process_list_tab = ttk.Frame(self.tabs)
        
        self.tabs.add(self.process_monitor_tab, text="Process Monitor")
        self.tabs.add(self.ip_port_monitor_tab, text="IP/Port Monitor")
        self.tabs.add(self.process_list_tab, text="Process List")
        
        self.setup_process_monitor_tab()
        self.setup_ip_port_monitor_tab()
        self.setup_process_list_tab()
        
        self.log_file = "keylogger_detection.log"
        
        self.is_monitoring = False
        self.monitor_thread = None
        
        self.update_process_list()
        self.root.after(10000, self.update_process_timer) 
    
    def update_process_timer(self):
        """update process list periodically"""
        self.update_process_list()
        self.root.after(10000, self.update_process_timer)
        
    def setup_process_monitor_tab(self):

        # process monitor GUI

        pid_frame = ttk.Frame(self.process_monitor_tab)
        pid_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(pid_frame, text="Process ID:").pack(side=tk.LEFT, padx=5)
        self.pid_input = ttk.Entry(pid_frame)
        self.pid_input.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.pid_select_btn = ttk.Button(pid_frame, text="Select from Process List", 
                                        command=self.show_process_list_tab)
        self.pid_select_btn.pack(side=tk.LEFT, padx=5)
        
        duration_frame = ttk.Frame(self.process_monitor_tab)
        duration_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(duration_frame, text="Monitoring Duration (seconds):").pack(side=tk.LEFT, padx=5)
        self.duration_input = tk.Spinbox(duration_frame, from_=10, to=300, width=5)
        self.duration_input.delete(0, tk.END)
        self.duration_input.insert(0, "60")
        self.duration_input.pack(side=tk.LEFT, padx=5)
        
        interface_frame = ttk.Frame(self.process_monitor_tab)
        interface_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(interface_frame, text="Network Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_var = StringVar(value="")  # Default value
        self.interface_input = ttk.Entry(interface_frame, textvariable=self.interface_var)
        self.interface_input.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        self.monitor_btn = ttk.Button(self.process_monitor_tab, text="Start Monitoring Process Connections",
                                     command=self.start_process_monitoring)
        self.monitor_btn.pack(padx=5, pady=5)
        
        ttk.Label(self.process_monitor_tab, text="Detected Connections:").pack(anchor=tk.W, padx=5, pady=2)
        
        table_frame = ttk.Frame(self.process_monitor_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        vscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.connections_table = ttk.Treeview(table_frame, 
                                    columns=("local", "remote", "action"),
                                    show="headings",
                                    yscrollcommand=vscroll.set)
        
        self.connections_table.heading("local", text="Local Address")
        self.connections_table.heading("remote", text="Remote Address")
        self.connections_table.heading("action", text="Action")

        self.connections_table.column("local", width=150, stretch=tk.YES)
        self.connections_table.column("remote", width=150, stretch=tk.YES)
        self.connections_table.column("action", width=100, stretch=tk.YES)
        
        vscroll.config(command=self.connections_table.yview)
        
        self.connections_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Label(self.process_monitor_tab, text="Log:").pack(anchor=tk.W, padx=5, pady=2)
        self.log_output = scrolledtext.ScrolledText(self.process_monitor_tab, height=10)
        self.log_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_output.config(state=tk.DISABLED)
        
    def setup_ip_port_monitor_tab(self):

        # ip/port monitoring GUI

        ip_port_frame = ttk.Frame(self.ip_port_monitor_tab)
        ip_port_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ip_port_frame, text="IP Address:").pack(side=tk.LEFT, padx=5)
        self.ip_input = ttk.Entry(ip_port_frame)
        self.ip_input.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        ttk.Label(ip_port_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_input = ttk.Entry(ip_port_frame, width=8)
        self.port_input.pack(side=tk.LEFT, padx=5)
        
        interface_frame = ttk.Frame(self.ip_port_monitor_tab)
        interface_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(interface_frame, text="Network Interface:").pack(side=tk.LEFT, padx=5)
        self.ip_interface_var = StringVar(value="")  
        self.ip_interface_input = ttk.Entry(interface_frame, textvariable=self.ip_interface_var)
        self.ip_interface_input.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        self.ip_monitor_btn = ttk.Button(self.ip_port_monitor_tab, text="Start Monitoring IP/Port",
                                       command=self.start_ip_port_monitoring)
        self.ip_monitor_btn.pack(padx=5, pady=5)
        
        ttk.Label(self.ip_port_monitor_tab, text="Log:").pack(anchor=tk.W, padx=5, pady=2)
        self.ip_log_output = scrolledtext.ScrolledText(self.ip_port_monitor_tab)
        self.ip_log_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ip_log_output.config(state=tk.DISABLED)
        
    def setup_process_list_tab(self):

        # Process list GUI

        search_frame = ttk.Frame(self.process_list_tab)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = StringVar()
        self.search_var.trace_add("write", self.filter_process_list)
        self.process_search = ttk.Entry(search_frame, textvariable=self.search_var)
        self.process_search.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        table_frame = ttk.Frame(self.process_list_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        vscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.process_table = ttk.Treeview(table_frame, 
                                columns=("pid", "name"),
                                show="headings",
                                yscrollcommand=vscroll.set)
        
        self.process_table.heading("pid", text="PID")
        self.process_table.heading("name", text="Name")

        self.process_table.column("pid", width=100, stretch=tk.YES)
        self.process_table.column("name", width=300, stretch=tk.YES)
        
        vscroll.config(command=self.process_table.yview)

        self.process_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.process_table.bind("<Double-1>", self.select_process)
        
        self.refresh_btn = ttk.Button(self.process_list_tab, text="Refresh Process List", 
                                     command=self.update_process_list)
        self.refresh_btn.pack(padx=5, pady=5)
    
    def update_process_list(self):
        """update the process list table"""
        try:
            # clear table
            for item in self.process_table.get_children():
                self.process_table.delete(item)
            
            # get processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    processes.append((proc.info['pid'], proc.info['name']))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # sort by PID
            processes.sort(key=lambda x: x[0])
            
            # add to table
            for pid, name in processes:
                self.process_table.insert("", tk.END, values=(pid, name))
                
            # apply filter if search text exists
            if self.search_var.get():
                self.filter_process_list()
                
        except Exception as e:
            self.log_message(f"Error updating process list: {str(e)}")
            
    
    def filter_process_list(self, *args):

        """filter the process list based on search text"""

        search_text = self.search_var.get().lower()
        
        # list all items
        for item in self.process_table.get_children():
            self.process_table.item(item, tags=())
        
        if search_text:
            # hide items that dont match
            for item in self.process_table.get_children():
                values = self.process_table.item(item)['values']
                match = False
                
                # convert values to strings for searching
                for value in values:
                    if search_text in str(value).lower():
                        match = True
                        break
                
                if not match:
                    self.process_table.item(item, tags=('hidden',))
            
            self.process_table.tag_configure('hidden', hide=True)
    
    def select_process(self, event):
        """handle process selection from the table"""
        selected_item = self.process_table.focus()
        if selected_item:
            pid = self.process_table.item(selected_item)['values'][0]
            self.pid_input.delete(0, tk.END)
            self.pid_input.insert(0, str(pid))
            self.tabs.select(0)  
    
    def show_process_list_tab(self):
        """switch to the process list tab"""
        self.tabs.select(2)
    
    def log_message(self, message, ip_tab=False):
        """write a message to the log file and update the GUI"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        try:
            with open(self.log_file, "a") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Error writing to log file: {str(e)}")
        
        # update the GUI
        if ip_tab:
            self.ip_log_output.config(state=tk.NORMAL)
            self.ip_log_output.insert(tk.END, log_entry + "\n")
            self.ip_log_output.see(tk.END)
            self.ip_log_output.config(state=tk.DISABLED)
        else:
            self.log_output.config(state=tk.NORMAL)
            self.log_output.insert(tk.END, log_entry + "\n")
            self.log_output.see(tk.END)
            self.log_output.config(state=tk.DISABLED)
    
    def start_process_monitoring(self):
        """start monitoring a process for connections"""
        if self.is_monitoring:
            messagebox.showwarning("Already Monitoring", 
                                  "A monitoring session is already in progress. Please stop it first")
            return
        
        try:
            pid = int(self.pid_input.get())
            duration = int(self.duration_input.get())
            
            # clear previous connections
            for item in self.connections_table.get_children():
                self.connections_table.delete(item)
            
            # start the monitoring in a separate thread
            self.is_monitoring = True
            self.monitor_btn.config(text="Stop Monitoring", command=self.stop_monitoring)
            
            self.log_message(f"Starting process connection monitoring for PID {pid} for {duration} seconds...")
            
            # create and start the worker thread
            self.monitor_thread = threading.Thread(
                target=self.process_monitor_worker,
                args=(pid, duration),
                daemon=True
            )
            self.monitor_thread.start()
            
        except ValueError:
            messagebox.showwarning("invalid Input", "Please enter a valid process ID.")
        except Exception as e:
            self.log_message(f"Error starting monitoring: {str(e)}")
    
    def connection_process_monitor(self, pid, duration):
        """monitor a process for connections"""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            self.root.after(0, lambda: self.log_message(f"Process: {process_name} (PID: {pid})"))
            self.root.after(0, lambda: self.log_message(f"Monitoring for new connections for {duration} seconds..."))
            
            seen_connections = set()
            start_time = time.time()
            stop_flag = False
            
            while time.time() - start_time < duration and not stop_flag and self.is_monitoring:
                try:
                    # get all system connections
                    system_connections = psutil.net_connections(kind='inet')
                    
                    # filter process
                    for conn in system_connections:
                        if conn.pid == pid and conn.raddr:  
                            conn_key = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                            
                            if conn_key not in seen_connections:
                                seen_connections.add(conn_key)
                                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                                
                                # update log and connections table in the main thread
                                self.root.after(0, lambda l=local_addr, r=remote_addr: self.add_connection(l, r))
                                self.root.after(0, lambda m=f"New connection detected: {local_addr} -> {remote_addr}": 
                                              self.log_message(m))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.log_message(f"error checking connections: {str(e)}"))
                
                # sleep before checking again
                time.sleep(1)
            
            if not seen_connections:
                self.root.after(0, lambda: self.log_message("No outbound connections detected during the monitoring period."))
            
            self.root.after(0, self.monitoring_finished)
            
        except psutil.NoSuchProcess:
            self.root.after(0, lambda: self.log_message(f"Error: Process with PID {pid} not found."))
            self.root.after(0, self.monitoring_finished)
        except psutil.AccessDenied:
            self.root.after(0, lambda: self.log_message(f"Error: Access denied when trying to access process with PID {pid}."))
            self.root.after(0, self.monitoring_finished)
        except Exception as e:
            self.root.after(0, lambda e=e: self.log_message(f"Error monitoring process: {str(e)}"))
            self.root.after(0, self.monitoring_finished)
    
    def add_connection(self, local_addr, remote_addr):
        """add a detected connection to the table"""
        item_id = self.connections_table.insert("", tk.END, values=(local_addr, remote_addr, "Monitor"))
        
        self.connections_table.tag_bind("clickable", '<ButtonRelease-1>', 
                                      lambda event: self.table_click_handler(event))
        
        self.connections_table.item(item_id, tags=("clickable",))
    
    def table_click_handler(self, event):
        """handle clicks on the connections table"""
        item_id = self.connections_table.identify_row(event.y)
        if not item_id:
            return
            
        column = self.connections_table.identify_column(event.x)
        
        # only respond to clicks in action column
        if column == '#3':
            # get values from the row
            values = self.connections_table.item(item_id)['values']
            if len(values) >= 2:
                remote_addr = values[1]
                self.monitor_connection(remote_addr)
    
    def monitor_connection(self, remote_addr):
        """monitor a specific connection for keylogger activity"""
        try:
            ip, port = remote_addr.split(":")
            self.ip_input.delete(0, tk.END)
            self.ip_input.insert(0, ip)
            self.port_input.delete(0, tk.END)
            self.port_input.insert(0, port)
            self.tabs.select(1)
        except Exception as e:
            self.log_message(f"error parsing connection address: {str(e)}")
    
    def start_ip_port_monitoring(self):
        """start monitoring a specific IP and port"""
        if self.is_monitoring:
            messagebox.showwarning("already Monitoring", 
                                  "A monitoring session is already in progress. Please stop it first.")
            return
        
        try:
            target_ip = self.ip_input.get()
            target_port = int(self.port_input.get())
            interface = self.ip_interface_input.get()
            
            self.is_monitoring = True
            self.ip_monitor_btn.config(text="Stop Monitoring", command=self.stop_monitoring)
            
            self.log_message(f"Starting IP/Port monitoring for {target_ip}:{target_port}...", True)
            
            self.monitor_thread = threading.Thread(
                target=self.ip_port_monitor_connection,
                args=(target_ip, target_port, interface),
                daemon=True
            )
            self.monitor_thread.start()
            
        except ValueError:
            messagebox.showwarning("Invalid Input", "Please enter a valid port number.")
        except Exception as e:
            self.log_message(f"Error starting monitoring: {str(e)}", True)
    
    def ip_port_monitor_connection(self, target_ip, target_port, interface):
        """monitor specific IP/port traffic"""

        ALERT_INTERVAL = 300 
        
        connection_data = {}
        self.stop_sniffing = False
        
        self.root.after(0, lambda: self.log_message("Starting keylogger network detection...", True))
        self.root.after(0, lambda: self.log_message(
            f"Monitoring for HTTP traffic to {target_ip}:{target_port}", True))
        
        def packet_callback(packet):
            """process each packet to detect keylogger traffic"""
            if self.stop_sniffing or not self.is_monitoring:
                return True 
                    
            if IP in packet and TCP in packet:
                source_ip = packet[IP].src
                
                # only processing packets that have a payload
                if Raw in packet:
                    payload = packet[Raw].load
                    current_time = time.time()
                    
                    if b"POST" in payload:
                        self.root.after(0, lambda: self.log_message(
                            f"HTTP POST request detected from {source_ip}", True))
                
                        ip_key = f"{source_ip}"
                        
                        # track this ip's POST timing
                        if ip_key not in connection_data:
                            connection_data[ip_key] = {
                                "timestamps": [current_time],
                                "alert_sent": False,
                                "last_alert_count": 0
                            }
                        else:
                            data = connection_data[ip_key]
                            data["timestamps"].append(current_time)
                            
                            # keep only recent timestamps
                            if len(data["timestamps"]) > 15:
                                data["timestamps"] = data["timestamps"][-15:]
                            
                            # check for patterns after 4 timestamps
                            if len(data["timestamps"]) >= 4:
                                
                                # intervals
                                intervals = [data["timestamps"][i] - data["timestamps"][i-1] 
                                            for i in range(1, len(data["timestamps"]))]
                                
                                mean_interval = sum(intervals) / len(intervals)
                                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                                std_dev = variance ** 0.5
                                cv = (std_dev / mean_interval) if mean_interval > 0 else float('inf')
                                
                                # check if this is the first alert
                                show_alert = False
                                if not data["alert_sent"]:
                                    show_alert = True
                                    data["alert_sent"] = True
                                    data["last_alert_count"] = len(data["timestamps"])
                                elif len(data["timestamps"]) >= data["last_alert_count"] + 4:
                                    show_alert = True
                                    data["last_alert_count"] = len(data["timestamps"])
                                
                                if cv < 0.2 and len(intervals) >= 3 and show_alert:

                                    self.root.after(0, lambda: self.log_message(
                                        f"Mean interval: {mean_interval:.2f} seconds", True))
                                    self.root.after(0, lambda: self.log_message(
                                        f"Standard deviation: {std_dev:.2f}", True))
                                    self.root.after(0, lambda: self.log_message(
                                        f"Coefficient of variation: {cv:.4f}", True))
                                    
                                    self.root.after(0, lambda: self.log_message(
                                        f"ALERT: Potential keylogger detected from {source_ip}!", True))
                                    self.root.after(0, lambda: self.log_message(
                                        "Evidence: Highly regular network behavior detected", True))
                                    self.root.after(0, lambda: self.log_message(
                                        f"Pattern: HTTP POST requests at {mean_interval:.2f} second intervals", True))
                                    self.root.after(0, lambda: self.log_message(
                                        f"Regularity: {cv:.4f} coefficient of variation", True))
        
        try:
            filter_str = f"host {target_ip} and port {target_port}"
            self.root.after(0, lambda: self.log_message(f"Using packet filter: {filter_str}", True))
            
            self.root.after(0, lambda: self.log_message(f"Listening on network interface: {interface}", True))
            
            sniff(filter=filter_str, iface=interface, prn=packet_callback, store=0, 
                 stop_filter=lambda p: self.stop_sniffing or not self.is_monitoring)
        except Exception as e:
            self.root.after(0, lambda e=e: self.log_message(f"Error in packet sniffing: {str(e)}", True))
        
        self.root.after(0, self.monitoring_finished)
    
    def stop_monitoring(self):
        """stop the current monitoring session"""
        if self.is_monitoring:
            self.is_monitoring = False
            self.stop_sniffing = True
            self.log_message("Stopping monitoring...", self.tabs.index("current") == 1)
            
    
    def monitoring_finished(self):
        """handle the completion of a monitoring session"""
        self.is_monitoring = False

        if self.tabs.index("current") == 0:  
            self.monitor_btn.config(text="Start Monitoring Process Connections", 
                                  command=self.start_process_monitoring)
        else:  
            self.ip_monitor_btn.config(text="Start Monitoring IP/Port",
                                     command=self.start_ip_port_monitoring)
        
        self.log_message("Monitoring finished.", self.tabs.index("current") == 1)

def main():
    root = tk.Tk()
    app = KeyloggerDetector(root)
    root.mainloop()

if __name__ == "__main__":
    main()