# Built with AI assist
# Remote PC Health Toolkit (with auto-install of deps)
# Auto-installs, if missing and you agree: paramiko (SSH), pywinrm (WinRM), speedtest-cli (speed test)
# Notes: Some IoT devices (for example Roku) do not expose SSH/WinRM. You can ping but not read RAM/CPU.

import os
import sys
import platform
import socket
import subprocess
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, messagebox

APP_TITLE = "Remote PC Health Toolkit"
DEFAULT_SUBNET = "192.168.1.0/24"
PING_TIMEOUT_SEC = 1.5
SCAN_MAX_THREADS = 128


# ---------------------- Dependency Management ----------------------

class InstallLog(tk.Toplevel):
    def __init__(self, parent, title="Installing packages"):
        super().__init__(parent)
        self.title(title)
        self.geometry("640x360")
        self.resizable(True, True)
        self.text = tk.Text(self, wrap="word")
        self.text.pack(fill="both", expand=True)
        self.btn = ttk.Button(self, text="Close", command=self.destroy, state="disabled")
        self.btn.pack(pady=6)

    def append(self, line):
        self.text.insert("end", line + "\n")
        self.text.see("end")

    def enable_close(self):
        self.btn.config(state="normal")


class Deps:
    # Map: human-friendly name -> (import_name, pip_name, optional post-check command)
    CATALOG = {
        "paramiko": ("paramiko", "paramiko", None),
        "pywinrm": ("winrm", "pywinrm", None),
        "speedtest-cli": ("speedtest", "speedtest-cli", "speedtest --version"),
    }

    @staticmethod
    def is_installed(import_name):
        try:
            __import__(import_name)
            return True
        except Exception:
            return False

    @staticmethod
    def missing(required_keys):
        missing = []
        for key in required_keys:
            import_name = Deps.CATALOG[key][0]
            if not Deps.is_installed(import_name):
                missing.append(key)
        return missing

    @staticmethod
    def install(parent, keys):
        if not keys:
            return True
        log = InstallLog(parent, title="Installing required packages")
        log.append("Starting installation...")
        parent.update_idletasks()

        success = True
        for key in keys:
            import_name, pip_name, _ = Deps.CATALOG[key]
            cmd = [sys.executable, "-m", "pip", "install", pip_name]
            log.append(f"\n$ {' '.join(cmd)}")
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                for line in iter(proc.stdout.readline, ''):
                    log.append(line.rstrip())
                    parent.update_idletasks()
                proc.wait()
                if proc.returncode != 0:
                    log.append(f"[ERROR] pip exited with code {proc.returncode}")
                    success = False
                else:
                    # Re-check import
                    if not Deps.is_installed(import_name):
                        log.append(f"[ERROR] {pip_name} appears not importable after install.")
                        success = False
                    else:
                        log.append(f"[OK] {pip_name} installed.")
            except Exception as e:
                log.append(f"[EXCEPTION] {e}")
                success = False

        log.append("\nInstallation complete.")
        log.enable_close()
        return success


# ---------------------- Transport Layer ----------------------

class ExecResult:
    def __init__(self, ok, output):
        self.ok = ok
        self.output = output


class BaseTransport:
    def __init__(self, host):
        self.host = host

    def exec(self, command, timeout=10):
        raise NotImplementedError("exec not implemented")

    def describe(self):
        return "Base"


class LocalTransport(BaseTransport):
    def __init__(self):
        super().__init__("127.0.0.1")

    def exec(self, command, timeout=10):
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                text=True,
                shell=isinstance(command, str)
            )
            return ExecResult(True, completed.stdout.strip())
        except Exception as e:
            return ExecResult(False, f"Error: {e}")

    def describe(self):
        return "Local"


class SSHTransport(BaseTransport):
    def __init__(self, host, username, password=None, port=22, parent=None):
        super().__init__(host)
        self.username = username
        self.password = password
        self.port = port
        self._client = None
        self.parent = parent

    def _ensure_client(self):
        if self._client is not None:
            return
        # Ensure paramiko present
        if not Deps.is_installed("paramiko"):
            agree = messagebox.askyesno(
                "Missing dependency",
                "SSH requires 'paramiko'. Install it now?"
            )
            if agree:
                ok = Deps.install(self.parent, ["paramiko"])
                if not ok:
                    raise RuntimeError("Paramiko installation failed.")
            else:
                raise RuntimeError("Paramiko not installed.")
        import paramiko  # now safe
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.host, port=self.port, username=self.username,
                       password=self.password, timeout=10)
        self._client = client

    def exec(self, command, timeout=15):
        try:
            self._ensure_client()
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            out = stdout.read().decode(errors="ignore")
            err = stderr.read().decode(errors="ignore")
            text = out if out.strip() else err
            return ExecResult(True, text.strip())
        except Exception as e:
            return ExecResult(False, f"SSH error: {e}")

    def describe(self):
        return f"SSH {self.username}@{self.host}:{self.port}"


class WinRMTransport(BaseTransport):
    def __init__(self, host, username, password, port=5985, use_https=False, parent=None):
        super().__init__(host)
        self.username = username
        self.password = password
        self.port = port
        self.use_https = use_https
        self._session = None
        self.parent = parent

    def _ensure_session(self):
        if self._session is not None:
            return
        if not Deps.is_installed("winrm"):
            agree = messagebox.askyesno(
                "Missing dependency",
                "WinRM requires 'pywinrm'. Install it now?"
            )
            if agree:
                ok = Deps.install(self.parent, ["pywinrm"])
                if not ok:
                    raise RuntimeError("pywinrm installation failed.")
            else:
                raise RuntimeError("pywinrm not installed.")
        import winrm  # now safe
        proto = "https" if self.use_https else "http"
        endpoint = f"{proto}://{self.host}:{self.port}/wsman"
        self._session = winrm.Session(endpoint, auth=(self.username, self.password))

    def exec(self, command, timeout=20):
        try:
            self._ensure_session()
            r = self._session.run_cmd(command, timeout=timeout)
            out = (r.std_out or b"").decode(errors="ignore")
            err = (r.std_err or b"").decode(errors="ignore")
            code = r.status_code
            text = out if out.strip() else err
            return ExecResult(code == 0, text.strip())
        except Exception as e:
            return ExecResult(False, f"WinRM error: {e}")

    def describe(self):
        scheme = "HTTPS" if self.use_https else "HTTP"
        return f"WinRM {scheme} {self.username}@{self.host}:{self.port}"


# ---------------------- Utilities ----------------------

def is_local_ip(host):
    try:
        if host in ("127.0.0.1", "localhost"):
            return True
        local_ip = socket.gethostbyname(socket.gethostname())
        host_ip = socket.gethostbyname(host)
        return host_ip == local_ip
    except Exception:
        return False


def ping_once(ip):
    flag = "-n" if os.name == "nt" else "-c"
    timeout_flag = "-w" if os.name == "nt" else "-W"
    cmd = ["ping", flag, "1", timeout_flag, str(int(PING_TIMEOUT_SEC)), ip]
    try:
        completed = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=PING_TIMEOUT_SEC + 1, text=True
        )
        out = completed.stdout.lower()
        if "ttl=" in out or "bytes from" in out:
            return True
        return completed.returncode == 0
    except Exception:
        return False


def resolve_hostname(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def iter_ips_from_cidr(cidr):
    try:
        network, prefix = cidr.split("/")
        prefix = int(prefix)
        octets = [int(x) for x in network.split(".")]
        if len(octets) != 4 or prefix < 0 or prefix > 32:
            return []
        base = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        netaddr = base & mask
        size = 2 ** (32 - prefix)
        ips = []
        for i in range(1, size - 1):
            v = netaddr + i
            ip = f"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"
            ips.append(ip)
        return ips
    except Exception:
        return []


def format_timedelta(delta):
    days = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def parse_windows_datetime(raw):
    for ln in raw.splitlines():
        s = ln.strip()
        if s and s[:2].isdigit():
            try:
                core = s.split(".")[0]
                return datetime.strptime(core[:14], "%Y%m%d%H%M%S")
            except Exception:
                continue
    try:
        return datetime.fromisoformat(raw.strip())
    except Exception:
        pass
    raise ValueError("No datetime found")


# ---------------------- Commands to run on targets ----------------------

def detect_os_family(transport):
    if isinstance(transport, LocalTransport):
        sysname = platform.system().lower()
        if "windows" in sysname:
            return "windows"
        return "linux"

    probe = transport.exec("ver")
    if probe.ok and ("windows" in probe.output.lower() or "microsoft" in probe.output.lower()):
        return "windows"
    uname = transport.exec("uname")
    if uname.ok and uname.output:
        return "linux"
    return "linux"


def cmd_check_internet(os_family):
    if os_family == "windows":
        return "ping -n 1 8.8.8.8"
    return "ping -c 1 8.8.8.8"


def cmd_disk_usage(os_family):
    if os_family == "windows":
        return "wmic logicaldisk get DeviceID,Size,FreeSpace"
    return "df -h"


def cmd_uptime(os_family):
    if os_family == "windows":
        return 'powershell -NoProfile "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"'
    return "cat /proc/uptime || uptime -p"


def cmd_cpu_model(os_family):
    if os_family == "windows":
        return "wmic cpu get name"
    return "cat /proc/cpuinfo | grep -i 'model name' | head -n 1"


def cmd_mem_model(os_family):
    if os_family == "windows":
        return "wmic memorychip get Manufacturer,PartNumber,Speed,Capacity"
    return "cat /proc/meminfo | grep -i MemTotal"


def cmd_speedtest(os_family):
    return "speedtest --simple || speedtest-cli --simple"


# ---------------------- Tkinter App ----------------------

class DeviceRecord:
    def __init__(self, ip, hostname=""):
        self.ip = ip
        self.hostname = hostname

    def label(self):
        if self.hostname:
            return f"{self.ip}    {self.hostname}"
        return self.ip


class Credentials:
    def __init__(self):
        self.mode = "local"         # local, ssh, winrm
        self.username = ""
        self.password = ""
        self.port = 22
        self.use_https = False

    def describe(self):
        if self.mode == "local":
            return "Local"
        if self.mode == "ssh":
            return f"SSH user={self.username} port={self.port}"
        return f"WinRM user={self.username} port={'5986' if self.use_https else '5985'}"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("800x560")
        self.resizable(True, True)

        self.creds = Credentials()
        self.devices = []

        container = ttk.Frame(self, padding=10)
        container.pack(fill="both", expand=True)

        self.frames = {}
        for F in (ScanView, ActionsView, CredsDialogShim):
            frame = F(parent=container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("ScanView")

        # Startup: offer to install helpful but optional 'speedtest-cli'
        missing = Deps.missing(["speedtest-cli"])
        if missing:
            yes = messagebox.askyesno(
                "Optional component",
                "Speed test requires 'speedtest-cli'. Install it now?"
            )
            if yes:
                Deps.install(self, missing)


    def show_frame(self, name):
        self.frames[name].tkraise()

    def set_devices(self, devices):
        self.devices = devices

    def get_frame(self, name):
        return self.frames[name]


class ScanView(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        title = ttk.Label(self, text="Discover Devices on Network", font=("Segoe UI", 14, "bold"))
        title.pack(pady=8, anchor="w")

        topbar = ttk.Frame(self)
        topbar.pack(fill="x", pady=(0, 8))

        ttk.Label(topbar, text="Subnet (CIDR):").pack(side="left")
        self.subnet_var = tk.StringVar()
        self.subnet_var.set(DEFAULT_SUBNET)
        ttk.Entry(topbar, textvariable=self.subnet_var, width=24).pack(side="left", padx=6)

        self.scan_btn = ttk.Button(topbar, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=4)

        self.creds_btn = ttk.Button(topbar, text="Set Credentials", command=self.open_creds)
        self.creds_btn.pack(side="left", padx=4)

        self.creds_label = ttk.Label(topbar, text="Mode: Local")
        self.creds_label.pack(side="left", padx=10)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(self, textvariable=self.status_var).pack(anchor="w")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True)

        self.listbox = tk.Listbox(mid, height=16)
        self.listbox.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=sb.set)
        sb.pack(side="left", fill="y")

        right = ttk.Frame(self)
        right.pack(fill="x", pady=8)
        ttk.Button(right, text="Select Device and Continue", command=self.to_actions).pack(side="left")

        self.output = tk.Text(self, height=10)
        self.output.pack(fill="both", expand=False, pady=6)

        self._scan_thread = None

    def open_creds(self):
        frame = self.controller.get_frame("CredsDialogShim")
        frame.load_from_creds(self.controller.creds)
        self.controller.show_frame("CredsDialogShim")

    def start_scan(self):
        subnet = self.subnet_var.get().strip()
        if not subnet or "/" not in subnet:
            messagebox.showerror("Invalid subnet", "Enter a subnet like 192.168.1.0/24")
            return
        self.output.delete("1.0", "end")
        self.listbox.delete(0, "end")
        self.status_var.set("Scanning...")
        self.scan_btn.state(["disabled"])
        t = threading.Thread(target=self._scan_worker, args=(subnet,))
        t.daemon = True
        self._scan_thread = t
        t.start()
        self.after(200, self._check_scan_done)

    def _scan_worker(self, subnet):
        ips = iter_ips_from_cidr(subnet)
        found = []
        if not ips:
            self._scan_result = ([], "Invalid or unsupported subnet")
            return
        self._append_output(f"Scanning {len(ips)} addresses...")
        with ThreadPoolExecutor(max_workers=min(SCAN_MAX_THREADS, len(ips))) as pool:
            futures = {pool.submit(ping_once, ip): ip for ip in ips}
            count = 0
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    alive = fut.result()
                except Exception:
                    alive = False
                count += 1
                if alive:
                    name = resolve_hostname(ip)
                    found.append(DeviceRecord(ip, name))
                    self._append_output(f"Alive: {ip} {(' ' + name) if name else ''}")
                if count % 25 == 0:
                    self.status_var.set(f"Progress: {count}/{len(ips)}")
        self._scan_result = (found, None)

    def _append_output(self, text):
        def _append():
            self.output.insert("end", text + "\n")
            self.output.see("end")
        self.after(0, _append)

    def _check_scan_done(self):
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self.after(250, self._check_scan_done)
            return
        self.scan_btn.state(["!disabled"])
        res = getattr(self, "_scan_result", ([], None))
        devices, err = res
        if err:
            self.status_var.set("Error")
            self._append_output(f"Error: {err}")
            return
        self.controller.set_devices(devices)
        for d in devices:
            self.listbox.insert("end", d.label())
        self.status_var.set(f"Done. Found {len(devices)} device(s).")
        self.creds_label.config(text=f"Mode: {self.controller.creds.describe()}")

    def to_actions(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Select a device from the list")
            return
        idx = sel[0]
        device = self.controller.devices[idx]
        frame = self.controller.get_frame("ActionsView")
        frame.set_target(device, self.controller.creds)
        self.controller.show_frame("ActionsView")


class CredsDialogShim(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="Execution Credentials", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 8))

        frm = ttk.Frame(self)
        frm.pack(anchor="w")

        self.mode_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.port_var = tk.IntVar()
        self.https_var = tk.BooleanVar()

        ttk.Label(frm, text="Mode").grid(row=0, column=0, sticky="w")
        mode_row = ttk.Frame(frm)
        mode_row.grid(row=0, column=1, sticky="w")
        self.rb_local = ttk.Radiobutton(mode_row, text="Local", variable=self.mode_var, value="local")
        self.rb_ssh = ttk.Radiobutton(mode_row, text="SSH", variable=self.mode_var, value="ssh")
        self.rb_winrm = ttk.Radiobutton(mode_row, text="WinRM", variable=self.mode_var, value="winrm")
        self.rb_local.pack(side="left")
        self.rb_ssh.pack(side="left", padx=8)
        self.rb_winrm.pack(side="left")

        ttk.Label(frm, text="Username").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frm, textvariable=self.user_var, width=28).grid(row=1, column=1, sticky="w", pady=(8, 0))

        ttk.Label(frm, text="Password").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm, show="*", textvariable=self.pass_var, width=28).grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Port (SSH)").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.port_var, width=10).grid(row=3, column=1, sticky="w")

        ttk.Checkbutton(frm, text="WinRM over HTTPS (5986)", variable=self.https_var).grid(row=4, column=1, sticky="w", pady=(6, 0))

        btns = ttk.Frame(self)
        btns.pack(anchor="w", pady=10)
        ttk.Button(btns, text="Save", command=self.save).pack(side="left", padx=6)
        ttk.Button(btns, text="Back", command=self.back).pack(side="left", padx=6)

        self.note = tk.Text(self, height=9, width=90)
        self.note.pack(fill="x", pady=6)
        self._populate_note()

    def _populate_note(self):
        self.note.delete("1.0", "end")
        lines = [
            "Tips:",
            " • Local runs on this computer only. It is blocked for remote IPs.",
            " • SSH: for Linux/macOS targets. Ensure SSH is enabled. Example: sudo systemctl enable --now ssh",
            " • WinRM: for Windows targets. On target, run 'winrm quickconfig'.",
            " • Many IoT devices (for example Roku) do not support SSH or WinRM.",
        ]
        self.note.insert("end", "\n".join(lines))

    def load_from_creds(self, creds):
        self.mode_var.set(creds.mode)
        self.user_var.set(creds.username)
        self.pass_var.set(creds.password)
        self.port_var.set(creds.port)
        self.https_var.set(creds.use_https)

    def save(self):
        c = self.controller.creds
        c.mode = self.mode_var.get()
        c.username = self.user_var.get().strip()
        c.password = self.pass_var.get()
        c.port = int(self.port_var.get() or 22)
        c.use_https = bool(self.https_var.get())
        messagebox.showinfo("Saved", "Credentials saved")
        self.controller.show_frame("ScanView")

    def back(self):
        self.controller.show_frame("ScanView")


class ActionsView(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.device = None
        self.creds = None
        self.transport = None
        self.os_family = "linux"

        top = ttk.Frame(self)
        top.pack(fill="x")

        self.header_var = tk.StringVar()
        ttk.Label(top, textvariable=self.header_var, font=("Segoe UI", 13, "bold")).pack(side="left")

        ttk.Button(top, text="Back to Devices", command=self.back_to_scan).pack(side="right")

        info = ttk.Frame(self)
        info.pack(fill="x", pady=(6, 10))
        self.exec_label_var = tk.StringVar(value="")
        ttk.Label(info, textvariable=self.exec_label_var).pack(anchor="w")

        grid = ttk.Frame(self)
        grid.pack(fill="x")

        self.btn_inet = ttk.Button(grid, text="1. Check Internet Connection", command=self.run_check_internet)
        self.btn_disk = ttk.Button(grid, text="2. Check Disk Usage", command=self.run_disk)
        self.btn_uptime = ttk.Button(grid, text="3. Check System Uptime", command=self.run_uptime)
        self.btn_speed = ttk.Button(grid, text="4. Run Speed Test", command=self.run_speedtest)
        self.btn_cpu = ttk.Button(grid, text="5. Check CPU Model", command=self.run_cpu)
        self.btn_mem = ttk.Button(grid, text="6. Check Memory Model", command=self.run_mem)

        self.btn_inet.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        self.btn_disk.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        self.btn_uptime.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        self.btn_speed.grid(row=3, column=0, sticky="ew", padx=4, pady=4)
        self.btn_cpu.grid(row=4, column=0, sticky="ew", padx=4, pady=4)
        self.btn_mem.grid(row=5, column=0, sticky="ew", padx=4, pady=4)

        self.output = tk.Text(self, height=16)
        self.output.pack(fill="both", expand=True, pady=8)

    def set_target(self, device, creds):
        self.device = device
        self.creds = creds
        self.header_var.set(f"Target: {device.ip}   {device.hostname}")
        self.output.delete("1.0", "end")
        self.output.insert("end", "Detecting transport and OS...\n")
        try:
            if not is_local_ip(device.ip) and creds.mode == "local":
                self.output.insert("end",
                    "Selected device is remote but mode is Local.\n"
                    "Go back and open Set Credentials. Choose SSH for Linux/macOS or WinRM for Windows.\n"
                )
            self.transport = self._build_transport(device, creds)
            self.os_family = detect_os_family(self.transport)
            self.exec_label_var.set(f"Execute via: {self.transport.describe()}   OS: {self.os_family}")
            self.output.insert("end", "Ready.\n")
        except Exception as e:
            self.transport = None
            self.exec_label_var.set("Error initializing transport")
            self.output.insert("end", f"Transport error: {e}\n")

    def _build_transport(self, device, creds):
        if creds.mode == "local" and not is_local_ip(device.ip):
            raise RuntimeError(
                "Local mode runs only on this computer.\n"
                "Use SSH for Linux/macOS or WinRM for Windows to run on the selected device."
            )
        if is_local_ip(device.ip) or creds.mode == "local":
            return LocalTransport()
        if creds.mode == "ssh":
            if not creds.username:
                raise RuntimeError("SSH username is required. Set Credentials.")
            return SSHTransport(device.ip, creds.username, creds.password, port=creds.port, parent=self.controller)
        if creds.mode == "winrm":
            if not creds.username or not creds.password:
                raise RuntimeError("WinRM username and password are required. Set Credentials.")
            port = 5986 if creds.use_https else 5985
            return WinRMTransport(device.ip, creds.username, creds.password, port=port,
                                  use_https=creds.use_https, parent=self.controller)
        return LocalTransport()

    def back_to_scan(self):
        self.controller.show_frame("ScanView")

    def _run(self, command, postprocess=None, timeout=15):
        self.output.insert("end", f"\n$ {command}\n")
        self.output.see("end")
        if self.transport is None:
            self.output.insert("end", "No transport available.\n")
            return
        res = self.transport.exec(command, timeout=timeout)
        if not res.ok:
            self.output.insert("end", f"{res.output}\n")
            self.output.see("end")
            return
        out = res.output
        if postprocess is not None:
            try:
                out = postprocess(out)
            except Exception as e:
                out = f"Postprocess error: {e}\nRaw:\n{res.output}"
        self.output.insert("end", out + "\n")
        self.output.see("end")

    def run_check_internet(self):
        cmd = cmd_check_internet(self.os_family)
        def summarize(text):
            low = text.lower()
            if "ttl=" in low or "bytes from" in low or "time=" in low:
                return "Internet looks reachable.\n\n" + text
            return "No reply. Internet may be unreachable.\n\n" + text
        self._run(cmd, postprocess=summarize, timeout=8)

    def run_disk(self):
        self._run(cmd_disk_usage(self.os_family), timeout=15)

    def run_uptime(self):
        family = self.os_family
        if family == "windows":
            def parse_up(text):
                try:
                    dt = parse_windows_datetime(text)
                    delta = datetime.now() - dt
                    return f"Last boot: {dt}\nUptime: {format_timedelta(delta)}"
                except Exception:
                    return text
            self._run(cmd_uptime(family), postprocess=parse_up, timeout=10)
        else:
            def parse_lin(text):
                parts = text.strip().split()
                if parts and parts[0].replace(".", "", 1).isdigit():
                    try:
                        seconds = float(parts[0])
                        delta = timedelta(seconds=int(seconds))
                        return f"Uptime: {format_timedelta(delta)}\n\n{text}"
                    except Exception:
                        return text
                return text
            self._run(cmd_uptime(family), postprocess=parse_lin, timeout=8)

    def run_speedtest(self):
        if Deps.missing(["speedtest-cli"]):
            agree = messagebox.askyesno(
                "Missing dependency",
                "Speed test requires 'speedtest-cli'. Install it now?"
            )
            if agree:
                ok = Deps.install(self.controller, ["speedtest-cli"])
                if not ok:
                    self.output.insert("end", "speedtest-cli installation failed.\n")
                    return
            else:
                self.output.insert("end", "speedtest-cli not installed.\n")
                return
        self._run(cmd_speedtest(self.os_family), timeout=120)

    def run_cpu(self):
        def clean(text):
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if not lines:
                return text
            return lines[-1]
        self._run(cmd_cpu_model(self.os_family), postprocess=clean, timeout=10)

    def run_mem(self):
        self._run(cmd_mem_model(self.os_family), timeout=12)


# ---------------------- Main ----------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()
