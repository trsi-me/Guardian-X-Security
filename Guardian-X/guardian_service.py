# -*- coding: utf-8 -*-
"""
Guardian-X Windows Service
--------------------------
Installs the edge agent as a Windows Service so it:
- Starts automatically when Windows boots
- Runs invisibly in the background
- Cannot be stopped or deleted by a regular user
- Requires Administrator rights to install/uninstall

INSTALL (run PowerShell as Administrator):
    pip install pywin32
    python guardian_service.py install
    python guardian_service.py start

UNINSTALL (run PowerShell as Administrator):
    python guardian_service.py stop
    python guardian_service.py remove
"""

import sys
import os
import time
import threading

# --- CONFIGURATION ---
WATCH_PATH = r"C:\Users\Dhai0\Documents"
SERVER_URL = "http://127.0.0.1:5000"
USER_ID    = "windows-service"
IGNORE_LIST = [".git", "__pycache__", "node_modules"]

AGENT_PATH = r"C:\Users\Dhai0\OneDrive\الصور\سطح المكتب\Guardian-X Security\Guardian-X\agent\edge_agent.py"

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import socket
except ImportError:
    print("ERROR: pywin32 not installed.")
    print("Run: pip install pywin32")
    sys.exit(1)


class GuardianXService(win32serviceutil.ServiceFramework):
    _svc_name_         = "GuardianXMonitor"
    _svc_display_name_ = "Guardian-X Security Monitor"
    _svc_description_  = (
        "Guardian-X behavioural anomaly detection agent. "
        "Monitors file system activity and sends events to the "
        "Guardian-X central analysis server in real time."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._running   = True
        self._thread    = None

    # ------------------------------------------------------------------ #
    # Service lifecycle                                                    #
    # ------------------------------------------------------------------ #

    def SvcStop(self):
        """Called by Windows Service Manager when stopping."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        """Main service entry point — runs the edge agent in a thread."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        self._thread = threading.Thread(target=self._run_agent, daemon=True)
        self._thread.start()

        # Keep service alive until stop is requested
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, "")
        )

    # ------------------------------------------------------------------ #
    # Agent runner                                                         #
    # ------------------------------------------------------------------ #
def _run_agent(self):
        import subprocess
        cmd = [
            sys.executable,
            AGENT_PATH,
            '--path', WATCH_PATH,
            '--server', SERVER_URL,
            '--user', USER_ID,
            '--insecure',
        ]
        try:
            servicemanager.LogInfoMsg(f"Guardian-X starting: {' '.join(cmd)}")
            proc = subprocess.Popen(cmd)
            while self._running:
                time.sleep(2)
            proc.terminate()
            proc.wait()
        except Exception as e:
            servicemanager.LogErrorMsg(f"Guardian-X error: {e}")

# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Running as service (called by Windows SCM)
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(GuardianXService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Running from command line: install / start / stop / remove
        win32serviceutil.HandleCommandLine(GuardianXService)
