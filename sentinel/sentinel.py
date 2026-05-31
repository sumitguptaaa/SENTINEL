import json
import sys
import time
import signal
from colorama import Fore, Style, init

init(autoreset=True)

from sentinel.core.capture import MAVCapture
from sentinel.ids.rules import SentinelRulesEngine, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL.value: Fore.RED + Style.BRIGHT,
    Severity.HIGH.value:     Fore.YELLOW + Style.BRIGHT,
    Severity.MEDIUM.value:   Fore.CYAN,
    Severity.LOW.value:      Fore.GREEN,
}

BANNER = r"""
+----------------------------------------------------------+
|                                                          |
|   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     |
|   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     |
|   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     |
|   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     |
|   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗|
|   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝|
|                                                          |
|   Passive MAVLink Intrusion Detection System             |
|   VIMANA Aerospace Security Platform — Module 1          |
|   Counter-Terrorism Drone Security Research              |
|   github.com/sumitguptaaa/SENTINEL                       |
|                                                          |
+----------------------------------------------------------+
"""


def print_alert(alert):
    color = SEVERITY_COLORS.get(alert.severity.value, '')
    print(
        f"\n{color}"
        f"{'='*55}\n"
        f"  [{alert.severity.value}] {alert.rule}\n"
        f"  Time:  {time.strftime('%H:%M:%S')}\n"
        f"  SysID: {alert.sysid}\n"
        f"  {alert.description}\n"
        f"{'='*55}"
        f"{Style.RESET_ALL}"
    )


def run(
    connection_string='udp:0.0.0.0:14550',
    log_file='sentinel_alerts.json'
):
    print(Fore.GREEN + BANNER + Style.RESET_ALL)
    print(f"[*] Connection : {connection_string}")
    print(f"[*] Log file   : {log_file}")
    print(f"[*] Learning   : 30 seconds")
    print(f"[*] Rules      : 6 detection rules")
    print()

    capture = MAVCapture(connection_string)
    engine  = SentinelRulesEngine()

    def shutdown(sig, frame):
        print("\n[SENTINEL] Shutting down...")
        capture.stop()
        print(f"[SENTINEL] Packets analysed : {engine.packets_analysed}")
        print(f"[SENTINEL] Alerts generated : {engine.alerts_generated}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    capture.start()

    print(
        f"\n[SENTINEL] "
        f"{Fore.YELLOW}LEARNING PHASE{Style.RESET_ALL}"
        f" — 30 seconds. No alerts."
    )

    with open(log_file, 'a') as log:
        while True:
            packet = capture.get_packet(timeout=1.0)
            if packet is None:
                continue
            alerts = engine.analyse(packet)
            for alert in alerts:
                print_alert(alert)
                log.write(alert.to_json() + '\n')
                log.flush()


if __name__ == '__main__':
    conn = sys.argv[1] if len(sys.argv) > 1 else 'udp:0.0.0.0:14550'
    run(connection_string=conn)
