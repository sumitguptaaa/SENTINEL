from dataclasses import dataclass, field
import time


@dataclass
class MAVPacket:
	msgtype: 	str
	sysid:		int
	compid:		int
	timestamp: float = field(default_factory=time.time)
	payload:   dict  = field(default_factory=dict)

	def __repr__(self):
		return (
			f"MAVPacket(type={self.msgtype}, "
			f"sysid={self.sysid}, "
			f"compid={self.compid})"
		)

import threading
import queue
from pymavlink import mavutil


class MAVCapture:

    def __init__(self, connection_string: str):
        self._queue = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="MAVCapture"
        )
        self.connection_string = connection_string
        self.connection = None
        self.packet_count = 0

    def start(self):
        print(f"[SENTINEL] Connecting to {self.connection_string}...")
        self.connection = mavutil.mavlink_connection(
            self.connection_string
        )
        print("[SENTINEL] Waiting for HEARTBEAT...")
        self.connection.wait_heartbeat()
        print(
            f"[SENTINEL] Connected. "
            f"SysID={self.connection.target_system} "
            f"CompID={self.connection.target_component}"
        )
        self._capture_thread.start()
        print("[SENTINEL] Capture engine started.")

    def stop(self):
        print("[SENTINEL] Stopping...")
        self._stop_event.set()
        self._capture_thread.join(timeout=2.0)
        print("[SENTINEL] Stopped.")

    def get_packet(self, timeout: float = 1.0):
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _capture_loop(self):
        import time
        while not self._stop_event.is_set():
            raw_msg = self.connection.recv_match(
                blocking=False
            )
            if raw_msg is None:
                time.sleep(0.001)
                continue
            packet = MAVPacket(
                msgtype=raw_msg.get_type(),
                sysid=raw_msg.get_srcSystem(),
                compid=raw_msg.get_srcComponent(),
                timestamp=time.time(),
                payload=raw_msg.to_dict(),
            )
            try:
                self._queue.put_nowait(packet)
                self.packet_count += 1
            except queue.Full:
                pass
