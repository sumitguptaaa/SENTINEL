"""
SENTINEL — MAVLink Capture Engine
Packet capture and parsing layer.
"""

from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class MAVPacket:
    """Parsed MAVLink packet with metadata."""
    msgtype:   str
    sysid:     int
    compid:    int
    timestamp: float = field(default_factory=time.time)
    payload:   dict  = field(default_factory=dict)

    def __repr__(self):
        return (f"MAVPacket(type={self.msgtype}, "
                f"sysid={self.sysid}, "
                f"ts={self.timestamp:.3f})")
