from dataclasses import dataclass, field
from enum import Enum
import time
import json


class Severity(Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    rule:        str
    severity:    Severity
    description: str
    sysid:       int
    timestamp:   float = field(default_factory=time.time)

    def to_dict(self):
        return {
            "rule":        self.rule,
            "severity":    self.severity.value,
            "description": self.description,
            "sysid":       self.sysid,
            "timestamp":   self.timestamp,
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __repr__(self):
        return (
            f"Alert(rule={self.rule}, "
            f"severity={self.severity.value}, "
            f"sysid={self.sysid})"
        )
import math
import time
from collections import defaultdict
from sentinel.core.capture import MAVPacket

LEARNING_DURATION  = 30.0
VELOCITY_THRESHOLD = 200.0
RATE_WINDOW        = 5.0
RATE_THRESHOLD     = 10.0
MAX_SEQ_HISTORY    = 1000


class SentinelRulesEngine:

    def __init__(self):
        self.start_time     = time.time()
        self.is_learning    = True
        self.known_sysids   = set()
        self.vehicle_armed  = False
        self.command_times  = defaultdict(list)
        self.last_position  = None
        self.last_pos_time  = None
        self.seen_sequences = defaultdict(set)
        self.packets_analysed = 0
        self.alerts_generated = 0

    def analyse(self, packet: MAVPacket) -> list:
        self.packets_analysed += 1

        if self.is_learning:
            elapsed = time.time() - self.start_time
            if elapsed >= LEARNING_DURATION:
                self.is_learning = False
                print(
                    f"[SENTINEL] Learning complete. "
                    f"Known sysids: {sorted(self.known_sysids)}. "
                    f"Detection active."
                )
            else:
                self._update_baseline(packet)
                return []

        self._update_baseline(packet)

        alerts = []
        alerts += self._rule1_unknown_source(packet)
        alerts += self._rule2_inflight_disarm(packet)
        alerts += self._rule3_command_flood(packet)
        alerts += self._rule4_gps_teleport(packet)
        alerts += self._rule5_replay_attack(packet)
        alerts += self._rule6_param_manipulation(packet)

        self.alerts_generated += len(alerts)
        return alerts

    def _update_baseline(self, packet: MAVPacket):
        if self.is_learning:
            self.known_sysids.add(packet.sysid)
        if packet.msgtype == 'HEARTBEAT':
            base_mode = packet.payload.get('base_mode', 0)
            self.vehicle_armed = bool(base_mode & 128)

    def _rule1_unknown_source(self, packet: MAVPacket) -> list:
        if packet.msgtype not in ('COMMAND_LONG', 'COMMAND_INT'):
            return []
        if packet.sysid in self.known_sysids:
            return []
        return [Alert(
            rule="UNKNOWN_SOURCE",
            severity=Severity.HIGH,
            description=(
                f"Command from UNKNOWN sysid {packet.sysid}. "
                f"Known: {sorted(self.known_sysids)}."
            ),
            sysid=packet.sysid
        )]

    def _rule2_inflight_disarm(self, packet: MAVPacket) -> list:
        if packet.msgtype not in ('COMMAND_LONG', 'COMMAND_INT'):
            return []
        if packet.payload.get('command', -1) != 400:
            return []
        if packet.payload.get('param1', 1.0) != 0.0:
            return []
        if not self.vehicle_armed:
            return []
        return [Alert(
            rule="INFLIGHT_DISARM",
            severity=Severity.CRITICAL,
            description=(
                f"DISARM from sysid {packet.sysid} "
                f"while vehicle ARMED. DRONE WILL CRASH."
            ),
            sysid=packet.sysid
        )]

    def _rule3_command_flood(self, packet: MAVPacket) -> list:
        if packet.msgtype not in ('COMMAND_LONG', 'COMMAND_INT'):
            return []
        now = packet.timestamp
        self.command_times[packet.sysid].append(now)
        cutoff = now - RATE_WINDOW
        self.command_times[packet.sysid] = [
            t for t in self.command_times[packet.sysid]
            if t > cutoff
        ]
        rate = len(self.command_times[packet.sysid]) / RATE_WINDOW
        if rate <= RATE_THRESHOLD:
            return []
        return [Alert(
            rule="COMMAND_FLOOD",
            severity=Severity.HIGH,
            description=(
                f"Flood from sysid {packet.sysid}: "
                f"{rate:.1f} cmd/s. Threshold: {RATE_THRESHOLD}."
            ),
            sysid=packet.sysid
        )]

    def _rule4_gps_teleport(self, packet: MAVPacket) -> list:
        if packet.msgtype != 'GLOBAL_POSITION_INT':
            return []
        lat = packet.payload.get('lat', 0) / 1e7
        lon = packet.payload.get('lon', 0) / 1e7
        now = packet.timestamp
        if self.last_position is None:
            self.last_position = (lat, lon)
            self.last_pos_time = now
            return []
        distance = self._haversine(
            self.last_position[0], self.last_position[1],
            lat, lon
        )
        elapsed = now - self.last_pos_time
        self.last_position = (lat, lon)
        self.last_pos_time = now
        if elapsed <= 0:
            return []
        velocity = distance / elapsed
        if velocity <= VELOCITY_THRESHOLD:
            return []
        return [Alert(
            rule="GPS_TELEPORT",
            severity=Severity.CRITICAL,
            description=(
                f"GPS teleport sysid {packet.sysid}: "
                f"{velocity:.1f} m/s implied. "
                f"Possible GPS spoofing."
            ),
            sysid=packet.sysid
        )]

    def _haversine(self, lat1, lon1, lat2, lon2) -> float:
        R = 6371000
        p1 = math.radians(lat1)
        p2 = math.radians(lat2)
        dp = math.radians(lat2 - lat1)
        dl = math.radians(lon2 - lon1)
        a = (math.sin(dp/2)**2 +
             math.cos(p1) * math.cos(p2) *
             math.sin(dl/2)**2)
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    def _rule5_replay_attack(self, packet: MAVPacket) -> list:
        if packet.msgtype not in ('COMMAND_LONG', 'COMMAND_INT'):
            return []
        seq = packet.payload.get('confirmation', None)
        if seq is None:
            return []
        sysid = packet.sysid
        if seq in self.seen_sequences[sysid]:
            return [Alert(
                rule="REPLAY_ATTACK",
                severity=Severity.MEDIUM,
                description=(
                    f"Duplicate seq {seq} from sysid {sysid}. "
                    f"Possible replay attack."
                ),
                sysid=sysid
            )]
        self.seen_sequences[sysid].add(seq)
        if len(self.seen_sequences[sysid]) > MAX_SEQ_HISTORY:
            self.seen_sequences[sysid] = set()
        return []

    def _rule6_param_manipulation(self, packet: MAVPacket) -> list:
        if packet.msgtype != 'PARAM_SET':
            return []
        if packet.sysid in self.known_sysids:
            return []
        param_id = packet.payload.get('param_id', 'UNKNOWN')
        param_value = packet.payload.get('param_value', 'UNKNOWN')
        return [Alert(
            rule="PARAM_MANIPULATION",
            severity=Severity.HIGH,
            description=(
                f"PARAM_SET from untrusted sysid {packet.sysid}: "
                f"'{param_id}' = {param_value}."
            ),
            sysid=packet.sysid
        )]
