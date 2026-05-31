import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


from pymavlink import mavutil
import time
import json

LOG_FILE = 'sentinel_alerts.json'
TRIALS   = 100

print("=" * 55)
print("  SENTINEL Evaluation Framework")
print("  Measures detection rate per rule")
print("=" * 55)
print()

conn = mavutil.mavlink_connection(
    'udpout:127.0.0.1:14550',
    source_system=99
)
print("[*] Evaluator connected as sysid 99")

def count_alerts(rule_name):
    if not os.path.exists(LOG_FILE):
        return 0
    count = 0
    with open(LOG_FILE) as f:
        for line in f:
            try:
                a = json.loads(line.strip())
                if a.get('rule') == rule_name:
                    count += 1
            except:
                pass
    return count

def evaluate(rule_name, attack_fn, wait=1.5):
    print(f"\n[EVAL] Testing {rule_name} — {TRIALS} trials...")
    detections = 0
    for i in range(TRIALS):
        before = count_alerts(rule_name)
        attack_fn()
        time.sleep(wait)
        after = count_alerts(rule_name)
        if after > before:
            detections += 1
        if (i+1) % 20 == 0:
            print(f"  [{i+1}/{TRIALS}] Detected: {detections}")
    rate = (detections / TRIALS) * 100
    print(f"  RESULT: {rate:.1f}% detection rate")
    return rate

print("\n[*] Waiting 35 seconds for SENTINEL learning phase...")
time.sleep(35)
print("[*] Starting evaluation...\n")

results = {}

# Rule 1 — Unknown Source
def atk_unknown():
    conn.mav.command_long_send(
        1, 1, 246, 0, 1, 0, 0, 0, 0, 0, 0
    )
results['UNKNOWN_SOURCE'] = evaluate('UNKNOWN_SOURCE', atk_unknown, 1.0)
# Rule 2 — Inflight DISARM
# We cannot arm SITL easily so we test the rule directly
# by checking the rule logic with a known armed state
print("\n[EVAL] Testing INFLIGHT_DISARM — 100 trials...")
print("  [NOTE] Testing with simulated armed state")
disarm_detections = 0
from sentinel.ids.rules import SentinelRulesEngine, Severity
from sentinel.core.capture import MAVPacket

for i in range(100):
    engine_test = SentinelRulesEngine()
    engine_test.is_learning = False
    engine_test.known_sysids = {1}
    engine_test.vehicle_armed = True
    
    pkt = MAVPacket(
        msgtype='COMMAND_LONG',
        sysid=1,
        compid=1,
        payload={'command': 400, 'param1': 0.0}
    )
    alerts = engine_test.analyse(pkt)
    if any(a.rule == 'INFLIGHT_DISARM' for a in alerts):
        disarm_detections += 1
    
    if (i+1) % 20 == 0:
        print(f"  [{i+1}/100] Detected: {disarm_detections}")

disarm_rate = (disarm_detections / 100) * 100
print(f"  RESULT: {disarm_rate:.1f}% detection rate")
results['INFLIGHT_DISARM'] = disarm_rate
# Rule 3 — Command Flood
def atk_flood():
    for i in range(60):
        conn.mav.command_long_send(
            1, 1, 246, i, 1, 0, 0, 0, 0, 0, 0
        )
        time.sleep(0.05)
results['COMMAND_FLOOD'] = evaluate('COMMAND_FLOOD', atk_flood, 2.0)

# Rule 4 — GPS Teleport
def atk_gps():
    # Send legitimate starting position first
    boot_ms = int(time.time() * 1000) % 4294967295
    conn.mav.global_position_int_send(
        boot_ms,
        int(-35.3632 * 1e7),
        int(149.1652 * 1e7),
        584000, 0, 0, 0, 0, 0
    )
    time.sleep(0.5)
    # Now teleport to Mumbai — 9000km jump
    boot_ms = int(time.time() * 1000) % 4294967295
    conn.mav.global_position_int_send(
        boot_ms,
        int(19.0760 * 1e7),
        int(72.8777 * 1e7),
        1000, 1000, 0, 0, 0, 0
    )
results['GPS_TELEPORT'] = evaluate('GPS_TELEPORT', atk_gps, 1.0)

# Rule 5 — Replay Attack
_seq = [0]
def atk_replay():
    conn.mav.command_long_send(
        1, 1, 246, _seq[0], 1, 0, 0, 0, 0, 0, 0
    )
    conn.mav.command_long_send(
        1, 1, 246, _seq[0], 1, 0, 0, 0, 0, 0, 0
    )
results['REPLAY_ATTACK'] = evaluate('REPLAY_ATTACK', atk_replay, 1.0)

# Rule 6 — Parameter Manipulation
def atk_param():
    conn.mav.param_set_send(
        1, 1,
        b'ATC_ANG_PIT_P',
        0.0,
        mavutil.mavlink.MAV_PARAM_TYPE_REAL32
    )
results['PARAM_MANIPULATION'] = evaluate(
    'PARAM_MANIPULATION', atk_param, 1.0
)

# Print results table
print("\n")
print("=" * 55)
print("  SENTINEL EVALUATION RESULTS")
print("=" * 55)
print(f"  {'Rule':<25} {'Rate':>8}  {'Status'}")
print("-" * 55)
for rule, rate in results.items():
    status = "PASS" if rate >= 80 else "NEEDS TUNING"
    print(f"  {rule:<25} {rate:>7.1f}%  {status}")
print("=" * 55)
print(f"  Trials per rule : {TRIALS}")
print(f"  Connection      : udpout:127.0.0.1:14550")
print(f"  Attacker sysid  : 99")
print(f"  Baseline sysid  : 1")
print("=" * 55)
