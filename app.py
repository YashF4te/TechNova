"""
Entry point: simulates branch auth, encrypted transfer, and IDS alerts.
"""

import os
import json
import time
from tabulate import tabulate
from branches import BranchManager
from security import KeyManager, encrypt_bytes, decrypt_bytes
from ids import SimpleIDS
from utils import setup_logging, log_event

# Create logs directory
os.makedirs("logs", exist_ok=True)
setup_logging("logs/simulator.log")

# Load config
with open("config.json", "r") as f:
    config = json.load(f)

branches = config["branches"]
users = config["users"]
ids_threshold = config.get("ids_threshold", 3)
ids_window = config.get("ids_window_seconds", 60)

# Initialize key manager and IDS
km = KeyManager("keys")
ids = SimpleIDS(threshold=ids_threshold, window_seconds=ids_window)

# Initialize branches
bm = BranchManager(branches, users, key_manager=km)

def pretty_print_branches():
    table = [(b.name, b.location, b.keyfile) for b in bm.list_branches()]
    print(tabulate(table, headers=["Branch", "Location", "Key file"]))

def simulate():
    print("=== Branch Secure Transfer Simulator ===\n")
    pretty_print_branches()

    # 1) simulate logins
    print("\n-- Simulating logins --")
    log_event("SIM", "Simulation started")

    # Successful login
    ok, msg = bm.login("Mumbai", "alice", "alicepass")
    print("Login Mumbai/alice:", ok, msg)
    if not ok:
        ids.record_failed("Mumbai", "alice")

    # Failed logins to trigger IDS
    for i in range(4):
        ok, msg = bm.login("Bengaluru", "bob", "wrongpass")
        print(f"Attempt {i+1} Bengaluru/bob:", ok, msg)
        if not ok:
            ids.record_failed("Bengaluru", "bob")
        time.sleep(0.5)

    # Check IDS alerts
    alerts = ids.check_alerts()
    if alerts:
        print("\nIDS Alerts:")
        for a in alerts:
            print("-", a)
            log_event("IDS", a)

    # 2) Simulate secure message from Mumbai -> Pune
    print("\n-- Secure transfer Mumbai -> Pune --")
    sender = "Mumbai"
    receiver = "Pune"
    payload = {
        "type": "financial_report",
        "content": "Quarterly revenue: INR 2,34,56,789",
        "timestamp": time.time()
    }
    data_bytes = json.dumps(payload).encode("utf-8")

    # encrypt using sender's key (for simulation we encrypt with receiver's key so receiver can decrypt)
    receiver_key = km.load_key_for_branch(receiver)
    ciphertext = encrypt_bytes(receiver_key, data_bytes)

    # "transfer" => write to file (simulate SFTP)
    transfer_path = f"transfer_{sender}_to_{receiver}.bin"
    with open(transfer_path, "wb") as f:
        f.write(ciphertext)
    print("Encrypted payload written to", transfer_path)
    log_event("TRANSFER", f"{sender} -> {receiver} : {transfer_path}")

    # Receiver reads and decrypts
    with open(transfer_path, "rb") as f:
        received_ct = f.read()
    try:
        plain = decrypt_bytes(receiver_key, received_ct)
        print("Receiver decrypted payload:", json.loads(plain.decode("utf-8")))
        log_event("RECEIVE", f"{receiver} decrypted message from {sender}")
    except Exception as e:
        print("Decryption failed:", e)
        log_event("ERROR", f"Decryption failed at {receiver}: {e}")

    print("\nSimulation complete. Check logs in logs/simulator.log")

if __name__ == "__main__":
    simulate()
