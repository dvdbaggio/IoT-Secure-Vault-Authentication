# main.py
import secrets
from source.config import VAULT_SIZE
from source.vault import SecureVault
from source.iot import IoTDevice, IoTServer

def run_auth_simulation():
    print("--- 1. System Setup ---")
    # Initialize identical vaults for Server and Device and a copy of keys to simulate them having the same shared secret
    initial_keys = [secrets.token_bytes(16) for _ in range(VAULT_SIZE)]
    
    server_vault = SecureVault(existing_keys=list(initial_keys)) 
    device_vault = SecureVault(existing_keys=list(initial_keys)) 
    
    server = IoTServer(server_vault)
    device = IoTDevice(device_vault)
    
    session_id = "SES_101"
    dev_id = "DEV_001"

    print(f"[Setup] Vaults initialized with {VAULT_SIZE} keys each.")

    print("\n--- 2. Authentication Handshake ---")
    
    # Step 1: M1 Device -> Server (Request)
    m1 = device.generate_M1(dev_id, session_id) 
    print(f"[Network] Device sent M1: {m1}")
    
    # Step 2: M2 Server -> Device (Challenge 1)
    m2 = server.receive_M1_generate_M2(m1['device_id'], m1['session_id'])
    print(f"[Network] Server sent Challenge C1 (M2)")
    
    # Step 3: M3 Device -> Server (Response 1 & Challenge 2)
    m3 = device.process_M2_generate_M3(m2)
    print(f"[Network] Device sent Encrypted Response & Challenge C2 (M3)")
    
    # Step 4: M4 Server -> Device (Response 2)
    m4 = server.receive_M3_generate_M4(session_id, m3)
    print(f"[Network] Server sent Encrypted Response (M4)")
    
    # Step 5: Device Processes M4 (Verification)
    device.process_M4(m4)

    # Final Verification
    if server.session_key == device.session_key:
        print(f"\n* SUCCESS: Mutual Authentication complete.")
        print(f"* Shared Session Key: {server.session_key.hex()[:20]}")
    else:
        print("\n* FAILURE: Session keys do not match.")

    # --- 3. Vault Update Phase ---
    print("\n--- 3. Vault Update Phase ---")
    
    # Mock session data exchanged during the session
    session_data = b"Temperature: 24.5C | Humidity: 77.7%"
    print(f"[App] Simulating session data exchange: {session_data}")
    
    # Both sides rotate their vaults independently using the same data
    server.vault.update_vault(session_data)
    device.vault.update_vault(session_data)
    
    # Verify that vaults are still synchronized
    if server.vault.keys == device.vault.keys:
        print("\n* SUCCESS: Vaults updated and remain synchronized.")
    else:
        print("\n* FAILURE: Vaults de-synchronized after update.")

if __name__ == "__main__":
    run_auth_simulation()