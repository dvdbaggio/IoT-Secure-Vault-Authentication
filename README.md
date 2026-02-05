# IoT Secure Vault Auth

A Python reference implementation and simulation of a lightweight mutual-authentication protocol proposed by [Shah et al.](https://ieeexplore.ieee.org/document/8455985/) for resource-constrained IoT devices based on synchronized "vaults" of secret keys.


## Usage
```bash
pip install -r requirements.txt
```

Run the simulation

```bash
python main.py
```

The script runs a full simulated handshake between an `IoTDevice` and an `IoTServer`, prints handshake progress, verifies session key agreement, and performs a vault update phase.

## Configuration
Simulation parameters can be adjusted in `config.py`, including key size, vault size, number of keys per challenge and AES block size.
