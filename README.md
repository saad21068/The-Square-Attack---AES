# The-Square-Attack---AES

# SQUARE Attack Simulation On AES-128

## Overview
This repository demonstrates the **SQUARE attack**, a cryptanalysis technique, by leveraging the AES-128 encryption algorithm. The repository includes two Python scripts:

- **AES_128.py**: Implements the AES-128 encryption algorithm, which is used as a target for cryptanalysis.
- **square.py**: Simulates the SQUARE attack to recover AES keys, utilizing the AES implementation from `AES_128.py`.

The project showcases both cryptographic construction and attack techniques, providing a hands-on understanding of the strengths and vulnerabilities of AES encryption.

---

## Features
### AES_128.py
- Comprehensive AES-128 implementation, including:
  - Key expansion.
  - SubBytes, ShiftRows, MixColumns, and AddRoundKey operations.
- Support for up to 10 encryption rounds, enabling custom cryptanalysis scenarios.

### square.py
- Fully automated simulation of the SQUARE attack.
- Features:
  - Active set generation for cryptanalysis.
  - Reverse engineering of AES round keys.
  - Validation and refinement of key guesses.
  - Recovery of the original AES key.

---

## Usage
### Prerequisites
- Python 3.7 or higher.
- Required libraries: `random`, `functools`.

### Running the SQUARE Attack
1. Ensure both `AES_128.py` and `square.py` are in the same directory.
2. Open `square.py` to verify or modify the constants:
   - **KEY**: The AES key used for encryption.
   - **ROUNDS**: Number of AES rounds for cryptanalysis.
3. Run the script:
   ```bash
   python square.py


