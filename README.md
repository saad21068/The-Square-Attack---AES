# The-Square-Attack---AES

# AES-128 Implementation and SQUARE Attack Simulation

## Overview
This repository contains two Python scripts that demonstrate advanced cryptographic concepts. It includes an implementation of the AES-128 encryption algorithm and a simulation of the SQUARE attack, showcasing the intricacies of cryptographic design and cryptanalysis.

- **AES_128.py**: Implements the AES-128 encryption algorithm, including key expansion, encryption, and decryption routines. The script allows flexibility in specifying the number of encryption rounds (up to 10).
- **square.py**: Simulates the SQUARE attack, a cryptanalysis method to recover AES keys using active sets and reverse engineering of the key schedule.

## Features
### AES_128.py
- Fully functional implementation of the AES-128 encryption algorithm.
- Modular design for key expansion, SubBytes, ShiftRows, MixColumns, and AddRoundKey steps.
- Support for user-defined encryption rounds (1-10) for enhanced customization.

### square.py
- Demonstrates the SQUARE attack for recovering AES keys by exploiting the balance property.
- Includes functions for:
  - Generating active sets of states.
  - Validating guesses using reverse transformations.
  - Refining key candidates to reconstruct the original AES key.
- Integrates with the AES implementation for seamless analysis and testing.

## Usage
### Prerequisites
- Python 3.7 or higher.
- Required libraries: `random`, `functools`.

### Running the AES Implementation
To encrypt a message using AES-128:
1. Open `AES_128.py`.
2. Modify the `encrypt` function call with your key and plaintext.
3. Run the script:
   ```bash
   python AES_128.py
