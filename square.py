from random import randbytes

import AES_128
from functools import reduce

# adish = True


KEY = b"AI powers world."
ROUNDS = 4


def create_active_set(constant_bytes: bytes) -> list[bytes]:
    # Generate a set of states with varying active byte at the first position.
    active_set = []
    for i in range(256):
        active_set.append(i.to_bytes(1, "big") + constant_bytes)
    return active_set


def generate_encrypted_set(key: bytes, num_rounds: int) -> list[bytes]:
    # Simulate an encryption oracle that encrypts the active set.
    active_set = create_active_set(randbytes(1) * 15)
    print(active_set)
    encrypted_set = []
    for state in active_set:
        encrypted_set.append(AES_128.encrypt(key, state, rounds=num_rounds))
    return encrypted_set



def reverse_last_round(guess_byte: bytes, byte_index: int, encrypted_set: list[bytes]) -> list[bytes]:
    
    #Reverse the final AES round using a guessed key byte at a specific index.
    
    assert len(guess_byte) == 1

    # Create a partial key with the guessed byte at the specified index
    partial_key = bytearray(16)
    partial_key[byte_index] = int.from_bytes(guess_byte, "big")
    partial_key = bytes(partial_key)

    # Reverse transformations for all states in the encrypted set
    return [
        AES_128.inverse_substitution_byte(AES_128.add_round_key_bytes(partial_key, state))
        for state in encrypted_set
    ]


def validate_guess(reversed_states: list[bytes], byte_index: int) -> bool:
    
    # Validate a guessed key byte by checking the balance property at the given index.

    extracted_bytes = [state[byte_index].to_bytes(1, "big") for state in reversed_states]
    return reduce(AES_128.xor_bytes, extracted_bytes) == b"\x00"


def find_possible_bytes(byte_index: int, encrypted_set: list[bytes]) -> set[bytes]:
    
    # Identify possible key bytes for a specific index by testing all candidates.
    
    return {
        candidate.to_bytes(1, "big")
        for candidate in range(256)
        if validate_guess(reverse_last_round(candidate.to_bytes(1, "big"), byte_index, encrypted_set), byte_index)
    }


def refine_key_guesses(candidate_keys: list[set[bytes]]) -> bytes:
    
    # Narrow down multiple guesses for each key byte to a single candidate.
    
    reconstructed_key = b""
    for index, possible_values in enumerate(candidate_keys):
        while len(possible_values) > 1:
            new_encrypted_set = generate_encrypted_set(KEY, ROUNDS)
            updated_candidates = find_possible_bytes(index, new_encrypted_set)
            possible_values.intersection_update(updated_candidates)
        reconstructed_key += possible_values.pop()
    return reconstructed_key




def recover_round_key() -> bytes:
    
    # Recover the AES round key for the last round using the SQUARE attack.
    
    encrypted_set = generate_encrypted_set(KEY, ROUNDS)
    print(encrypted_set)
    guessed_candidates = [find_possible_bytes(i, encrypted_set) for i in range(16)]
    print("$$$$",guessed_candidates)
    return refine_key_guesses(guessed_candidates)



def reverse_key_schedule(final_round_key: bytes, rounds: int = 10) -> bytes:
    
    # Reconstruct the original AES key by reversing the key expansion process.
    
    key_words = [final_round_key[i:i + 4] for i in range(0, 16, 4)][::-1]  # Reverse word order

    for round_num in range(rounds, 0, -1):
        base_index = (rounds - round_num) * 4
        for i in range(3):
            key_words.append(AES_128.xor_bytes(key_words[base_index + i], key_words[base_index + i + 1]))

        temp_word = AES_128.sub_word_bytes(AES_128.left_rotate_bytes(key_words[base_index + 4]))
        temp_word = AES_128.xor_bytes(temp_word, AES_128.rcon_bytes(round_num))
        key_words.append(AES_128.xor_bytes(temp_word, key_words[base_index + 3]))

    return b"".join(key_words[::-1][:4])



def execute_attack() -> bytes:
    
    # Perform the SQUARE attack to retrieve the original AES key.
    
    last_round_key = recover_round_key()
    return reverse_key_schedule(last_round_key, ROUNDS)


def main():
    # Entry point of the script. Executes the attack and validates the result.
    
    recovered_key = execute_attack()
    print(f"Recovered Key: {recovered_key}")
    print(f"Original Key: {KEY}")
    assert recovered_key == KEY, "Key recovery failed!"
    print("Key successfully recovered!")


if __name__ == "__main__":
    main()

