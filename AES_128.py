# S-box for the SubBytes step in AES

sbox = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]
# Round constants for key expansion

round_const = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# Inverse Substitution Box (inverse S-box) for Decryption
inverse_sbox = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]

# Function to perform inverse SubBytes transformation
def inverse_substitution(text):
    for i in range(len(text)):
        for j in range(len(text[i])):
            text[i][j] = inverse_sbox_value(text[i][j])
    return text


def inverse_sbox_value(value):
    row = value // 16
    column = value % 16
    return inverse_sbox[row][column]

def inverse_substitution_byte(state):
    state = convert_bytes_to_state(state)
    state = inverse_substitution(state)
    return convert_state_to_bytes(state)

# Function to convert a hex string into a 4x4 matrix state representation in AES

def make_matrix_hex(hex_string):
    state = []
    for i in range(0, len(hex_string), 8):
        lst = []
        for j in range(i, i + 8, 2):
            lst.append(hex_string[j:j + 2])
        state.append(lst)
    # print(state)
    state = [[state[j][i] for j in range(len(state))] for i in range(len(state[0]))]
    # print(state)
    return state

# Function to convert a hex string matrix to an integer matrix

def convert_hex_to_int(hex_string_metrix):
    ls_int = []
    for i in range(len(hex_string_metrix)):
        lst = []
        for j in range(len(hex_string_metrix[i])):
            lst.append(int(hex_string_metrix[i][j], 16)) # Convert hex to integer
        ls_int.append(lst)
    return ls_int

# Function to convert an integer matrix back to hex string format

def convert_int_to_hex(int_of_metrix):
    ls_hex = []
    for i in range(len(int_of_metrix)):
        lst = []
        for j in range(len(int_of_metrix[i])):
            lst.append(format(int_of_metrix[i][j], '02x')) # Convert integer back to hex string
        # print(lst)
        ls_hex.append(lst)
    return ls_hex

# Function to left rotate a list used in key expansion
def left_rotate(lst):
    first_element = lst.pop(0)
    lst.append(first_element)
    return lst

# Function to perform AddRoundKey step by XOR operation with round key for every round
def add_round_key(plaintext, key):
    initial_round = []
    for i in range(4):
        lst = []
        for j in range(4):
            lst.append(plaintext[i][j] ^ key[i][j]) #Here is the Xor step
        initial_round.append(lst)
    return initial_round

def convert_state_to_bytes(state):
    # print("state in int: ", state)
    state = convert_int_to_hex(state)
    # print("state in hex: ", state)
    hex_state = ""
    for i in range(4):
        for j in range(4):
            hex_state += state[i][j]
    
    return bytes.fromhex(hex_state)

def convert_bytes_to_state(state):
    state = state.hex()
    ans = []
    for i in range(4):
        ans.append([])
        for j in range(4):
            ans[-1].append(state[(i * 4 + j) * 2: (i * 4 + j) * 2 + 2])

    return convert_hex_to_int(ans)

def convert_bytes_to_state_hex(state):
    state = state.hex()
    ans = []
    for i in range(4):
        ans.append([])
        for j in range(4):
            ans[-1].append(state[(i * 4 + j) * 2: (i * 4 + j) * 2 + 2])

    return ans


def convert_state_to_bytes_hex(state):
    
    hex_state = ""
    for i in range(4):
        for j in range(4):
            hex_state += state[i][j]
    
    return bytes.fromhex(hex_state)

def add_round_key_bytes(key, state):
    
    key = convert_bytes_to_state(key)
    state = convert_bytes_to_state(state)
    ans_state = add_round_key(state, key)
    ans =  convert_state_to_bytes(ans_state)
    # print(ans.hex())
    # print()
    return ans

def sub_word_bytes(word):
    word = str(word.hex())
    ans = ""
    for i in range(0, len(word), 2):
        temp = str(hex(sbox_value(int(word[i: i + 2], 16))))[2:]
        ans += "0" * (2 - len(temp)) + temp
    return bytes.fromhex(ans)

# XORS the bytes
def xor_bytes(a, b):
    return bytes(a[i] ^ b[i] for i in range(len(a)))

def rcon_bytes(i):
    return bytes([round_const[i - 1]]) + bytes(3)

# Left rotates the bytes
def left_rotate_bytes(word, shift = 1):
    state = word.hex()
    state = [int(state[i * 2: i * 2 + 2], 16) for i in range(4)]
    for i in range(shift):
        state = left_rotate(state)
    ans = ""
    for i in range(len(state)):
        temp = str(hex(state[i]))[2:]
        ans += "0" * (2 - len(temp)) + temp
    return bytes.fromhex(ans)
    

# Function to perform key expansion to generate all round keys
def key_expansion(key):
    key_matrix = key
    round_keys = []
    i = 0
    # Expanding the key to generate 44 words 4 words for each round key for 11 rounds
    while len(key_matrix) < 44:
        word = list(key_matrix[-1])
        # Every 4th word needs more trasformation
        if len(key_matrix) % 4 == 0:
            word = left_rotate(word) #1) Left rotating
            for j in range(len(word)):
                word[j] = sbox_value(word[j]) #2) Subsitition
            word[0] ^= round_const[i] #3) Xor Round Constant
            i += 1
        # Xor with previous 4th word to generate new word for another round
        for j in range(len(word)):
            word[j] = word[j] ^ key_matrix[-4][j]
        key_matrix.append(list(word))
    # Grouping the word 4 X 4 for each round key
    for i in range(11):
        round_keys.append(key_matrix[4 * i:4 * (i + 1)])
    return round_keys

# Function to perform the SubBytes step for substituting each byte using the AES S-box
def substitution(text):
    for i in range(len(text)):
        for j in range(len(text[i])):
            text[i][j] = sbox_value(text[i][j]) # subsituting values from S-Box
    return text


def sbox_value(value):
    row = value // 16
    column = value % 16
    return sbox[row][column]

# Function to perform the ShiftRows step
def shiftRows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

# Function to perform the MixColumns step
def mix_columns(state):
    fixed_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]
    mixed_state = []
    for i in range(4):
        result_lst = []
        for j in range(4):
            result = (
                    gf_multiply(fixed_matrix[i][0], state[0][j]) ^
                    gf_multiply(fixed_matrix[i][1], state[1][j]) ^
                    gf_multiply(fixed_matrix[i][2], state[2][j]) ^
                    gf_multiply(fixed_matrix[i][3], state[3][j])
            )
            result_lst.append(result)
        mixed_state.append(result_lst)
    return mixed_state

# Computes gf multiplication
def gf_multiply(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return result & 0xff

# Encryption function to perform AES encryption on plaintext with a given key and number of rounds
def encryption(plaintext, round_keys, n):
    state = add_round_key(plaintext, round_keys[0]) # Doing an initial AddRoundKey at the start considerd as Round 0

    for i in range(1, n):
        # print(f"\nAfter SubBytes (Round {i}):")
        state = substitution(state) # Doing Subsitution Operation
        
        state = shiftRows(state) # Doing ShiftRows Operation
        
        state = mix_columns(state) # Doing MixColoms Operation
        
        round_key_hex = convert_int_to_hex(round_keys[i])
        
        state = add_round_key(state, round_keys[i]) # Adding Round Key
        # print(f"\nAfter AddRoundKey (Round {i}):")
        rounds = convert_int_to_hex(state)
        
    state = substitution(state) # Doing Subsitution Operation
    
    state = shiftRows(state) # Doing ShiftRows Operation
    
    round_key_hex = convert_int_to_hex(round_keys[n])
    # for row in round_key_hex:
    #     print(row)
    ciphertext = add_round_key(state, round_keys[n]) # Adding Round Key
    
    return convert_int_to_hex(ciphertext)
    


# Main Fucntion
def encrypt(key, message, rounds = 10):
    # bytes.fromhex("61747461636b206174206461776e2121")
    # key = "0f1571c947d9e8590cb7add6af7f6798" # Key
    key = key.hex()
    plaintext = message.hex() # PlainText
    plaintext_metrix_hex = make_matrix_hex(plaintext) # Making Statr of hexadecimal of plaintext

    plaintext_of_int = convert_hex_to_int(plaintext_metrix_hex) # Plaintext Converted to Integer state

    key_metrix_hex = make_matrix_hex(key) # key state of Hexadecimal
    key_metrix_hex = [[key_metrix_hex[j][i] for j in range(len(key_metrix_hex))] for i in
                      range(len(key_metrix_hex[0]))]
    key = make_matrix_hex(key)
    # print("Key:- ")
    # for l in key:
    #     print(l)
    key_of_int = convert_hex_to_int(key_metrix_hex) # Converting key state of hex to Integer
    round_keys = key_expansion(key_of_int) # Doing the Key expansion to generate RoundKeys
    final_round_keys = []
    for l in range(len(round_keys)):
        keys = round_keys[l]
        keys = [[keys[j][i] for j in range(len(keys))] for i in range(len(keys[0]))]
        final_round_keys.append(keys)
    # print("\n")
    rounds_to_display = rounds
    # print("done")
    if(rounds_to_display>10):
        print("AES Input for round should be less than 10")
    else:
        Ciphertext = encryption(plaintext_of_int, final_round_keys, rounds_to_display) # Doing encryption to generate Ciphertext
        # print("done")
        ans = ""
        if (Ciphertext):
            # print("Final Cipher Text")
            for j in range(4):
                for el in range(4):
                    ans += Ciphertext[el][j]
            return bytes.fromhex(ans)

if __name__ == "__main__":
    hex_string = "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
    byte_data = bytes.fromhex(hex_string.replace(" ", ""))
    print(byte_data)

    hex_string = "0f1571c947d9e8590cb7add6af7f6798"
    byte_data = bytes.fromhex(hex_string)
    print(byte_data)

    message = b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10'
    key = b'\x0f\x15q\xc9G\xd9\xe8Y\x0c\xb7\xad\xd6\xaf\x7fg\x98'

    x = encrypt(key, message)
    print(x)
    print(x.hex())
