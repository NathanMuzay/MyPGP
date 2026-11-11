"""AES-128/192/256 : blocs de 16 octets, sans bibliothèque externe.

L'état AES est rangé colonne par colonne. L'interface du sujet représente
la clé et le chiffré en little-endian par mots de 32 bits.
"""

BLOCK_SIZE = 16
KEY_SIZES = (16, 24, 32)

# Table SubBytes définie par FIPS 197.
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_inverse = [0] * 256
for _index, _value in enumerate(SBOX):
    _inverse[_value] = _index
INV_SBOX = bytes(_inverse)
del _inverse, _index, _value


def _multiply(a, b):
    """Multiplication dans GF(2^8), modulo le polynôme AES 0x11b."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11b if a & 0x80 else 0)) & 0xff
        b >>= 1
    return result


def _expand_key(key):
    """Développe la clé en Nr + 1 clés de tour (Nr = Nk + 6)."""
    if len(key) not in KEY_SIZES:
        raise ValueError("AES requires a 16-, 24- or 32-byte key")
    key_size = len(key)
    expanded_size = BLOCK_SIZE * (key_size // 4 + 7)
    expanded = list(key)
    rcon = 1
    while len(expanded) < expanded_size:
        word = expanded[-4:]
        if len(expanded) % key_size == 0:
            word = [SBOX[value] for value in word[1:] + word[:1]]
            word[0] ^= rcon
            rcon = _multiply(rcon, 2)
        elif key_size == 32 and len(expanded) % key_size == 16:
            word = [SBOX[value] for value in word]
        for value in word:
            expanded.append(expanded[-key_size] ^ value)
    return [expanded[i:i + BLOCK_SIZE] for i in range(0, expanded_size, BLOCK_SIZE)]


def _add_round_key(state, key):
    return [value ^ mask for value, mask in zip(state, key)]


def _shift_rows(state, inverse=False):
    direction = -1 if inverse else 1
    return [state[4 * ((column + direction * row) % 4) + row]
            for column in range(4) for row in range(4)]


def _mix_columns(state, inverse=False):
    coefficients = (14, 11, 13, 9) if inverse else (2, 3, 1, 1)
    result = []
    for column in range(4):
        values = state[4 * column:4 * column + 4]
        for row in range(4):
            value = 0
            for index in range(4):
                value ^= _multiply(values[index], coefficients[(index - row) % 4])
            result.append(value)
    return result


def _little_endian_words(data):
    """Inverse chaque mot de quatre octets (conversion réversible)."""
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


def _validate(data, key, block_mode, decrypting=False):
    if len(key) not in KEY_SIZES:
        raise ValueError("AES requires a 16-, 24- or 32-byte key")
    if block_mode and len(data) != BLOCK_SIZE:
        raise ValueError("AES block mode requires exactly 16 message bytes")
    if decrypting and len(data) % BLOCK_SIZE:
        raise ValueError("AES ciphertext must contain complete 16-byte blocks")


# Chiffrement

def _encrypt_block(block, round_keys):
    """Cœur AES standard : un bloc, sans conversion de représentation."""
    state = _add_round_key(block, round_keys[0])
    rounds = len(round_keys) - 1
    for round_number in range(1, rounds + 1):
        state = [SBOX[value] for value in state]
        state = _shift_rows(state)
        if round_number != rounds:
            state = _mix_columns(state)
        state = _add_round_key(state, round_keys[round_number])
    return bytes(state)


def encrypt(data, key, block_mode=False):
    """Chiffre bloc par bloc et complète le dernier bloc avec des zéros."""
    _validate(data, key, block_mode)
    round_keys = _expand_key(_little_endian_words(key))
    result = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE].ljust(BLOCK_SIZE, b"\x00")
        result.extend(_little_endian_words(_encrypt_block(block, round_keys)))
    return bytes(result)


# Déchiffrement

def _decrypt_block(block, round_keys):
    """Inverse les tours AES pour retrouver un bloc clair."""
    rounds = len(round_keys) - 1
    state = _add_round_key(block, round_keys[rounds])
    for round_number in range(rounds - 1, -1, -1):
        state = _shift_rows(state, inverse=True)
        state = [INV_SBOX[value] for value in state]
        state = _add_round_key(state, round_keys[round_number])
        if round_number != 0:
            state = _mix_columns(state, inverse=True)
    return bytes(state)


def decrypt(data, key, block_mode=False):
    """Déchiffre des blocs complets et conserve les zéros de padding."""
    _validate(data, key, block_mode, decrypting=True)
    round_keys = _expand_key(_little_endian_words(key))
    result = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        block = _little_endian_words(data[offset:offset + BLOCK_SIZE])
        result.extend(_decrypt_block(block, round_keys))
    return bytes(result)
