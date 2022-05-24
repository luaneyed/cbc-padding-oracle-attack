import sys

from oracle_python_v1_2 import pad_oracle


def is_padding_correct(iv, block):
    """Return the padding is correct or not"""
    return pad_oracle(iv, block) == b'1'


def attack(c0, c1):
    original_iv_arr = to_byte_arr(c0)
    block_len = len(original_iv_arr)
    iv_arr = [0] * block_len
    iv_xor_plaintext = [0] * block_len

    for i in range(block_len - 1, -1, -1):
        for j in range(i + 1, block_len):
            iv_arr[j] = iv_xor_plaintext[j] ^ (block_len - i)

        iv_byte_candidates = []
        for iv_byte in range(256):
            iv_arr[i] = iv_byte
            if is_padding_correct(to_hex_string(iv_arr), c1):
                iv_byte_candidates.append(iv_byte)

        iv = next(i for i in iv_byte_candidates if i != original_iv_arr[block_len - 1])\
            if len(iv_byte_candidates) == 2\
            else iv_byte_candidates.pop()

        iv_xor_plaintext[i] = iv ^ (block_len - i)

    print(''.join(map(chr, remove_padding([iv_xor_plaintext[i] ^ original_iv_arr[i] for i in range(block_len)]))))


def remove_padding(arr):
    return arr[0:-arr[-1]]


def to_byte_arr(hex_string):
    return bytes.fromhex(hex_string[2:])


def to_hex_string(arr):
    return '0x' + ''.join(map(to_hex, arr))


def to_hex(n):
    return hex(n)[2:].rjust(2, '0')


if __name__ == "__main__":
    attack(sys.argv[1], sys.argv[2])
