#!/usr/bin/env python3
import pwn

HOST = "cyberchallenge.disi.unitn.it"
PORT = 50100

def apply_bit_flips(ciphertext_hex, flips):
    modified = bytearray.fromhex(ciphertext_hex)
    for offset, xor_val in flips:
        modified[offset] ^= xor_val
    return modified.hex()

def cryptozoo():
    conn = pwn.remote(HOST, PORT)
    conn.recvuntil(b"> ")
    conn.sendline(b"1")
    conn.recvuntil(b"> ")
    conn.sendline(b"Gerris")
    conn.recvuntil(b"> ")
    conn.sendline(b"subberduck")
    conn.recvuntil(b"tamper with it:")
    ciphertext_hex = conn.recvline().strip().decode()
    print("[DEBUG] Original ciphertext:", ciphertext_hex)

    # Offsets IV
    flips = [
        (4, ord("G")^ord("F")),   # G -> F
        (15, ord("s")^ord("r")),  # s -> r
    ]


    modified_ciphertext = apply_bit_flips(ciphertext_hex, flips)
    print("[DEBUG] Modified ciphertext:", modified_ciphertext)

    conn.recvuntil(b"> ")
    conn.sendline(b"2")
    conn.recvuntil(b"> ")
    conn.sendline(modified_ciphertext.encode())
    final = conn.recvall(timeout=5)
    print("[DEBUG] Final response:\n", final.decode())
    conn.close()

if __name__ == "__main__":
    cryptozoo()

