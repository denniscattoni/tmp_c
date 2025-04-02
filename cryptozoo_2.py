#!/usr/bin/env python3
import pwn

HOST = "cyberchallenge.disi.unitn.it"
PORT = 50101
BLOCK_SIZE = 16

def apply_flips(ciphertext_hex, flips):
    data = bytearray.fromhex(ciphertext_hex)
    for offset, xor_val in flips:
        data[offset] ^= xor_val
    return data.hex()

def cryptozoo_2():
    conn = pwn.remote(HOST, PORT)

    # 1. Making the zoo
    conn.recvuntil(b"> ")
    conn.sendline(b"1")
    conn.recvuntil(b"> ")
    conn.sendline(b"abcdefghijkk")  #First animal
    conn.recvuntil(b"> ")
    conn.sendline(b"subberduckxbcdefghijklmnopq")  #Second animal

    # 2. Receiving ciphertext
    ciphertext_hex = None
    while True:
        line = conn.recvline(timeout=3)
        if not line:
            break
        decoded = line.decode(errors="replace").strip()
        print("[DEBUG]", decoded)
        if "Here's your zoo" in decoded:
            ciphertext_hex = decoded.split(": ")[1].strip()
            break

    if not ciphertext_hex:
        print("[-] Ciphertext not founded.")
        conn.close()
        return

    print(f"\n[+] Original Ciphertext:\n{ciphertext_hex}")

    # 3. Required bit flipping
    flips = [
        (37, ord("s")^ord("r")),   # 's' -> 'r'
        (47, ord("x")^ord("|")),   # 'x' -> '|'
        (69, ord("t")^ord("F")),   # 't' -> 'F'
        (75, ord("t")^ord("|"))    # 't' -> '|'
    ]

    # ord("t")^ord("F") (valore decimale del carattere all'interno della tabella ASCII)

    modified_ciphertext_hex = apply_flips(ciphertext_hex, flips)
    print(f"\n[+] Necessary Flips: {flips}")
    print(f"[+] Modified Ciphertext:\n{modified_ciphertext_hex}")

    # 4. Sending modified cipertext (view zoo)
    conn.recvuntil(b"> ")
    conn.sendline(b"2")
    conn.recvuntil(b"> ")
    conn.sendline(modified_ciphertext_hex.encode())

    # 5. Receiving the Flag
    response = conn.recvall(timeout=5)
    print("\n[+] Risposta del server:\n")
    print(response.decode(errors="replace"))
    conn.close()

if __name__ == "__main__":
    cryptozoo_2()

