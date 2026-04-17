# 🦥 LazyPwn 💥

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Kali](https://img.shields.io/badge/OS-Kali%20Linux-black)
![Asyncio](https://img.shields.io/badge/Arch-Async%20Event--Driven-success)

*English version below | [Versione Italiana più in basso](#-versione-italiana)*

---

IMPORTANT: some features have been tested only on one single CTF machine, if they do not work it's because the code hasn't been adapted or polished. Now you know.

## 🇬🇧 English Version

### What is this?
I built `LazyPwn` because I was tired of running the exact same 15 commands every time I spawn a Hack The Box machine. It's not an "auto-hacker" bloatware; it's an asynchronous, event-driven orchestrator written in Python. 

It does the boring reconnaissance for you in a couple of minutes, manages crashes gracefully, and prepares the exact templates and payloads you need to actually pwn the box. Less typing, more thinking.

### 🔥 Features
* **Blazing Fast Pipeline:** Uses `rustscan` to instantly grab ports, then feeds them to `nmap` for a deep, targeted scan (TCP & UDP). No more waiting 10 minutes for a `-p-` scan.
* **Smart Service Router:** Parses Nmap XMLs on the fly and asynchronously spins up specialized modules:
  * 🌐 **Web:** DNS Wildcard detection, VHOST fuzzing (`ffuf`), Directory hunting, and CVE scanning (`nuclei`).
  * 🏢 **AD & Windows:** Extracts domains, maps SMB shares, attempts LDAP anonymous binds/kerberoasting, and screams at you to use Certipy if it finds AD CS.
  * 🗄️ **MS-SQL:** Checks for weak auth and prepares you for NTLM coercion (`xp_dirtree`).
  * 🔑 **VPN:** Automatically attempts IKE Aggressive Mode PSK extraction.
  * 🛠️ **Infra:** Checks Anonymous FTP, DNS Zone Transfers, and exposed NFS shares.
* **Bulletproof State Manager (`state.json`):** VPN dropped? Accidentally hit `Ctrl+C`? LazyPwn remembers exactly where it left off. Relaunch it and it skips the tools that already finished.
* **Post-Exploitation Buddy (`--shell`):** Drops a local Python HTTP server to serve your tools (like LinPEAS) and gives you copy-paste ready commands to stabilize your dumb reverse shell.
* **Auto-Reporting (HR Flex):** Automatically generates a clean `REPORT.md` with open ports, discovered VHOSTs, and infra vulnerabilities. 

### ⚙️ Prerequisites
Tested on **Kali Linux 2026.1**. Make sure you have these in your `$PATH`:
`rustscan`, `nmap`, `netexec`, `ffuf`, `nuclei`, `gowitness`, `ike-scan`.

### 🚀 Usage

**1. The Recon Mode (Pwn Phase):**
Just pass the target IP. It creates a dedicated workspace folder (`htb_<ip>/`) for logs, loot, and reports.
```bash
python3 automation.py 10.10.11.10
```

2. The Post-Exploitation Mode (Shell Phase):
Got a reverse shell? Open a new tab and run this. It automatically grabs your tun0 IP, starts a web server in a tools/ directory, and prints your TTY stabilization cheatsheet.

```Bash
python3 automation.py --shell
```

## ⚠️ Legal Disclaimer
This tool, **LazyPwn**, was created **STRICTLY for educational purposes, Capture The Flag (CTF) events, and authorized penetration testing**. 

Any use of this tool for illegal, malicious, or unauthorized activities is strictly prohibited. The author assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by this tool. By using LazyPwn, you agree to take full responsibility for your actions. **At least during hacking, respect the law.**

🇮🇹 Versione Italiana
Che cos'è?
Ho scritto LazyPwn perché mi ero rotto di lanciare gli stessi 15 comandi a ogni avvio di una macchina su Hack The Box. Non è il classico script pieno di bloatware che promette di hackerare i server da solo; è un orchestratore asincrono e ad eventi, scritto in Python, iper-ottimizzato.

Fa la reconnaissance noiosa al posto tuo in un paio di minuti, gestisce i crash in modo elegante e ti prepara i payload e i template esatti per bucare la macchina. Meno tempo a digitare roba standard, più tempo a ragionare sulla vulnerabilità.

🔥 Features
Core Asincrono Velocissimo: Usa rustscan per estrarre le porte in 3 secondi e le passa a nmap per l'analisi profonda (TCP & UDP). Addio scansioni infinite.

Smart Service Router: Legge gli XML di Nmap al volo e lancia in parallelo moduli specializzati:

🌐 Web: Check per DNS Wildcard, fuzzing dei VHOST (ffuf), Directory hunting e scansione vulnerabilità (nuclei).

🏢 AD & Windows: Estrae domini, mappa le share SMB, tenta l'anonymous bind su LDAP/Kerberoasting e ti avvisa di checkare vulnerabilità ESC se c'è un AD CS.

🗄️ MS-SQL: Cerca credenziali deboli (guest/scott) e ti prepara la coercion NTLM (xp_dirtree).

🔑 VPN: Tenta in automatico l'estrazione dell'hash PSK via IKE Aggressive Mode.

🛠️ Infra: Controlla l'accesso Anonymous FTP, i DNS Zone Transfer e le share NFS esposte.

State Manager a prova di bomba (state.json): Ti cade la VPN? Sbagli a premere Ctrl+C? LazyPwn si ricorda dove si era fermato. Rilancialo e salterà le scansioni già fatte.

Supporto Post-Exploitation (--shell): Tira su un server HTTP locale per passarti i tool (es. LinPEAS) e ti stampa a schermo i comandi pronti da incollare per stabilizzare la TTY della tua reverse shell in bash.

Auto-Reporting (HR Flex): A fine run ti genera un REPORT.md pulitissimo con porte, VHOST scoperti e vulnerabilità infrastrutturali da allegare ai tuoi writeup.

⚙️ Prerequisiti
Testato su Kali Linux 2026.1. Assicurati di avere questi tool nel $PATH:
rustscan, nmap, netexec, ffuf, nuclei, gowitness, ike-scan.

🚀 Utilizzo
1. Modalità Recon (Fase di Pwn):
Passagli l'IP target. Creerà una cartella di workspace dedicata (htb_<ip>/) per i log, il loot e i report.

```Bash
python3 automation.py 10.10.11.10
2. Modalità Post-Exploitation (Fase Shell):
Hai ottenuto la reverse shell? Apri una nuova tab e lancia questo. Prende in automatico il tuo IP di tun0, avvia un web server nella cartella tools/ e ti spara a schermo il cheatsheet per stabilizzare la TTY.
```

```Bash
python3 automation.py --shell
```

## ⚠️ Avvertenze Legali
Questo strumento, **LazyPwn**, è stato sviluppato **ESCLUSIVAMENTE per scopi educativi, competizioni CTF (Hack The Box) e penetration test autorizzati**.

Qualsiasi utilizzo di questo tool per attività illegali, malevole o non autorizzate è severamente vietato. L'autore declina ogni responsabilità per eventuali danni diretti o indiretti, usi impropri o conseguenze legali derivanti dall'utilizzo di questo software. Utilizzando LazyPwn, ti assumi la totale responsabilità delle tue azioni. **Almeno qua, sii etico.**


Yes. AI helped me with cleaning and refining the README and the code, trust me, it was unreadable (e pieno di insulti, meglio evitare).