<div align="center">

```text
 _                     ____
| |   __ _ _____   _  |  _ \__      ___ __
| |  / _` |_  / | | | | |_) \ \ /\ / / '_ \
| |___ (_| |/ /| |_| | |  __/ \ V  V /| | | |
|_____\__,_/___|\__, | |_|     \_/\_/ |_| |_|
                |___/
```

**Because typing `nmap` 500 times a week is boring.**

</div>

## 🤷‍♂️ What is this? / Che cos'è?

**[EN]** Look, I got tired of running the same commands every time I spun up a CTF or Boot2Root box. This isn't your standard corporate bloatware. It's a lazy, highly aggressive, context-aware framework born out of pure exhaustion. You point it at an IP, grab a coffee, and come back to a shiny HTML report and Discord pings with your loot. Less typing, more pwn.

**[IT]** Senti, mi ero palesemente rotto di lanciare gli stessi comandi ogni volta che avviavo una macchina CTF o Boot2Root. Questo non è il classico script pieno di bloatware aziendale pompato. È un framework pigro, altamente aggressivo e context-aware nato per pura disperazione. Lo punti contro un IP, ti prendi un caffè e torni trovandoti un report HTML scintillante e i ping su Discord o Slack con il bottino. Meno sbatti, più shell.

---

## ✨ Updated Features / Features Aggiornate

**[EN]** What's under the hood?
* **Blazing Fast Pipeline:** Async Nmap & Rustscan. Because we don't have all day.
* **Context-Aware Web Fuzzing:** Reads the room. Reacts with WAF evasion, Auto-CEWL (spits out dynamic wordlists based on the site text), skips DNS annoyances, and hunts VHOSTs via `crt.sh`.
* **Auto-Dumper & Secret Hunter:** Sucks out `.env` files automatically, then parses JS files in-memory to rip out JWTs and API keys before you can even blink.
* **Auto-Breach:** So it found some passwords? Cool. It instantly sprays them across SSH and SMB. Addio copy-paste.
* **Post-Exploitation Buddy (`--shell`):** Spins up a local HTTP server, generates C ELF reverse shells via MSFvenom on the fly, sets up Chisel pivoting, and drops TTY stabilization cheatsheets.
* **Quality of Life:** Features Auto-Chown (no more `sudo chown` to claim your own damn root-created results folder), hooks into Discord/Slack, and generates a pretty interactive HTML report.

**[IT]** Cosa c'è sotto il cofano?
* **Blazing Fast Pipeline:** Nmap asincrono e Rustscan. Perché non abbiamo tutto il giorno.
* **Context-Aware Web Fuzzing:** Legge la stanza. WAF evasion, Auto-CEWL (crea wordlist dinamiche), aggira il DNS e trova VHOST via crt.sh autonomamente.
* **Auto-Dumper & Secret Hunter:** Scarica i file `.env`, estrae JWT e API keys dai file JS in memoria appena li fiuta.
* **Auto-Breach:** Se trova password, fa spraying automatico su SSH e SMB. Addio ai copia-incolla infiniti.
* **Post-Exploitation Buddy (`--shell`):** Server HTTP locale, script per Pivoting con Chisel, reverse shell ELF in C generate al volo con MSFvenom e cheatsheet belli pronti per stabilizzare la maledetta TTY.
* **Quality of Life:** Auto-Chown (non devi più fare `sudo chown` a mano per riprenderti i file), Discord/Slack Webhooks nativi e report HTML interattivo per fingere di aver faticato.

---

## 🛠️ Prerequisites / Prerequisiti

**[EN]** Get these on your OS path:
**[IT]** Installa questa roba nel tuo PATH:

```bash
sudo apt update
sudo apt install nmap masscan ffuf nuclei gowitness netexec wpscan ike-scan wafw00f
sudo apt install seclists
```

---

## 💻 Usage / Utilizzo

**[EN/IT]** The basics. You need `sudo` because Nmap needs raw sockets for SYN scans. Don't complain. / Le basi. Ti serve `sudo` perché Nmap fa SYN scan. Muto e lancia.

```bash
# Esempio base - The lazy way
sudo python3 automation.py <IP>

# Esempio avanzato - The tryhard way
sudo python3 automation.py 10.10.11.200 --profile aggressive --webhook "https://discord.com/api/webhooks/..." --reset

# Post-exploitation Buddy - Im in, now what?
sudo python3 automation.py --shell
```

---

## ⚠️ DISCLAIMER: THE "IT WORKS ON MY MACHINE" CLAUSE / LA CLAUSOLA "DA ME FUNZIONA"

**[EN]** Listen to me very carefully: This script was calibrated, tweaked, and sweat over for highly specific environments—mostly Hack The Box **Season 9** machines. If you run it on a 1998 IBM mainframe, a toaster, or some random local CTF and it crashes harder than Windows ME... that sounds like a *you* problem. Zero support guaranteed. It works on my machine. ¯\_(ツ)_/¯

**[IT]** Ascoltami bene: questo script è stato calibrato, testato e sudato su macchine iper-specifiche, in particolare quelle della **Season 9 di Hack The Box**. Se lo lanci su un mainframe IBM del 1998, un tostapane o su una CTF a caso di paese e crasha malamente... non è un mio problema. Zero supporto garantito. Da me funziona benissimo. Fatti due domande. ¯\_(ツ)_/¯

---

## ⚖️ Legal Disclaimer / Avvertenze Legali

**[EN]** Written exclusively for educational purposes, authorized CTFs, and legal audits with explicit consent. I am not responsible if you do something highly illegal and go to jail because you pointed this broadly across the Internet. Be ethical. Stay out of prison.
**[IT]** Scritto per esclusivi scopi educativi ed uso autorizzato su reti con esplicito consenso. L'autore non è responsabile per i danni causati dall'uso illecito di questo framework. Sii etico e non farti arrestare.
