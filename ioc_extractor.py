#!/usr/bin/env python3
import shlex
import requests
import time
import argparse
import subprocess
import os
import sys
import hashlib
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from prettytable import PrettyTable
import sqlite3

config = configparser.ConfigParser()
config.optionxform = str
config.read('tools.ini')

# Global Docker configuration variables (IaC)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCKER_IMAGE_FASE1 = "static-analysis:latest"
DOCKER_IMAGE_FASE3 = "memory-forensics:latest"

# -------------------------
# Phase 1: Static Analysis
# -------------------------
def run_tool(command, output_file=None, output_folder=None):
    """Local execution runner (for non-dockerized tools such as strings or curl)"""
    print(f"Executing local command: {command}")
    result = subprocess.run(shlex.split(command) if isinstance(command, str) else command, capture_output=True, text=True)
    if output_file and output_folder:
        output_path = os.path.join(output_folder, output_file)
        with open(output_path, 'w') as f:
            f.write(result.stdout)
    return result.stdout

def run_tool_docker_phase1(cmd_inside_container, file_path, output_folder, output_file=None):
    """Centralized wrapper to run static analysis tools inside Docker containers"""
    input_dir = os.path.dirname(os.path.abspath(file_path))
    filename = os.path.basename(file_path)
    out_dir = os.path.abspath(output_folder)
    
    os.makedirs(out_dir, exist_ok=True)
    # DEVOPS: Temporarily grant write permissions to avoid Rootless Docker permission issues
    os.chmod(out_dir, 0o777) 
    
    docker_cmd = (
        f"MALWARE_INPUT_DIR='{input_dir}' "
        f"ANALYSIS_OUTPUT_DIR='{out_dir}' "
        f"docker compose run --rm static-analysis "
        f"{cmd_inside_container.format(input_file='/input/' + filename)}"
    )
    print(f"Executing compose: {docker_cmd}")
    
    # DEVOPS: Set Rootless Docker UID 999 to avoid SSH session permission failures
    import os
    os.environ["XDG_RUNTIME_DIR"] = "/run/user/999"
    os.environ["DOCKER_HOST"] = "unix:///run/user/999/docker.sock"
    
    # shlex.split() elimina la vulnerabilidad de inyección de comandos al no usar shell=True
    print(f"Executing compose seguro: {docker_cmd}")
    result = subprocess.run(shlex.split(docker_cmd), capture_output=True, text=True)

    
    if output_file:
        output_path = os.path.join(output_folder, output_file)
        with open(output_path, 'w') as f:
            f.write(result.stdout)
    return result.stdout

def avclass(file_path, output_folder, api_key):
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    sha256 = sha256_hash.hexdigest()
    vt_command = f"curl -s https://www.virustotal.com/api/v3/files/{sha256} --header 'X-Apikey: {api_key}'"
    run_tool(vt_command, output_file='virustotal_result.txt', output_folder=output_folder)
    
    out_dir = os.path.abspath(output_folder)
    os.chmod(out_dir, 0o777)
    
    # AVClass reads the previously downloaded VT JSON using Docker Compose
    docker_cmd = f"ANALYSIS_OUTPUT_DIR='{out_dir}' docker compose run --rm static-analysis avclass -f /output/virustotal_result.txt"
    print(f"Executing compose: {docker_cmd}")
    
    # DEVOPS: Set Rootless Docker UID 999 to avoid SSH session permission failures
    import os
    os.environ["XDG_RUNTIME_DIR"] = "/run/user/999"
    os.environ["DOCKER_HOST"] = "unix:///run/user/999/docker.sock"
    
    # shlex.split() elimina la vulnerabilidad de inyección de comandos al no usar shell=True
    print(f"Executing compose seguro: {docker_cmd}")
    result = subprocess.run(shlex.split(docker_cmd), capture_output=True, text=True)

    
    output_path = os.path.join(output_folder, 'avclass_result.txt')
    with open(output_path, 'w') as f:
        f.write(result.stdout)
    return result.stdout

def capa(file_path, output_folder):
    return run_tool_docker_phase1("capa -v {input_file}", file_path, output_folder, 'capa_result.txt')

def floss(file_path, output_folder):
    return run_tool_docker_phase1("floss --minimum-length 7 {input_file}", file_path, output_folder, 'floss_result.txt')

def exiftool(file_path, output_folder):
    return run_tool_docker_phase1("exiftool {input_file}", file_path, output_folder, 'exiftool_result.txt')

def file(file_path, output_folder):
    return run_tool_docker_phase1("file {input_file}", file_path, output_folder, 'file_result.txt')

def strings(file_path, output_folder):
    return run_tool(f"strings {file_path}", output_file='strings_result.txt', output_folder=output_folder)

def md5sum(file_path, output_folder):
    return run_tool(f"md5sum {file_path}", output_file='md5sum_result.txt', output_folder=output_folder)

def sha256sum(file_path, output_folder):
    return run_tool(f"sha256sum {file_path}", output_file='sha256sum_result.txt', output_folder=output_folder)

def xxd(file_path, output_folder):
    return run_tool(f"xxd {file_path}", output_file='xxd_result.txt', output_folder=output_folder)

def yara(file_path, output_folder):
    output = run_tool_docker_phase1("yara /rules/yara-rules-full.yar {input_file}", file_path, output_folder, 'yara_result.txt')
    command = f"sed -i '/===== PROFILING INFORMATION =====/,$d' {output_folder}/yara_result.txt"
    run_tool(command)
    return output

def imphash(file_path, output_folder):
    cmd = "python3 -c \"import pefile, sys; print(pefile.PE(sys.argv[1]).get_imphash())\" {input_file}"
    return run_tool_docker_phase1(cmd, file_path, output_folder, 'imphash_result.txt')

def rabin2(file_path, output_folder):
    return run_tool_docker_phase1("rabin2 -g {input_file}", file_path, output_folder, 'rabin2_result.txt')

def diec(file_path, output_folder):
    command = f"tools/Detect-It-Easy/docker/diec.sh -e -j {file_path}"
    return run_tool(command, output_file='diec_result.txt', output_folder=output_folder)

def ssdeep(file_path, output_folder):
    return run_tool_docker_phase1("ssdeep {input_file}", file_path, output_folder, 'ssdeep_result.txt')

def phase1(file_path, args, output_folder):
    print("Starting static analysis (phase1) ...")
    print("=====================================")

    tools_to_run = []
    available_tools = [
        func for func in globals().keys()
        if callable(globals()[func]) and not func.startswith("__")
    ]

    for tool_name in available_tools:
        if config.has_option('Phase1', tool_name):
            if config.getboolean('Phase1', tool_name, fallback=False):
                tools_to_run.append(tool_name)

    results = {}
    output_folder = f"{output_folder}/static"
    os.makedirs(output_folder, exist_ok=True)
    with ThreadPoolExecutor() as executor:
        futures = {}
        for tool_name in tools_to_run:
            if tool_name == 'avclass':
                if not args.vt_api_key:
                    print("avclass: VirusTotal API key is required.")
                    continue
                futures[executor.submit(avclass, file_path, output_folder, args.vt_api_key)] = tool_name
            else:
                tool_func = globals().get(tool_name)
                if callable(tool_func):
                    futures[executor.submit(tool_func, file_path, output_folder)] = tool_name
        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                output = future.result()
                results[tool_name] = output
            except Exception as e:
                results[tool_name] = f"Error: {e}"

    print("=====================================")
    print(f"Static analysis completed. Results are available in {output_folder}")
    print("=====================================")

# -------------------------
# Phase 2: Dynamic Analysis
# -------------------------
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    dump_path = None
    stop_server_callback = None

    def do_POST(self):
        if not self.dump_path:
            self.send_response(500)
            self.end_headers()
            return
        try:
            content_length = int(self.headers['Content-Length'])
            file_data = self.rfile.read(content_length)
            os.makedirs(os.path.dirname(self.dump_path), exist_ok=True)
            with open(self.dump_path, 'wb') as f:
                f.write(file_data)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'File received')
            self.wfile.flush()
        except Exception:
            self.send_response(500)
            self.end_headers()
            self.wfile.flush()
        finally:
            if self.stop_server_callback:
                self.stop_server_callback()

def start_server(dump_path, port=8888):
    SimpleHTTPRequestHandler.dump_path = dump_path
    server = HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)
    def stop_server(*args):
        server.shutdown()
    SimpleHTTPRequestHandler.stop_server_callback = stop_server
    def server_thread():
        server.serve_forever()
    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    return thread

def extract_results(data, output_folder):
    try:
        summary = data.get("behavior", {}).get("summary", {}) or {}
        for key, values in summary.items():
            output_path = os.path.join(output_folder, f"{key}_results.txt")
            with open(output_path, "w") as f:
                f.write("\n".join(values))

        network = data.get("network", {}) or {}
        hosts = network.get("hosts", []) or []
        norm_hosts = []
        for h in hosts:
            if isinstance(h, str):
                norm_hosts.append(h)
            elif isinstance(h, dict):
                norm_hosts.append(h.get("ip", ""))
        norm_hosts = [h for h in norm_hosts if h]
        with open(os.path.join(output_folder, "hosts_results.txt"), "w") as f:
            f.write("\n".join(norm_hosts))

        domains = network.get("domains", []) or []
        with open(os.path.join(output_folder, "domains_results.txt"), "w") as f:
            for entry in domains:
                if isinstance(entry, dict):
                    dom = entry.get("domain", "")
                    ip = entry.get("ip", "")
                else:
                    dom, ip = str(entry), ""
                if dom or ip:
                    f.write(f"{dom};{ip}\n")
    except Exception as e:
        print(f"Error: {e}")

def wait_for_task_and_report(task_id, report_path, max_wait=600, poll=5):
    db = "/opt/CAPEv2/cuckoo.db"
    t0 = time.time()
    with sqlite3.connect(db) as conn:
        cur = conn.cursor()
        while time.time() - t0 < max_wait:
            cur.execute("SELECT status FROM tasks WHERE id=?", (task_id,))
            row = cur.fetchone()
            status = row[0] if row else None
            if status in ("reported", "completed"):
                break
            if status in ("failed_analysis", "failure", "stopped", "unserviceable", "invalid"):
                raise RuntimeError(f"CAPE marcó la tarea #{task_id} como {status}")
            time.sleep(poll)
        else:
            raise TimeoutError(f"Tarea #{task_id} no terminó en {max_wait} s")

    t0 = time.time()
    while time.time() - t0 < max_wait:
        if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
            return
        time.sleep(poll)
    raise TimeoutError(f"{os.path.basename(report_path)} no apareció en {max_wait} s")

def phase2(file_path, output_folder):
    print("Starting dynamic analysis (phase2) ...")
    print("======================================")

    env_out = subprocess.run("poetry --directory /opt/CAPEv2/ env list --full-path", shell=True, capture_output=True, text=True).stdout.strip()
    if not env_out:
        raise RuntimeError("No pude obtener la ruta del virtualenv de CAPE.")
    venv_path = env_out.splitlines()[0].split()[0]
    poetry_python = f"{venv_path}/bin/python"

    command = f'{poetry_python} /opt/CAPEv2/utils/submit.py --timeout 60 "{file_path}"'
    result = subprocess.run(shlex.split(command) if isinstance(command, str) else command, capture_output=True, text=True)
    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    m = re.search(r'ID\s+(\d+)', combined)
    if not m:
        m = re.search(r'added\s+as\s+task\s+with\s+ID\s+(\d+)', combined, re.IGNORECASE)
    if not m:
        raise RuntimeError("No pude extraer el Task ID de la salida de submit.py.")
    task_id = int(m.group(1))

    report_path = f"/opt/CAPEv2/storage/analyses/{task_id}/reports/report.json"
    dump_path =  f"/opt/CAPEv2/storage/analyses/{task_id}/memory/memdump.raw.zst"

    start_server(dump_path)
    wait_for_task_and_report(task_id, report_path, max_wait=600, poll=5)

    with open(report_path, 'r') as file:
        data = json.load(file)

    output_folder = f"{output_folder}/dynamic"
    os.makedirs(output_folder, exist_ok=True)
    extract_results(data, output_folder)

    if os.path.exists(dump_path) and os.path.getsize(dump_path) > 0:
        print("Memory dump received.")
    else:
        print("Memory dump NOT received.")
        dump_path = None

    print("=====================================")
    print(f"Dynamic analysis completed. Results are available in {output_folder}")
    print("=====================================")
    return dump_path

# -------------------------
# Phase 3: Memory Forensics
# -------------------------

def apply_filters(plugin_name, output):
    patterns = {
        "windows.netscan": r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)",
        "windows.cmdline": r"(base64|EncodedCommand|wscript|powershell|cmd\.exe)",
        "windows.ldrmodule": r"(.*True.*False.*True.*\n)",
        "windows.dlllist": r"(AppData|Temp|random\.dll)",
        "windows.handles": r"(Temp|RunOnce|Run|Registry|HKEY|startup|NamedPipe|CurrentVersion|Security Center|Winlogon)",
        "windows.filescan": r"(\.exe|\.dll|\.tmp|\.scr|\.sys|\.bat|\.ps1|\.js|\.hta)",
        "windows.vadinfo": r"(EXECUTE)"
    }
    pattern = patterns.get(plugin_name)
    if not pattern:
        return output

    filtered_lines = [line for line in output.splitlines() if re.search(pattern, line, re.IGNORECASE)]
    return '\n'.join(filtered_lines)

def run_volatility(plugin_name, memdump_file, pid=None, extra_args=None, output_folder=None):
    import os, subprocess, shlex
    dumps_folder = os.path.abspath(f"{output_folder}/dumps")
    os.makedirs(dumps_folder, exist_ok=True)
    os.chmod(dumps_folder, 0o777)
    
    memdump_dir = os.path.dirname(os.path.abspath(memdump_file))
    memdump_filename = os.path.basename(memdump_file)
    
    # 1. Inyectamos las variables de entorno de forma nativa a nivel de SO
    env = os.environ.copy()
    env["XDG_RUNTIME_DIR"] = "/run/user/999"
    env["DOCKER_HOST"] = "unix:///run/user/999/docker.sock"
    env["MEMDUMPS_DIR"] = memdump_dir
    env["ANALYSIS_OUTPUT_DIR"] = dumps_folder
    
    # 2. Comando puro (El entrypoint ya tiene python3 /volatility3/vol.py)
    cmd = ["docker", "compose", "run", "--rm", "memory-forensics", "-q", "-f", f"/dumps/{memdump_filename}", "-o", "/output", plugin_name]
    if pid:
        cmd.extend(["--pid", str(pid)])
    if extra_args:
        cmd.extend(shlex.split(extra_args))
        
    print(f"Executing Volatility: {shlex.join(cmd)}")
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    
    # 3. Guardar el resultado real
    out_name = f"{plugin_name}_{pid}.txt" if pid else f"{plugin_name}.txt"
    out_path = os.path.join(output_folder, out_name)
    with open(out_path, "w") as f:
        if result.stdout:
            f.write(result.stdout)
        if result.stderr:
            f.write("\n--- ERRORES DEL CONTENEDOR ---\n")
            f.write(result.stderr)
    return result.stdout

def get_pids(memdump_file):
    memdump_dir = os.path.dirname(os.path.abspath(memdump_file))
    memdump_filename = os.path.basename(memdump_file)

    def voljson(cmd_suffix):
        import os, subprocess, shlex, json
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = "/run/user/999"
        env["DOCKER_HOST"] = "unix:///run/user/999/docker.sock"
        env["MEMDUMPS_DIR"] = memdump_dir
        
        cmd = ["docker", "compose", "run", "--rm", "memory-forensics", "-q", "-f", f"/dumps/{memdump_filename}", "-r", "json"] + shlex.split(cmd_suffix)
        
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        out = (r.stdout or "").strip()
        if not out:
            return []
        try:
            return json.loads(out)
        except Exception:
            return []

    def collect_children(node, acc):
        for c in node.get("__children", []):
            pid = c.get("PID")
            if pid:
                acc.add(pid)
            collect_children(c, acc)

    try:
        agent_names = {"python.exe", "pythonw.exe", "agent.exe"}
        ps = voljson("windows.pslist.PsList")
        if not ps:
            return []

        cand_pids = [p.get("PID") for p in ps if (p.get("ImageFileName") or "").lower() in agent_names]
        cand_pids = [pid for pid in cand_pids if pid]
        if not cand_pids:
            return []

        analyzer_pids = []
        for pid in cand_pids:
            cmd_entries = voljson(f"windows.cmdline.CmdLine --pid {pid}")
            for e in cmd_entries:
                cmd = (e.get("CommandLine") or e.get("Cmd") or "").lower()
                if "analyzer.py" in cmd or "agent.py" in cmd:
                    analyzer_pids.append(pid)
                    break

        tree = voljson("windows.pstree.PsTree")
        if not tree:
            return []

        def find_by_pid(node, pid):
            if node.get("PID") == pid:
                return node
            for c in node.get("__children", []):
                hit = find_by_pid(c, pid)
                if hit:
                    return hit
            return None

        pids = set()

        if analyzer_pids:
            for apid in analyzer_pids:
                node = None
                for root in tree:
                    node = find_by_pid(root, apid)
                    if node:
                        break
                if node:
                    collect_children(node, pids)

        if not pids:
            for pid in cand_pids:
                node = None
                for root in tree:
                    node = find_by_pid(root, pid)
                    if node:
                        break
                if node:
                    collect_children(node, pids)

        return sorted(pids)
    except Exception:
        return []

def prepare_dump(memdump_path):
    memdump_dir = os.path.dirname(memdump_path)
    memdump_file = os.path.join(memdump_dir, "memdump.raw")
    command = f"zstdcat {memdump_path} > {memdump_file}"
    subprocess.run(command, capture_output=True, shell=True)
    if os.path.exists(memdump_file):
        print("Memory dump file ready to process.")
        return memdump_file
    else:
        print("Unable to process memory dump.")
        return None

def phase3(memdump_path, args, output_folder):
    print("Starting memory forensics (phase3) ...")
    print("======================================")

    if args.memdump:
        memdump_file = memdump_path
    else:
        memdump_file = prepare_dump(memdump_path)

    pid_list = get_pids(memdump_file)
    if not pid_list:
        print("No valid PIDs found.")
        return
    else:
        print(f"Running analysis on these PIDs: {pid_list}")

    plugins = []
    for plugin_option in config.items('Phase3'):
        plugin_entry = plugin_option[0]
        enabled = config.getboolean('Phase3', plugin_entry, fallback=False)
        if enabled:
            details = plugin_entry.split(',')
            plugin_name = details[0]
            requires_pid = 'use_pid' in details
            args_index = details.index('args') + 1 if 'args' in details else None
            extra_args = ' '.join(details[args_index:]) if args_index else None
            plugins.append((plugin_name, requires_pid, extra_args))

    output_folder = f"{output_folder}/memory"
    os.makedirs(output_folder, exist_ok=True)
    
    with ThreadPoolExecutor() as executor:
        futures = {}
        for plugin in plugins:
            plugin_name, requires_pid, extra_args = plugin
            if requires_pid:
                for pid in pid_list:
                    futures[executor.submit(run_volatility, plugin_name, memdump_file, pid, extra_args, output_folder)] = f"{plugin_name}_{pid}"
            else:
                futures[executor.submit(run_volatility, plugin_name, memdump_file, None, extra_args, output_folder)] = plugin_name

        for future in as_completed(futures):
            pass

    print("=====================================")
    print(f"Memory forensics analysis completed. Results are available in {output_folder}")
    print("=====================================")

def generate_report(args):
    report = []
    static_dir = os.path.join(f"{args.output_folder}","static")
    dynamic_dir = os.path.join(f"{args.output_folder}","dynamic")
    memory_dir = os.path.join(f"{args.output_folder}","memory")

    def static_analysis():
        data = {}
        def process_key_value_file(file_path, exclude_keys=None):
            exclude_keys = exclude_keys or []
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    for line in f:
                        if ":" in line:
                            key, value = map(str.strip, line.split(":", 1))
                            if key not in exclude_keys:
                                data[key] = value

        process_key_value_file(f"{static_dir}/exiftool_result.txt", exclude_keys=["ExifTool Version Number"])
        
        if os.path.exists(f"{static_dir}/md5sum_result.txt"):
            data["MD5 Hash"] = open(f"{static_dir}/md5sum_result.txt").readline().split()[0]
        if os.path.exists(f"{static_dir}/sha256sum_result.txt"):
            data["SHA256 Hash"] = open(f"{static_dir}/sha256sum_result.txt").readline().split()[0]

        if os.path.exists(f"{static_dir}/ssdeep_result.txt"):
            with open(f"{static_dir}/ssdeep_result.txt") as f:
                lines = f.readlines()
                if len(lines) > 1:
                    data["SSDEEP Hash"] = lines[1].split(",")[0]

        if os.path.exists(f"{static_dir}/imphash_result.txt"):
            data["ImpHash"] = open(f"{static_dir}/imphash_result.txt").readline().strip()

        try:
            with open(f"{static_dir}/diec_result.txt", "r") as f:
                txt = f.read().strip()
                if txt:
                    diec_data = json.loads(txt)
                    data["PE Status"] = diec_data.get("status", "unknown")
                    data["Entropy"] = round(diec_data.get("total", 0), 2)
                else:
                    data["PE Status"] = "unknown"
                    data["Entropy"] = "n/a"
        except Exception:
            data["PE Status"] = "unknown"
            data["Entropy"] = "n/a"

        avclass_fp = f"{static_dir}/avclass_result.txt"
        if os.path.exists(avclass_fp):
           try:
              line = open(avclass_fp, "r").readline()
              parts = line.split("\t")
              data["AVClass"] = parts[1].strip() if len(parts) > 1 else line.strip()
           except Exception:
              data["AVClass"] = "unknown"
        else:
           data["AVClass"] = "not-run"

        if os.path.exists(f"{static_dir}/yara_result.txt"):
            with open(f"{static_dir}/yara_result.txt", "r") as yara_file:
                yara_lines = [line.strip() for line in yara_file if line.strip()]
                for idx, line in enumerate(yara_lines, start=1):
                    data[f"YARA_{idx}"] = line

        table = PrettyTable()
        table.field_names = ["Attribute", "Value"]
        table.align = "l"
        for key, value in data.items():
            table.add_row([key, value])
        return f"\n#### Phase 1: Static Analysis ####\n\n{table}\n"

    def dynamic_analysis():
        if not os.path.exists(dynamic_dir):
            return "\n#### Phase 2: Dynamic Analysis ####\n\nNo dynamic analysis data.\n"
        files = [f for f in os.listdir(dynamic_dir) if os.path.isfile(os.path.join(dynamic_dir, f)) and f.endswith("_results.txt")]
        sections = []
        for file_name in files:
            base_name = file_name.replace("_results.txt", "").replace("_", " ").title()
            words = base_name.split(" ")
            flipped_header = " ".join(words[::-1])
            sections.append((flipped_header, os.path.join(dynamic_dir, file_name)))
        sections.sort(key=lambda x: x[0])
        result = ["\n#### Phase 2: Dynamic Analysis ####\n"]
        for header, file_path in sections:
            separator = "=" * len(header)
            with open(file_path, "r") as f:
                lines = [line.strip() for line in f if line.strip()]
                count = len(lines)
                first_three = lines[:3]
                result.append(f"{header}\n{separator}\n- Total Indicators: {count}")
                if count > 0:
                    result.append("- Examples:")
                    for idx, line in enumerate(first_three, 1):
                        result.append(f"  {idx}. {line}")
                else:
                    result.append("- No indicators found.")
                result.append("")
        return "\n".join(result)

    def memory_forensics():
        if not os.path.exists(memory_dir):
            return "\n#### Phase 3: Memory Forensics ####\n\nNo memory analysis data.\n"
        result = subprocess.run(f"tree -h {memory_dir}", shell=True, text=True, capture_output=True, check=False)
        return f"\n#### Phase 3: Memory Forensics ####\n\n{result.stdout}\n"

    report.append(f"\nThis is a summary report. For the full list of indicators, please check output folder: {args.output_folder}")
    report.append(static_analysis())
    report.append(dynamic_analysis())
    report.append(memory_forensics())

    print("\n".join(report))
    report_file = os.path.join(args.output_folder,"summary_report.txt")
    with open(report_file, "w") as f:
        f.writelines(report)

def main():
    parser = argparse.ArgumentParser(description="Automated Malware Analysis")
    parser.add_argument("-f", "--file", required=True, help="Path to the malware sample file")
    parser.add_argument("-o", "--output-folder", default="output", help="Output folder for result files")
    parser.add_argument("--phase1", action='store_true', help="Run Phase 1: Static Analysis")
    parser.add_argument("--phase2", action='store_true', help="Run Phase 2: Dynamic Analysis")
    parser.add_argument("--phase3", action='store_true', help="Run Phase 3: Memory Forensics")
    parser.add_argument("--vt-api-key", help="API Key for VirusTotal")
    parser.add_argument("--memdump", help="Path to the memory dump file for Phase 3")
    parser.add_argument("--report", action='store_true', help="Only generate report from existing path")
    args = parser.parse_args()

    file_path = args.file
    output_folder = args.output_folder
    os.makedirs(output_folder, exist_ok=True)

    if not (args.phase1 or args.phase2 or args.phase3):
        args.phase1 = args.phase2 = args.phase3 = True
    if args.report:
        args.phase1 = args.phase2 = args.phase3 = False

    if args.phase1:
        phase1(file_path, args, output_folder)

    dump_path = None
    if args.phase2:
        dump_path = phase2(file_path, output_folder)

    if args.phase2 and args.phase3:
        if dump_path:
            phase3(dump_path, args, output_folder)
    else:
        if args.phase3:
            if not args.memdump:
                print("Memory dump file is required for Phase 3.")
                sys.exit(1)
            phase3(args.memdump, args, output_folder)

    if (args.phase1 and args.phase2 and args.phase3) or args.report:
        generate_report(args)

if __name__ == "__main__":
    main()
