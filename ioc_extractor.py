#!/usr/bin/env python
import argparse
import subprocess
import os
import sys
import hashlib
import re
import json
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from prettytable import PrettyTable

config = configparser.ConfigParser()
config.optionxform = str
config.read('tools.ini')

# -------------------------
# Phase 1: Static Analysis
# -------------------------
def run_tool(command, output_file=None, output_folder=None):
    # command is an argument list (no shell), so file paths and other
    # interpolated values cannot be interpreted as shell metacharacters.
    print(f"Executing command: {shlex.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    if output_file:
        if output_folder:
            output_path = os.path.join(output_folder, output_file)
            with open(output_path, 'w') as f:
                f.write(result.stdout)
    return result.stdout

def avclass(file_path, output_folder, api_key):
    # Calculate sha256 hash
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    sha256 = sha256_hash.hexdigest()
    vt_command = [
        "curl", f"https://www.virustotal.com/api/v3/files/{sha256}",
        "--header", f"X-Apikey: {api_key}",
    ]
    run_tool(vt_command, output_file='virustotal_result.txt', output_folder=output_folder)
    av_command = ["avclass", "-f", os.path.join(output_folder, "virustotal_result.txt")]
    output = run_tool(av_command, output_file='avclass_result.txt', output_folder=output_folder)
    return output

def capa(file_path, output_folder):
    command = ["tools/capa", "-v", file_path]
    output = run_tool(command, output_file='capa_result.txt', output_folder=output_folder)
    return output

def floss(file_path, output_folder):
    command = ["floss", "--minimum-length", "7", file_path]
    output = run_tool(command, output_file='floss_result.txt', output_folder=output_folder)
    return output

def exiftool(file_path, output_folder):
    command = ["exiftool", file_path]
    output = run_tool(command, output_file='exiftool_result.txt', output_folder=output_folder)
    return output

def file(file_path, output_folder):
    command = ["file", file_path]
    output = run_tool(command, output_file='file_result.txt', output_folder=output_folder)
    return output

def strings(file_path, output_folder):
    command = ["strings", file_path]
    output = run_tool(command, output_file='strings_result.txt', output_folder=output_folder)
    return output

def md5sum(file_path, output_folder):
    command = ["md5sum", file_path]
    output = run_tool(command, output_file='md5sum_result.txt', output_folder=output_folder)
    return output

def sha256sum(file_path, output_folder):
    command = ["sha256sum", file_path]
    output = run_tool(command, output_file='sha256sum_result.txt', output_folder=output_folder)
    return output

def xxd(file_path, output_folder):
    command = ["xxd", file_path]
    output = run_tool(command, output_file='xxd_result.txt', output_folder=output_folder)
    return output

def yara(file_path, output_folder):
    command = ["yara", "yara-rules-full.yar", file_path]
    output = run_tool(command, output_file='yara_result.txt', output_folder=output_folder)
    command = ["sed", "-i", "/===== PROFILING INFORMATION =====/,$d",
               os.path.join(output_folder, "yara_result.txt")]
    output = run_tool(command, output_file=None, output_folder=None)
    return output

def imphash(file_path, output_folder):
    command = ["python", "-c",
               "import pefile, sys; print(pefile.PE(sys.argv[1]).get_imphash())",
               file_path]
    output = run_tool(command, output_file='imphash_result.txt', output_folder=output_folder)
    return output

def rabin2(file_path, output_folder):
    command = ["rabin2", "-g", file_path]
    output = run_tool(command, output_file='rabin2_result.txt', output_folder=output_folder)
    return output

def diec(file_path, output_folder):
    command = ["tools/Detect-It-Easy/docker/diec.sh", "-e", "-j", file_path]
    output = run_tool(command, output_file='diec_result.txt', output_folder=output_folder)
    return output

def ssdeep(file_path, output_folder):
    command = ["ssdeep", file_path]
    output = run_tool(command, output_file='ssdeep_result.txt', output_folder=output_folder)
    return output

def phase1(file_path, args, output_folder):
    print("Starting static analysis (phase1) ...")
    print("=====================================")

    tools_to_run = []
    available_tools = [
        func for func in globals().keys()
        if callable(globals()[func]) and not func.startswith("__")
    ]

    for tool_name in available_tools:
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
                    print("avclass: VirusTotal API key is required for VirusTotal analysis.")
                    continue
                futures[executor.submit(avclass, file_path, output_folder, args.vt_api_key)] = tool_name
            else:
                tool_func = globals().get(tool_name)
                if callable(tool_func):
                    futures[executor.submit(tool_func, file_path, output_folder)] = tool_name
                else:
                    print(f"Tool {tool_name} is not defined.")
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
    # return results

# -------------------------
# Phase 2: Dynamic Analysis
# -------------------------
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    dump_path = None 

    def do_POST(self):
        if not self.dump_path:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Server not properly initialized.')
            return
    
        try:
            content_length = int(self.headers['Content-Length'])
            file_data = self.rfile.read(content_length)
            # Check folder and save file
            os.makedirs(os.path.dirname(self.dump_path), exist_ok=True)
            with open(self.dump_path, 'wb') as f:
                f.write(file_data)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'File received')
            self.wfile.flush()
        
        except:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Failed to save the file')
            self.wfile.flush()
        
        finally:        
            # Stop the server after handling the request
            if self.stop_server_callback:
                print("Stopping server after receiving the file...")
                self.stop_server_callback()

def start_server(dump_path, port=8888):
    SimpleHTTPRequestHandler.dump_path = dump_path
    server = HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)
    
    # Define a callback to stop the server
    def stop_server(*args):
        server.shutdown()
    
    SimpleHTTPRequestHandler.stop_server_callback = stop_server

   # Run the server in a separate thread
    def server_thread():
        print(f"Server starting on port {port}, dump path: {dump_path}")
        server.serve_forever()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    return thread

def extract_results(data, output_folder):
    try:
        summary = data['behavior']['summary']
        for key, values in summary.items():
            output_path = os.path.join(output_folder, f"{key}_results.txt")
            with open(output_path, 'w') as f:
                f.write('\n'.join(values))
        
        network = data['network']
        hosts_output_path = os.path.join(output_folder, "hosts_results.txt")
        with open(hosts_output_path, 'w') as f:
            f.write('\n'.join(network['hosts']))

        domains_output_path = os.path.join(output_folder, "domains_results.txt")
        with open(domains_output_path, 'w') as f:
            for entry in network['domains']:
                f.write(f"{entry['domain']};{entry['ip']}\n")

    except Exception as e:
        print(f"Error: {e}")

def phase2(file_path, output_folder):
    print("Starting dynamic analysis (phase2) ...")
    print("======================================")

    # Get poetry executable for running CAPE
    poetry_python = subprocess.run(
        ["poetry", "--directory", "/opt/CAPEv2/", "env", "list", "--full-path"],
        capture_output=True, text=True).stdout.strip()

    # Run CAPE
    command = [f"{poetry_python}/bin/python", "/opt/CAPEv2/utils/submit.py",
               "--timeout", "60", file_path]
    result = subprocess.run(command, capture_output=True, text=True)
    match = re.search(r'ID (\d+)', result.stdout)
    if not match:
        raise RuntimeError(
            f"Could not parse task ID from CAPE submit output.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    task_id = int(match.group(1))
    report_path = f"/opt/CAPEv2/storage/analyses/{task_id}/reports/report.json"
    dump_path =  f"/opt/CAPEv2/storage/analyses/{task_id}/memory/memdump.raw.zst"

    # Start HTTP server to receive the dump file for phase 3
    server_thread = start_server(dump_path)

    start_time = time.time()
    timeout = 200
    interval = 15
    # Wait for report to be created
    while not os.path.exists(report_path):
        if time.time() - start_time > timeout:
            raise TimeoutError(f"report.json not found within {timeout} seconds.")
        print(f"Waiting for {report_path} to exist...")
        time.sleep(interval)

    # Open report.json file
    with open(report_path, 'r') as file:
        data = json.load(file)

    output_folder = f"{output_folder}/dynamic"
    os.makedirs(output_folder, exist_ok=True)
    extract_results(data, output_folder)
    
    if os.path.exists(dump_path):
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
    # print(f"Filtering plugin: {plugin_name}")  # Debugging info
    patterns = {
        "windows.netscan": r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)",
        "windows.cmdline": r"(base64|EncodedCommand|wscript|powershell|cmd\.exe)",
        "windows.ldrmodule": r"(.*True.*False.*True.*)",
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
    dumps_folder = f"{output_folder}/dumps" # used for plugins with --dump
    os.makedirs(dumps_folder, exist_ok=True)
    command = ["./tools/volatility3/vol.py", "-q", "-f", memdump_file,
               "-o", dumps_folder, plugin_name]
    if pid:
        command += ["--pid", str(pid)]
    if extra_args:
        command += shlex.split(extra_args)
    print(f"Executing command: {shlex.join(command)}")  # Debugging info
    result = subprocess.run(command, capture_output=True, text=True)
    if output_folder:
        raw_output_folder = f"{output_folder}/raw"
        filtered_output_folder = f"{output_folder}/filtered"
        pid = str(pid) if pid else "all"
        os.makedirs(raw_output_folder, exist_ok=True)
        os.makedirs(filtered_output_folder, exist_ok=True)

        raw_output_file = os.path.join(raw_output_folder, f"{plugin_name}.{pid}_results.txt")
        with open(raw_output_file, 'w') as f:
            f.write(result.stdout)

        filtered_output_file = os.path.join(filtered_output_folder, f"{plugin_name}.{pid}_results.txt")
        with open(filtered_output_file, 'w') as f:
            f.write(apply_filters(plugin_name, result.stdout))

    return f"{plugin_name}.{pid if pid else 'all'}", result.stdout

def get_pids(memdump_file):
    try:
        # Get PID of pyw.exe (CAPE agent)
        command = ["./tools/volatility3/vol.py", "-f", memdump_file,
                   "-r", "json", "windows.pslist.PsList"]
        print(f"Executing command: {shlex.join(command)}")
        pslist_result = subprocess.run(command, capture_output=True, text=True)
        processes = json.loads(pslist_result.stdout)
        pyw_pid = None
        for proc in processes:
            if proc.get('ImageFileName', '').lower() == 'pyw.exe':
                pyw_pid = proc.get('PID')
                break
        if pyw_pid is None:
            print("Could not find process 'pyw.exe'")
            return []
        
        # Get process tree of pyw.exe
        command = ["./tools/volatility3/vol.py", "-f", memdump_file,
                   "-r", "json", "windows.pstree.PsTree", "--pid", str(pyw_pid)]
        pstree_result = subprocess.run(command, capture_output=True, text=True)
        pstree = json.loads(pstree_result.stdout)
        
        children_pids = []
        def traverse_tree(process):
            # Search for process pythonw.exe with command analyzer.py
            if process.get('ImageFileName', '').lower() == 'pythonw.exe' and 'analyzer.py' in process.get('Cmd', ''):
                collect_children_pids(process)
            else:
                for child in process.get('__children', []):
                    traverse_tree(child)

        def collect_children_pids(process):
            for child in process.get('__children', []):
                children_pids.append(child.get('PID'))
                collect_children_pids(child)
        
        for process in pstree:
            traverse_tree(process)

        return children_pids

    except Exception as e:
        print(f"Error getting PIDs: {e}")
        return []
    
def prepare_dump(memdump_path):
    memdump_dir = os.path.dirname(memdump_path)
    memdump_file = os.path.join(memdump_dir, "memdump.raw")
    with open(memdump_file, "wb") as out:
        subprocess.run(["zstdcat", memdump_path], stdout=out, stderr=subprocess.PIPE)
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

    # Load plugins to run from config file
    plugins = []
    for plugin_option in config.items('Phase3'):
        plugin_entry = plugin_option[0]
        enabled = config.getboolean('Phase3', plugin_entry, fallback=False)
        if enabled:
            # Parse plugin details
            details = plugin_entry.split(',')
            plugin_name = details[0]
            requires_pid = 'use_pid' in details
            args_index = details.index('args') + 1 if 'args' in details else None
            extra_args = ' '.join(details[args_index:]) if args_index else None
            plugins.append((plugin_name, requires_pid, extra_args))

    # print(plugins)

    output_folder = f"{output_folder}/memory"
    os.makedirs(output_folder, exist_ok=True)
    results = []
    with ThreadPoolExecutor() as executor:
        futures = {}
        for plugin in plugins:
            plugin_name, requires_pid, extra_args = plugin
            if requires_pid: 
                for pid in pid_list: # execute plugin for each pid
                    futures[executor.submit(run_volatility, plugin_name, memdump_file, pid, extra_args, output_folder)] = f"{plugin_name}_{pid}"
            else: # execute plugin for whole memdump
                futures[executor.submit(run_volatility, plugin_name, memdump_file, None, extra_args, output_folder)] = plugin_name

        for future in as_completed(futures):
            plugin_name = futures[future]
            try:
                name, output = future.result()
                results.append((name, output))
            except Exception as e:
                results.append((plugin_name, f"Error: {e}"))

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

        # Extract a single value; if the source file is missing or malformed
        # (e.g. a non-PE sample, or a tool that produced no output), record
        # "N/A" and keep going instead of aborting the whole report.
        def safe_extract(key, extractor, default="N/A"):
            try:
                data[key] = extractor()
            except Exception as e:
                print(f"Warning: could not extract '{key}': {e}")
                data[key] = default

        # Helper to process key-value files
        def process_key_value_file(file_path, exclude_keys=None):
            exclude_keys = exclude_keys or []
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        if ":" not in line:
                            continue
                        key, value = map(str.strip, line.split(":", 1))
                        if key not in exclude_keys:
                            data[key] = value
            except Exception as e:
                print(f"Warning: could not process '{file_path}': {e}")

        process_key_value_file(f"{static_dir}/exiftool_result.txt", exclude_keys=["ExifTool Version Number"])
        safe_extract("MD5 Hash", lambda: open(f"{static_dir}/md5sum_result.txt").readline().split()[0])
        safe_extract("SHA256 Hash", lambda: open(f"{static_dir}/sha256sum_result.txt").readline().split()[0])

        try:
            with open(f"{static_dir}/ssdeep_result.txt") as f:
                lines = f.readlines()
                if len(lines) > 1:
                    data["SSDEEP Hash"] = lines[1].split(",")[0]
        except Exception as e:
            print(f"Warning: could not extract 'SSDEEP Hash': {e}")

        safe_extract("ImpHash", lambda: open(f"{static_dir}/imphash_result.txt").readline().strip())

        try:
            with open(f"{static_dir}/diec_result.txt", "r") as f:
                diec_data = json.load(f)
                data["PE Status"] = diec_data["status"]
                data["Entropy"] = round(diec_data["total"], 2)
        except Exception as e:
            print(f"Warning: could not extract DIE info: {e}")
            data["PE Status"] = "N/A"
            data["Entropy"] = "N/A"

        safe_extract("AVClass", lambda: open(f"{static_dir}/avclass_result.txt").readline().split("\t")[1].strip())

        try:
            with open(f"{static_dir}/yara_result.txt", "r") as yara_file:
                yara_lines = [line.strip() for line in yara_file if line.strip()]
                for idx, line in enumerate(yara_lines, start=1):
                    data[f"YARA_{idx}"] = line
        except Exception as e:
            print(f"Warning: could not read YARA results: {e}")

        table = PrettyTable()
        table.field_names = ["Attribute", "Value"]
        table.align = "l"
        for key, value in data.items():
            table.add_row([key, value])
        return f"\n#### Phase 1: Static Analysis ####\n\n{table}\n"

    def dynamic_analysis():
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
        result = subprocess.run(["tree", "-h", memory_dir], text=True, capture_output=True, check=True)
        return f"\n#### Phase 3: Memory Forensics ####\n\n{result.stdout}\n"

    # Generate the complete report
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

    # If no phases are specified, run all phases
    if not (args.phase1 or args.phase2 or args.phase3):
        args.phase1 = args.phase2 = args.phase3 = True
    # If report is specified, disable all phases
    if args.report:
        args.phase1 = args.phase2 = args.phase3 = False

    if args.phase1:
        phase1(file_path, args, output_folder)

    dump_path = None
    if args.phase2:
        dump_path = phase2(file_path, output_folder) #, args, output_folder)

    # run phase3 after phase2
    if args.phase2 and args.phase3:
        if dump_path:
            phase3(dump_path, args, output_folder)
    # run only phase 3
    else: 
        if args.phase3:
            if not args.memdump:
                print("Memory dump file is required for Phase 3.")
                sys.exit(1)
            phase3(args.memdump, args, output_folder)
    
    if args.phase1 and args.phase2 and args.phase3:
        generate_report(args)
    elif args.report:
        if not args.output_folder:
            print("Output folder required for generating report.")
        generate_report(args)

if __name__ == "__main__":
    main()