#!/usr/bin/env python3
import json
import os
import re
from datetime import datetime

class IOCReportUnifier:
    def __init__(self, sample_name="second_stage.exe"):
        self.report = {
            "execution_metadata": {
                "engine": "Advanced Unified IOC Extractor v2.5-Integrated",
                "malware_folder_target": sample_name,
                "timestamp_generation": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "sample": {
                "filename": sample_name,
                "md5": "",
                "sha256": ""
            },
            "iocs": [],
            "summary": {
                "total_iocs": 0,
                "by_phase": {"static": 0, "dynamic": 0, "memory": 0, "multi": 0}
            }
        }
        self.ioc_map = {}

    def add_ioc(self, value, ioc_type, phase, detail_msg):
        """Agrega o fusiona un IoC garantizando trazabilidad multi-fase."""
        if not value or str(value).strip() == "":
            return

        value = str(value).strip()
        
        if value in self.ioc_map:
            ioc_entry = self.ioc_map[value]
            if phase not in ioc_entry["sources"]:
                ioc_entry["sources"].append(phase)
                ioc_entry["details"][phase] = detail_msg
        else:
            ioc_entry = {
                "value": value,
                "type": ioc_type,
                "sources": [phase],
                "details": {
                    phase: detail_msg
                }
            }
            self.ioc_map[value] = ioc_entry
            self.report["iocs"].append(ioc_entry)

    def parse_static_phase(self, static_data):
        if not isinstance(static_data, dict): return
        hashes = static_data.get("hashes", {})
        self.report["sample"]["md5"] = hashes.get("md5", "")
        self.report["sample"]["sha256"] = hashes.get("sha256", "")
        
        if self.report["sample"]["md5"]:
            self.add_ioc(self.report["sample"]["md5"], "md5", "static", "Sample MD5 File Hash")
        if self.report["sample"]["sha256"]:
            self.add_ioc(self.report["sample"]["sha256"], "sha256", "static", "Sample SHA256 File Hash")

    def parse_dynamic_phase(self, dynamic_data):
        if not isinstance(dynamic_data, dict): return
        
        network = dynamic_data.get("network", {})
        for domain in network.get("domains", []):
            self.add_ioc(domain.get("domain", ""), "domain", "dynamic", "Outbound DNS query in CAPEv2")
        for host in network.get("hosts", []):
            self.add_ioc(host, "ip", "dynamic", "Direct outbound connection in CAPEv2")

    def parse_memory_phase(self, memory_data):
        if not isinstance(memory_data, dict): return
        
        netscan_lines = memory_data.get("windows.netscan", [])
        for line in netscan_lines:
            ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(line))
            for ip in ip_matches:
                if ip not in ["0.0.0.0", "127.0.0.1", "255.255.255.255"]:
                    self.add_ioc(ip, "ip", "memory", "Volatility windows.netscan: Active connection state found")

    def compile_summary(self):
        self.report["summary"]["total_iocs"] = len(self.report["iocs"])
        by_phase = {"static": 0, "dynamic": 0, "memory": 0, "multi": 0}
        
        for ioc in self.report["iocs"]:
            if len(ioc["sources"]) > 1:
                by_phase["multi"] += 1
            for src in ioc["sources"]:
                if src in by_phase:
                    by_phase[src] += 1
                    
        self.report["summary"]["by_phase"] = by_phase

    def save_report(self, output_path):
        self.compile_summary()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=4, ensure_ascii=False)
        print(f"[+] Unified Master Report built successfully at: {output_path}")
