from src.tool import Tool
import subprocess
import json
import os
import xml.etree.ElementTree as ET

class Nuclei(Tool):

    def scan(self, complete_scan):
        ScanResults = []

        tree = ET.parse(complete_scan["services"])
        root = tree.getroot()

        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue

            ip_address = addr_el.get("addr")

            for port in host.findall(".//port"):
                if not self.isPortOpen(port):
                    continue
            
                service = port.find("service")
                if service is None:
                    continue
            
                service_name = service.get("name")
                portid = port.get("portid")
            
                is_web, protocol = self.detectWebService(service_name, portid)
                if not is_web:
                    continue
            
                target = f"{protocol}://{ip_address}:{portid}"
                output_file = os.path.join(self.OUTPUT_DIR, f"Nuclei_{ip_address}_{portid}.json")
            
                print(f"[+] Start Nuclei scan op {target}")
            
                subprocess.run(
                    ["nuclei", "-u", target, "-jsonl", "-o", output_file],
                    check=False
                )
            
                ScanResults.append({
                    "host": ip_address,
                    "port": portid,
                    "service": service_name,
                    "output": output_file
                })

        return {
            "tool": "Nuclei",
            "total_scans": len(ScanResults),
            "results": ScanResults
        }
    pass