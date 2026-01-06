from src.tool import Tool
import subprocess
import json
import os
import xml.etree.ElementTree as ET

class Nikto(Tool):

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
                output_file = os.path.join(self.OUTPUT_DIR, f"Nikto_{protocol.upper()}_{ip_address}_{portid}.xml")

                print(f"[+] Start Nikto {protocol.upper()} scan op {target}")

                command = ["nikto", "-h", target, "-o", output_file, "-Format", "xml"]
                if protocol == "https":
                    command.insert(2, "-ssl")

                subprocess.run(command, check=False)

                ScanResults.append({
                    "host": ip_address,
                    "protocol": protocol,
                    "port": portid,
                    "ssl": protocol == "https",
                    "output": output_file
                })

        return {
            "tool": "Nikto",
            "total_scans": len(ScanResults),
            "results": ScanResults
        }
    pass