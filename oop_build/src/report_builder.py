import subprocess
import json
import xml.etree.ElementTree as ET

class ReportBuilder:
    @staticmethod
    def parseNucleiJSON(output_file):
        findings = []
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    data = json.loads(line)

                    info = data.get("info", {})
                    classification = info.get("classification", {})

                    cve_list = classification.get("cve-id", []) or info.get("cve", []) or []
                    cve = cve_list[0] if isinstance(cve_list, list) and cve_list else "UNKNOWN"

                    severity = info.get("severity", "UNKNOWN")
                    description = info.get("name", "Kwetsbaarheid gedetecteerd door Nuclei.")
                    references = info.get("reference", [])

                    if not isinstance(references, list):
                        references = [str(references)]

                    findings.append({
                        "cve": cve,
                        "severity": severity,
                        "description": description,
                        "references": references
                    })

        except Exception:
            pass

        return findings
        
    @staticmethod
    def parseGoBusterOutput(output_file):
        entries = []

        try:
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()

                    if not line.startswith("/"):
                        continue

                    # Verwachte formats:
                    # /admin (Status: 403) [Size: 287]
                    # /login (Status: 200)
                    path = line.split()[0]

                    status = "unknown"
                    marker = "Status:"
                    if marker in line:
                        after = line.split(marker, 1)[1].strip()   # bv "403) [Size: 287]"
                        status = "".join(ch for ch in after if ch.isdigit()) or "unknown"

                    entries.append(f"{path} ({status})")

        except Exception:
            pass

        return entries
        
    @staticmethod
    def buildReconReport(recon_results):
        reconnaissance_report = {
            "hosts": {}
        }

        # ==== Nmap Service Detectie Fase =====

        tree_services = ET.parse(recon_results["Nmap"]["services"])
        root_services = tree_services.getroot()

        for host in root_services.findall("host"):
            ip = host.find("address").get("addr")

            reconnaissance_report["hosts"][ip] = {
                "ip": ip,
                "os": None,
                "services": {}
            }

            for port in host.findall(".//port"):
                portid = port.get("portid")
                service_el = port.find("service") 
                service_name = service_el.get("name") if service_el is not None else "unknown"

                reconnaissance_report["hosts"][ip]["services"][portid] = {
                    "service": service_name,
                    "paths": [],
                    "weaknesses": [],
                    "vulnerabilities": []
                }

        # ===== Nmap OS Detectie Fase =======

        try:
            tree_os = ET.parse(recon_results["Nmap"]["os"])
            root_os = tree_os.getroot()

            for host in root_os.findall("host"):
                ip = host.find("address").get("addr")
                osmatch = host.find(".//osmatch")
                if osmatch is not None:
                    reconnaissance_report["hosts"][ip]["os"] = osmatch.get("name")
        except Exception:
            pass  # OS-detectie is optioneel

        # ===== Nikto Web Server Scanning Fase =======

        for result in recon_results["Nikto"]["results"]:
            ip = result["host"]
            protocol = result["protocol"]

            for service in reconnaissance_report["hosts"][ip]["services"].values():
                if protocol in service["service"]:
                    service["weaknesses"].append({
                        "tool": "Nikto",
                        "ssl": result["ssl"],
                        "output": result["output"]
                    })

        # ====== GoBuster Path Scanning Fase =======

        for result in recon_results["GoBuster"]["results"]:
            ip = result["host"]
            protocol = result["protocol"]

            for service in reconnaissance_report["hosts"][ip]["services"].values():
                if protocol in service["service"]:
                    service["paths"].append({
                        "tool": "GoBuster",
                        "output": result["output"],
                        "entries": ReportBuilder.parseGoBusterOutput(result["output"])
                    })

        # ======= Nuclei Vulnerability Scanning Fase ========

        for result in recon_results["Nuclei"]["results"]:
            ip = result["host"]
            port = result["port"]

            nuclei_findings = ReportBuilder.parseNucleiJSON(result["output"])

            for finding in nuclei_findings:
                vuln = {
                    "tool": "Nuclei",
                    "service": result["service"],
                    "output": result["output"],

                    "cve": finding["cve"],
                    "severity": finding["severity"],
                    "description": finding["description"],
                    "references": finding["references"],

                    # Intelligence verrijking
                    "finding_type": "Remote Service Vulnerability",
                    "attack_phase": "Initial Access",
                    "source_confidence": "High (CVE-based detection)" if finding["cve"] != "UNKNOWN" else "Medium",

                    "impact": "Afhankelijk van context kan misbruik leiden tot systeemcompromittering.",
                    "solution": "Patch of mitigatie toepassen volgens vendor.",
                    "usable_for_attack": finding["severity"] in ["high", "critical"]
                }

                if ip in reconnaissance_report["hosts"] and port in reconnaissance_report["hosts"][ip]["services"]:
                    reconnaissance_report["hosts"][ip]["services"][port]["vulnerabilities"].append(vuln)

        # ===== Host-level Intelligence Samenvatting =====

        for host_ip, host_data in reconnaissance_report["hosts"].items():
            total_services = len(host_data["services"])
            total_vulns = 0
            highest_severity = "none"

            severity_order = ["none", "info", "low", "medium", "high", "critical"]

            for service in host_data["services"].values():
                for vuln in service["vulnerabilities"]:
                    total_vulns += 1
                    sev = (vuln.get("severity") or "none").lower()
                    if sev not in severity_order:
                        sev = "info"
                    if severity_order.index(sev) > severity_order.index(highest_severity):     
                        highest_severity = sev

            host_data["summary"] = {
                "total_services": total_services,
                "total_vulnerabilities": total_vulns,
                "highest_severity": highest_severity
            }

            if highest_severity in ["critical", "high"]:
                host_data["risk_level"] = "High"
            elif highest_severity == "medium":
                host_data["risk_level"] = "Medium"
            else:
                host_data["risk_level"] = "Low"

        return reconnaissance_report