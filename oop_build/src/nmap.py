from src.tool import Tool
import subprocess
import json
import xml.etree.ElementTree as ET

class Nmap(Tool):

    def scan(self, target_ip):
        
        # Stap 1: Nmap Network Exploration

        subprocess.run(
            ["nmap", "-sn", target_ip, "-oX", self.DISCOVERY],
            check=True
        )

        print("Nmap Network Discovery Scan voltooid.")
        print("Resultaten opgeslagen in", self.DISCOVERY)

        tree = ET.parse(self.DISCOVERY)
        root = tree.getroot()

        TargetsUp = []

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                addr_el = host.find("address")
                if addr_el is not None:
                    ip_address = addr_el.get("addr")
                    print(f"Gevonden IP: {ip_address}")
                    TargetsUp.append(ip_address)

        print(f"Totaal up hosts: {len(TargetsUp)}")

        # input("Druk op Enter om door te gaan naar de OS-scan van alleen deze hosts...")

        # Stap 2: Nmap OS Exploration (alleen HostUps)

        #Alles in één keer (één Nmap-call met alle IP's)
        if TargetsUp:
            subprocess.run(
                ["nmap", "-O"] + TargetsUp + ["-oX", self.OS],
                check=True
            )
            print("Nmap OS Exploration voltooid voor up hosts.")
            print("Resultaten opgeslagen in TARGET_os.xml")
        else:
            print("Geen up hosts gevonden, OS-scan wordt overgeslagen.")

        # input("Druk op Enter om door te gaan naar de volgende stap...")

        # Stap 3: Nmap Service Discovery (ook alleen HostUps)

        if TargetsUp:
            subprocess.run(
                ["nmap", "-sV"] + TargetsUp + ["-oX",  self.SERVICES],
                check=True
            )
            print("Nmap Service Scan voltooid voor up hosts.")
            print("Resultaten opgeslagen in TARGET_services.xml")
        else:
            print("Geen up hosts gevonden, services-scan wordt overgeslagen.")

        # input("Druk op Enter om door te gaan naar de volgende stap...")

    # Target_discovery.xml + Targetos.xml + Target_services.xml
    # Combineren van de verschillende XML-bestanden in één overzichtelijk bestand.

        return {
            "discovery": self.DISCOVERY,
            "os": self.OS,
            "services": self.SERVICES
        }

    ######
    pass