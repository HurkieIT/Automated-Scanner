from src.nmap import Nmap
from src.nikto import Nikto
from src.gobuster import Gobuster
from src.nuclei import Nuclei
from src.report_builder import ReportBuilder

import subprocess
import json
import xml.etree.ElementTree as ET



def main():
    nmap = Nmap()
    nikto = Nikto()
    gobuster = Gobuster()
    nuclei = Nuclei()
    
    # target_ip = input('Voer het Target IP OF Network in (bijv. 192.168.XXX.XXX | 192.168.XXX.0/24): ')

    nmap_results = nmap.scan("10.82.163.50")
    nikto_results = nikto.scan(nmap_results)
    gobuster_results = gobuster.scan(nmap_results)
    nuclei_results = nuclei.scan(nmap_results)
    
    final_report = ReportBuilder.buildReconReport({
        "Nmap": nmap_results,
        "Nikto": nikto_results,
        "GoBuster": gobuster_results,
        "Nuclei": nuclei_results
    })

    print("\n Scan afgerond")
    print(json.dumps(final_report, indent=4))

    pass

if __name__ == "__main__":
    main()