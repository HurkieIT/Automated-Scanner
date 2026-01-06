from abc import ABC, abstractmethod
import subprocess
import json
import xml.etree.ElementTree as ET

class Tool:

    #Define constants
    DISCOVERY = "./output/target_discovery.xml"
    OS = "./output/os_scans.xml"
    SERVICES = "./output/service_scans.xml"
    OUTPUT_DIR = "./output"

    def __init__(self):
        print("Initialization completed")
        pass
    
    def isPortOpen(self, port):
        state = port.find("state")
        return state is not None and state.get("state") == "open"

    def detectWebService(self, service_name, portid):
        """
        Normaliseert Nmap service naming.
        Geeft terug: (is_web, protocol) waarbij protocol 'http' of 'https' is.
        """
        s = (service_name or "").lower()
        # web als er "http" in de servicenaam zit (bv http, ssl/http, http-alt)
        is_web = "http" in s
        if not is_web:
            return (False, None)

        # https als ssl/https voorkomt, of als port 443 is
        is_https = ("ssl" in s) or ("https" in s) or (str(portid) == "443")
        return (True, "https" if is_https else "http")

    @abstractmethod
    def scan(self):
        """Elke child class moet deze methode implementeren"""
        pass