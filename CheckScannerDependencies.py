#Dependency checker for Automated Scanner.
#Gemaakt door: Jens Cornelius Gijsbertus van den Hurk
#Datum: 2-1-2025 - 6-1-2025

#___________________________________________________

##Check Dependencies for Automated Scanner


#Import modules for OS interaction
import subprocess
import sys
import shutil

AutoInstall = "--auto-install" in sys.argv

def ask_install(package):
    #AUTO_INSTALL bepaalt alleen default (Enter = y).
    default = "y" if AutoInstall else "n"
    ans = input(f"Install {package} now? (y/n) [default: {default}]: ").strip().lower()
    if ans == "":
        ans = default
    return ans == "y"

def install_with_apt(package):
    print(f"Attempting to install {package} via apt...")
    print("You may be prompted for your sudo password.")
    try:
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", package], check=True)
        print(f"{package} installed successfully.")
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to install {package}.")
        return False

#______________________________________________________

#Functions to check for each tool.
def dependency_check_nmap():
    print("Checking if Nmap is available for Automated Scanner...")
    if shutil.which("nmap") is None:
        print("Nmap is not installed.")

        if ask_install("nmap"):
            if install_with_apt("nmap") and shutil.which("nmap") is not None:
                print("Nmap is installed.")
                return True
            print("Nmap install attempted, but command is still not found.")
            return False

        print("Skipped. Manual install: sudo apt install nmap")
        return False

    print("Nmap is installed.")
    return True

def dependency_check_nikto():
    print("Checking if Nikto is available for Automated Scanner...")
    if shutil.which("nikto") is None:
        print("Nikto is not installed.")

        if ask_install("nikto"):
            if install_with_apt("nikto") and shutil.which("nikto") is not None:
                print("Nikto is installed.")
                return True
            print("Nikto install attempted, but command is still not found.")
            return False

        print("Skipped. Manual install: sudo apt install nikto")
        return False

    print("Nikto is installed.")
    return True

def dependency_check_gobuster():
    print("Checking if Gobuster is available for Automated Scanner...")
    if shutil.which("gobuster") is None:
        print("Gobuster is not installed.")

        if ask_install("gobuster"):
            if install_with_apt("gobuster") and shutil.which("gobuster") is not None:
                print("gobuster is installed.")
                return True
            print("Gobuster install attempted, but command is still not found.")
            return False

        print("Skipped. Manual install: sudo apt install gobuster")
        return False

    print("Gobuster is installed.")
    return True

def dependency_check_nuclei():
    print("Checking if Nuclei is available for Automated Scanner...")
    if shutil.which("nuclei") is None:
        print("nuclei is not installed.")

        if ask_install("nuclei"):
            if install_with_apt("nuclei") and shutil.which("nuclei") is not None:
                print("Nuclei is installed.")
                return True
            print("Nuclei install attempted, but command is still not found.")
            return False

        print("Skipped. Manual install: sudo apt install nuclei")
        return False

    print("nuclei is installed.")
    return True

def version_check():
    print("Checking versions of installed dependencies...")
    try:
        nmap_version = subprocess.check_output(["nmap", "--version"]).decode()
        print(f"Nmap version:\n{nmap_version}")
    except subprocess.CalledProcessError:
        print("Failed to get Nmap version.")

    try:
        nikto_version = subprocess.check_output(["nikto", "-H"]).decode()
        print(f"Nikto version:\n{nikto_version}")
    except subprocess.CalledProcessError:
        print("Failed to get Nikto version.")

    try:
        gobuster_version = subprocess.check_output(["gobuster", "version"]).decode()
        print(f"Gobuster version:\n{gobuster_version}")
    except subprocess.CalledProcessError:
        print("Failed to get Gobuster version.")

    try:
        nuclei_version = subprocess.check_output(["nuclei", "-version"]).decode()
        print(f"Nuclei version:\n{nuclei_version}")
    except subprocess.CalledProcessError:
        print("Failed to get Nuclei version.")


def install_dependencies():

    nmapcheck = dependency_check_nmap()
    niktocheck = dependency_check_nikto()
    gobustercheck = dependency_check_gobuster()
    nucleicheck = dependency_check_nuclei()

    if not (nmapcheck and niktocheck and gobustercheck and nucleicheck):
        print("One or more dependencies are missing. Please install them to continue.")
        sys.exit(1)

    version_check()
    print("All dependencies are installed. Continue to Automated Scanner.")
    return True

if __name__ == "__main__":
    install_dependencies()
    sys.exit(0)

#End of dependency checker for Automated Scanner.