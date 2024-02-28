import subprocess

def install_packages(package_list):
    """
    Instaluje pakiety przy użyciu menedżera pakietów systemu.
    """
    for package in package_list:
        subprocess.run(['apt-get', 'install', '-y', package])

def main():
    # Lista pakietów do zainstalowania
    packages_to_install = [
        'python3',         # Python 3 interpreter
        'python3-pip',     # Python 3 package manager
        'python3-tk',      # Python 3 Tkinter (GUI toolkit)
        'python3-dev',     # Python 3 header files and static library for building Python modules
        'libssl-dev',      # SSL development libraries
        'libffi-dev',      # Foreign Function Interface (FFI) development libraries
        'tk-dev',          # Tkinter development files (for building Python GUIs)
        'tcl-dev',         # Tcl development files (for building Python GUIs)
        'scapy',           # Packet manipulation tool
        'paramiko',        # SSH library for Python
        'aiohttp',         # Asynchronous HTTP client/server framework
        'bs4',             # Beautiful Soup web scraping library
        'holehe',          # Tool for checking breached data
    ]

    # Instalacja pakietów
    install_packages(packages_to_install)

if __name__ == "__main__":
    main()
