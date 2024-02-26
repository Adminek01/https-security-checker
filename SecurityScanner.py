import os

def scan_ports(target, start_port, end_port):
    # Implementacja skanowania portów

def ddos_attack(target):
    # Implementacja ataku DDoS

def brute_force(target):
    # Implementacja ataku brute force

def sql_injection(target_url):
    # Implementacja testu SQL injection

def personal_data_scan(target_url):
    # Implementacja skanowania danych osobowych

def main():
    print("Witaj w narzędziu Security Scanner!")
    print("Wybierz akcję:")
    print("1. Skanowanie portów")
    print("2. Atak DDoS")
    print("3. Atak brute force")
    print("4. Test SQL injection")
    print("5. Skanowanie danych osobowych")
    choice = input("Wybierz opcję: ")

    if choice == "1":
        target = input("Podaj adres IP docelowego hosta: ")
        start_port = int(input("Podaj początkowy port skanowania: "))
        end_port = int(input("Podaj końcowy port skanowania: "))
        scan_ports(target, start_port, end_port)
    elif choice == "2":
        target = input("Podaj adres IP docelowego hosta: ")
        ddos_attack(target)
    elif choice == "3":
        target = input("Podaj adres IP docelowego hosta: ")
        brute_force(target)
    elif choice == "4":
        target_url = input("Podaj adres URL do przetestowania: ")
        sql_injection(target_url)
    elif choice == "5":
        target_url = input("Podaj adres URL do przetestowania: ")
        personal_data_scan(target_url)
    else:
        print("Nieprawidłowy wybór.")

if __name__ == "__main__":
    main()