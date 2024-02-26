#!/bin/bash

# Usuwanie istniejącego katalogu z programem
rm -rf /root/https-security-checker

# Pobieranie najnowszej wersji z GitHub
git clone https://github.com/Adminek01/https-security-checker /root/https-security-checker

# Przejście do katalogu z programem
cd /root/https-security-checker

echo "Program został zaktualizowany i jest gotowy do użycia."
