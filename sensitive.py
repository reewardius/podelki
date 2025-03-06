import re

# Указываем входной и выходной файлы
input_file = "katana.txt"
output_file = "matches.txt"

# Регулярка для чувствительных файлов
pattern = re.compile(r'\b[^/\s]+\.(pem|key|pfx|p12|crt|cer|env|sql|bak|db|sqlite|mdb|ldf|mdf|cfg|config|yml|yaml|json|xml|log|ini|passwd|shadow|htpasswd|pgpass|ovpn|rdp|ps1|sh|bash_history|zsh_history|history|ssh|id_rsa|id_dsa|secrets|cred|credentials|token|backup|dump|dmp|swp|log.1|old|disabled|csv|xls|xlsx|tsv|gpg|asc|keystore|jks|pfx|p7b|p7c|crt|csr|der|pkcs12|sso|dat|cache|auth|sess|session|adb|firestore|ndjson|sqlite3|db3|db-wal|db-shm|psql|myd|myi|frm|ibd|parquet|feather|orc|avro|tar|gz|zip|rar|7z|tgz|pdf|bz2|xz|zst|bak1|bak2|old1|old2|log1|log2)\b', re.IGNORECASE)

# Читаем файл и ищем совпадения
matches = []
with open(input_file, "r", encoding="utf-8") as infile:
    for line in infile:
        if pattern.search(line):
            matches.append(line.strip())

# Сохраняем результаты
with open(output_file, "w", encoding="utf-8") as outfile:
    outfile.write("\n".join(matches))

print(f"[+] Найдено {len(matches)} совпадений. Сохранено в {output_file}")
