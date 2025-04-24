#!/bin/bash

# Проверяем, существует ли исходный файл
INPUT_FILE="alive_http_services.txt"
if [ ! -f "$INPUT_FILE" ]; then
  echo "Файл $INPUT_FILE не найден!"
  exit 1
fi

# Чистим старые файлы
rm -f part_* part_*.out nuclei.txt

# Разбиваем файл на 3 части
split -n l/3 "$INPUT_FILE" part_

# Запускаем nuclei параллельно
parallel -j 3 "nuclei -l {} -itags config,exposure -etags ssl,tls,headers -es unknown -rl 1000 -c 100 -o {}.out" ::: part_*

# Объединяем результаты в nuclei.txt
cat part_*.out > nuclei.txt

# Удаляем временные файлы
rm -f part_* part_*.out

echo "Готово. Результаты сохранены в nuclei.txt"
