📌 Итог по машине Kenobi:
Этап	Что сделали
1. Разведка	Nmap, enum4linux, smbclient
2. Доступ	ProFTPD mod_copy → скопировали SSH-ключ в шару
3. Вход	SSH as kenobi
4. Эскалация	SUID-бинарник /usr/bin/menu → подмена PATH → root