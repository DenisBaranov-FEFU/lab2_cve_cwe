# Firefox_Vulns
Лабораторная работа №2 Банк данных уязвимостей приложения

Проект запускался командой:

docker run --name app --network host -e DB_HOST=127.0.0.1 -v $(pwd)/data:/app/data cve_app

src/ - скрипты 

data/ - хранятся результаты работы скриптов 
