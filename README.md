# dt-report-generator
## Main information
Инструмент разработан для выгрузки отчетов из [Dependency Track](https://dependencytrack.org/) в форматах Word (.docx) и Excel (.xlsx).\
Подробнее об инструменте и способе использования есть в статье на [habr](https://habr.com/ru/articles/860536/).
## Getting started
### Installation and start
№1. Python
```
# git clone <this repo>
# pip install --upgrade pip
# pip install -r requirements.txt
# python ./app.py
```
№2. Docker
```
# git clone <this repo>
# docker build -t dt-report:v1 .
# docker run -d -p 5000:5000 dt-report:v1
```
### Usage
1. Открыть в браузере [localhost:5000](http://localhost:5000)
2. Заполнить форму:
    - URL - адрес DT (формат "protocol"://"domain"). Например, [https://dependencytrack.org](https://dependencytrack.org). Автоматически подставляется путь до API - */api/v1/*
    - Token - API ключ ([как получить](https://docs.dependencytrack.org/integrations/rest-api/))
    - Project - ID проекта (параметр Object Identifier в Project Details или идентификатор в URL после ".../projects/")
    - Severities - уровни критичности
3. Нажать "Get report"
4. Подождать

## Roadmap
Запланированный функционал:
- [x] *Поиск проектов*. Упростить поиск проектов через предоставленную ссылку и токен.
- [x] *Дерево зависимостей*. Выгружать дерево с отметкой уязвимых компонентов.
- [ ] *Дашборды с обзорной информацией*. Визуализировать данные в виде различных графиков для наглядного анализа.
- [ ] *Приоритезация уязвимостей*. Реализовать логику, которая поможет оценить, какие уязвимости требуют первоочередного исправления.
- [ ] *Релизная политика*. Сформировать правила выпуска релизов и публиковать сразу Docker-образы.
- [ ] *Безопасное использование as a service*. Добавить возможность определения доверенных адресов (исключение SSRF) или отключение выбора URL и token через задание дефолтных значений.
- [ ] *Оптимизация*. Добавить БД.
