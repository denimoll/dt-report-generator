# dt-report-generator
## Main information
Инструмент разработан для выгрузки отчетов из инструмента [Dependency Track](https://dependencytrack.org/) в форматах Word (.docx) и Excel (.xlsx). 

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
    - Report type - формат отчета
3. Нажать "Get report"
4. Подождать

## Support
Предложения и замечания принимаю в [issues](https://github.com/denimoll/dt-report-generator/issues).

## Roadmap
Запланированный функционал:
- [ ] nothing
- [ ] nothing
- [ ] nothing
