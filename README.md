# dt-report-generator
## Main information
Tool for create reports from [Dependency Track](https://dependencytrack.org/) in Word (.docx) и Excel (.xlsx) formats.\
More information about tool and how to use it can be found in the article on [habr](https://habr.com/ru/articles/860536/) (rus).
## Getting started
### Installation and start
№1. Python
```
git clone <this repo>
pip install --upgrade pip
pip install -r requirements.txt
python ./app.py
```
№2. Docker

```
docker pull ghcr.io/denimoll/dt-report-generator:latest
docker run --name dt-report-generator -d -p 5000:5000 ghcr.io/denimoll/dt-report-generator
```
### Usage
1. Open in browser [localhost:5000](http://localhost:5000)
2. Fill out the form:
    - URL - DT address (format "protocol"://"domain"). For example, [https://dependencytrack.org](https://dependencytrack.org). The path to the API is automatically substituted - */api/v1/*
    - Token - API key ([how to get](https://docs.dependencytrack.org/integrations/rest-api/))
    - Project - project ID (Object Identifier parameter in Project Details or identifier in the URL after ".../projects/")
    - Severities - severity levels
3. Click "Get report"
4. Wait
## Roadmap
Planned functionality:
- [x] *Project search*. Simplify the search for projects via the provided link and token.
- [x] *Dependency tree*. Export the tree with vulnerable components marked.
- [x] *Release policy*. Create release rules and publish Docker images.
- [ ] *Dashboards with overview information*. Visualize data in the form of various graphs for visual analysis.
- [ ] *Vulnerability prioritization*. Implement logic that will help assess which vulnerabilities require priority fixing.
- [ ] *Secure use as a service*. Add the ability to define trusted addresses (SSRF exclusion) or disable URL and token selection by setting default values.
- [ ] *Optimization*. Add a Database.
- [ ] *Docs*. Add a documentation or just more info in readme.md for advansed settings (like custom port, use specific version and etc.)
