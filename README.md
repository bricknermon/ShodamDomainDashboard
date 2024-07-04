# ShodanDomainDashboard

ShodanDomainDashboard is a locally hosted tool that tracks domain metrics and trends over time using the Shodan API. Plug in your Shodan API key, specify the domains, and monitor your domains effectively.

## Features

- Track domain metrics and trends over time.
- Visualize data using interactive dashboards.
- Easy setup with minimal configuration.
- Utilize Shodan API to gather detailed information about your domains.
- Locally hosted metrics and data.

## Installation

To run this project, you need to install the following Python packages:

```bash
pip install dash dash-core-components dash-html-components dash-bootstrap-components dash-table pandas numpy plotly shodan 
```

## Usage

1.  Clone the repository:
```bash
git clone https://github.com/bricknermon/ShodanDomainDashboard.git
cd ShodanDomainDashboard
```

2. Configure your Shodan API key:
- Open the 'scan_and_store.py' file and add your Shodain API KEY:
```bash
SHODAN_API_KEY = 'API KEY HERE'
```

3. Specify the domains you want to track in the 'domains.csv' file.

4. Scan the domains (may take a few minutes to complete depending on amount of scanned domains):
```bash
python scan_and_store.py
```
4. Run the application:
```bash
python dashboard.py
```

5. Open the application on browser:
127.0.0.1:8050

## Demo
![demo](https://github.com/bricknermon/ShodanDomainDashboard/assets/94518180/bd951353-1f0a-463c-a5a9-5243ae705eb1)
