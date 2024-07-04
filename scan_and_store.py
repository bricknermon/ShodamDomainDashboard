
import shodan
import csv
import sqlite3

SHODAN_API_KEY = 'key_here'
api = shodan.Shodan(SHODAN_API_KEY)


def initialize_db():
    conn = sqlite3.connect('scan_data.db')
    cursor = conn.cursor()

    # Create 'domains' table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS domains (
                          id INTEGER PRIMARY KEY,
                          domain_name TEXT NOT NULL,
                          scan_date DATE NOT NULL
                      )''')

    # Create 'domain_data' table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS domain_data (
                          id INTEGER PRIMARY KEY,
                          domain_id INTEGER,
                          subdomain TEXT,
                          address TEXT,
                          open_ports TEXT,
                          vulnerabilities TEXT,
                          FOREIGN KEY (domain_id) REFERENCES domains(id)
                      )''')

    conn.commit()
    conn.close()


def get_dns_data(domain):
    try:
        return api.dns.domain_info(domain).get("data", [])
    except shodan.APIError:
        return []

def get_host_details(ip):
    try:
        return api.host(ip)
    except shodan.APIError:
        return None

def process_domain(domain):
    dns_entries = get_dns_data(domain)
    domain_data = []
    for entry in dns_entries:
        if entry["type"] in ["A", "CNAME"]:
            subdomain = f"{entry['subdomain']}.{domain}" if entry['subdomain'] else domain
            address = entry.get('value', 'N/A')
            ports = ', '.join(map(str, entry.get('ports', [])))
            vulnerabilities = 'None'
            
            if entry["type"] == "A" and 'value' in entry:
                host_details = get_host_details(entry['value'])
                if host_details and 'vulns' in host_details:
                    vulnerabilities = ', '.join(host_details['vulns'])
            
            domain_data.append((subdomain, address, ports, vulnerabilities))
    return domain_data

def store_in_db(domain, domain_data):
    conn = sqlite3.connect('scan_data.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO domains (domain_name, scan_date) VALUES (?, date("now"))', (domain,))
    domain_id = cursor.lastrowid
    for data in domain_data:
        cursor.execute('INSERT INTO domain_data (domain_id, subdomain, address, open_ports, vulnerabilities) VALUES (?, ?, ?, ?, ?)', (domain_id, *data))
    conn.commit()
    conn.close()

def main():
    initialize_db()  # Initialize the database before any operations
    with open('domains.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header
        
        for row in reader:
            domain = row[0]
            domain_data = process_domain(domain)
            store_in_db(domain, domain_data)

    print("Processing complete. Data saved to scan_data.db")

if __name__ == "__main__":
    main()
