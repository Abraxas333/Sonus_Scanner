import requests


def fetch_domains():
    domains_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt"
    wildcards_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt"

    # Fetch domains
    domains_response = requests.get(domains_url)
    domains = set(domains_response.text.strip().split('\n'))

    # Fetch wildcards
    wildcards_response = requests.get(wildcards_url)
    wildcards = set(wildcards_response.text.strip().split('\n'))

    return domains | wildcards

def update_domains(file):
    with open(file, "a+") as f:
        existing_domains = set(line.strip() for line in f.readlines() if line.strip())
        new_domains = fetch_domains()
        domains_to_add = new_domains - existing_domains

        for domain in domains_to_add:
            f.write(domain + '\n')

        return list(existing_domains | new_domains)







