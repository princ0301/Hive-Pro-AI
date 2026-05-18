import urllib.request
import re
import os

def download_nist():
    url = "https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    html = urllib.request.urlopen(req).read().decode('utf-8')
    links = re.findall(r'href=[\'"]([^\'"]+\.csv)[\'"]', html)
    nist_url = None
    for link in links:
        if 'sp800-53r5-control-catalog' in link.lower() or 'sp800-53' in link.lower():
            nist_url = link if link.startswith('http') else "https://csrc.nist.gov" + link
            break
            
    if nist_url:
        print(f"Found NIST URL: {nist_url}")
        urllib.request.urlretrieve(nist_url, 'data/nist_800_53_rev5.csv')
        print("Downloaded NIST CSV")
    else:
        print("Could not find NIST CSV link")

def download_kev():
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    urllib.request.urlretrieve(kev_url, 'data/kev.json')
    print("Downloaded CISA KEV JSON")

if __name__ == "__main__":
    if not os.path.exists('data'):
        os.makedirs('data')
    try:
        download_kev()
        download_nist()
    except Exception as e:
        print(f"Error: {e}")
