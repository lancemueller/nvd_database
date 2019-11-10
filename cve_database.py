import requests
import zipfile
import sqlite3 as lite
import json
import os

if __name__ == '__main__':
    con = lite.connect("nvd_db.db")
    con.text_factory = str
    with con:
        cur = con.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS cve (cve TEXT, cvss TEXT, severity TEXT, impactScore TEXT, exploitScore TEXT, desc TEXT);')
        cur.execute('delete from cve')

        years = range(2002, 2025)
        for year in years:
            try:
                base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-' + str(year) + '.json.zip'
                print base_url
                r = requests.get(base_url)
                if r.status_code == 200:
                    with open('nvdcve-1.1-' + str(year) + '.json.zip', 'wb') as f:
                        f.write(r.content)

                    with zipfile.ZipFile('nvdcve-1.1-' + str(year) + '.json.zip') as zip_ref:
                        zip_ref.extractall()
                    os.remove('nvdcve-1.1-' + str(year) + '.json.zip')

                    with open('nvdcve-1.1-' + str(year) + '.json', 'r') as f:
                        data = json.load(f)
                        for record in data['CVE_Items']:
                            if 'baseMetricV2' in record['impact']:
                                cur.execute(
                                    'INSERT OR IGNORE INTO cve (cve, cvss, severity, impactScore, exploitScore, desc) VALUES (?,?,?,?,?,?)',
                                    (record['cve']['CVE_data_meta']['ID'],
                                     record['impact']['baseMetricV2']['cvssV2']['baseScore'],
                                     record['impact']['baseMetricV2']['severity'],
                                     record['impact']['baseMetricV2']['impactScore'],
                                     record['impact']['baseMetricV2']['exploitabilityScore'],
                                     record['cve']['description']['description_data'][0]['value'])
                                )
                    os.remove('nvdcve-1.1-' + str(year) + '.json')
            except:
                print "Error! %s" % year
    con.commit()
    con.close()