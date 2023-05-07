import grequests
from bs4 import BeautifulSoup
import requests
import re
from datetime import datetime
from collections import defaultdict


class LinkCollector:

    def __init__(self):
        pass

    def __get_cve_to_insert_nvd(self):
        print("Gathering CVEs from NVD...")
        req = requests.get("https://nvd.nist.gov/vuln/full-listing")
        soup = BeautifulSoup(req.text, "lxml")
        month_links = [a['href'] for a in soup.findAll("a", href = re.compile(r"^/vuln/full-listing/"))]

        cve_list_nvd = []
        for link in month_links:
            req = requests.get("https://nvd.nist.gov" + link)
            soup = BeautifulSoup(req.text, "lxml")
            cve_codes = [a.string for a in soup.findAll("a", href = re.compile(r"^/vuln/detail/"))]
            for cve in cve_codes:
                cve_list_nvd.append({"cve" : cve, "nvd" : "https://nvd.nist.gov/vuln/detail/" + cve})

            #if(len(cve_list_nvd) > 200):
                #break

        print("CVEs from NVD completed")
        return cve_list_nvd#[:200]

    def __get_cve_to_insert_cvedetails(self):
        print("Gathering CVEs from CveDetails...")
        req = requests.get("https://www.cvedetails.com/browse-by-date.php")
        soup = BeautifulSoup(req.text, "lxml")
        year_links = [a['href'] for a in soup.findAll("a", href = re.compile(r"/vulnerabilities.html$"))]

        cve_list_cvedetails = []
        for link in year_links:
            req = requests.get("https://www.cvedetails.com" + link)
            soup = BeautifulSoup(req.text, "lxml")
            page_container = soup.find("div", id="pagingb")
            page_list = [a['href'] for a in page_container.findAll("a", href = re.compile(r"/vulnerability-list.php\?vendor_id"))]      
            results = grequests.map((grequests.get("https://www.cvedetails.com" + u) for u in page_list), size=10)

            for page in results:
                soup = BeautifulSoup(page.text, "lxml")
                cve_codes = [a.string for a in soup.findAll("a", href = re.compile(r"^/cve/CVE"))]
                for cve in cve_codes:
                    cve_list_cvedetails.append({"cve" : cve, "cvedetails" : "https://www.cvedetails.com/cve/" + cve})
                
            #if(len(cve_list_cvedetails) > 200):
                #break

        print("CVEs from cvedetails completed")
        return cve_list_cvedetails#[:200]

    def __get_cve_to_insert_snyk(self):
        print("Gathering CVEs from Snyk...")
        cve_list_snyk = []
        page_index = 2
        links = []
        req = requests.get("https://security.snyk.io/disclosed-vulnerabilities/" + str(page_index))
        soup = BeautifulSoup(req.text, "lxml")
        cve_snyk_links = soup.findAll("a", href = re.compile(r"^/vuln/SNYK-"))
        while cve_snyk_links:
            req = requests.get("https://security.snyk.io/disclosed-vulnerabilities/" + str(page_index))
            soup = BeautifulSoup(req.text, "lxml")
            cve_snyk_links = soup.findAll("a", href = re.compile(r"^/vuln/SNYK-"))
            links.extend([a["href"] for a in cve_snyk_links if "Malicious Package" not in a.contents[0]])
            page_index = page_index + 1
            
        for link in links:
            req = requests.get("https://security.snyk.io" + link)
            soup = BeautifulSoup(req.text, "lxml")
            cve_container = soup.find("span", class_="cve")
            if cve_container.find("a", class_="vue--anchor"):
                cve_code = cve_container.find("a", class_="vue--anchor").contents[0]
                cve_list_snyk.append({"cve" : cve_code, "snyk" : "https://security.snyk.io" + link})

            #if(len(cve_list_snyk) > 200):
                #break

        print("CVEs from snyk completed")
        return cve_list_snyk#[:200]

    def __get_cve_to_insert_jira(self):
        print("Gathering CVEs from Jira...")
        cve_list_jira = []
        links = []
        # No CVEs exists before this date
        year_bottom = 2014
        year_top = 2015

        while year_bottom <= datetime.now().year:
            start_index = 0
            result_end = 0
            
            while True:
                index_string = ""
                if start_index > 0:
                    index_string = "&startIndex=" + str(start_index)
                req = requests.get("https://jira.atlassian.com/issues/?jql=project%20%3D%20JRASERVER%20AND%20issuetype%20in%20(Bug%2C%20%22Public%20Security%20Vulnerability%22)%20AND%20created%20%3E%20%27" + str(year_bottom) + "%2F02%2F07%27%20and%20created%20%3C%20%20%27" + str(year_top) + "%2F02%2F07%27%20order%20by%20created%20ASC" + index_string)
                soup = BeautifulSoup(req.text, "lxml")
                current_links = []
                page_links = []
                summaries = soup.findAll("li", {"data-key" : re.compile(r"^JRASERVER")})
                for summary in summaries:
                    current_links.append({"link": summary.find("a")["href"], "isCVE": True if "CVE-" in summary.find("span", class_="issue-link-summary").contents[0] else False})

                start_index = start_index + 50

                # breaks out of cycle if end of pagination is reached
                if current_links and current_links[0]["link"] in [d["link"] for d in links]:
                    break

                links.extend(current_links)

            year_bottom = year_bottom + 1
            year_top = year_top + 1

        links = [d["link"] for d in links if d["isCVE"]]

        for link in links:
            req = requests.get("https://jira.atlassian.com" + link)
            soup = BeautifulSoup(req.text, "lxml")
            cve_label = soup.find('a', {'title' : re.compile(r"^CVE")})
            if(cve_label):
                cve_list_jira.append({"cve" : cve_label['title'], "jira" : "https://jira.atlassian.com" + link})

            #if(len(cve_list_jira) > 200):
                #break

        print("CVEs from jira completed")
        return cve_list_jiral1a

    def get_cve_to_insert(self):
        cve_list =  self.__get_cve_to_insert_nvd() + self.__get_cve_to_insert_jira()
        #cve_list =  self.__get_cve_to_insert_nvd() + self.__get_cve_to_insert_cvedetails() + self.__get_cve_to_insert_snyk() + self.__get_cve_to_insert_jira()

        merge_by_keys = ['cve']
        out = defaultdict(list)
        for entry in cve_list:
            out[tuple((entry[x],x) for x in merge_by_keys)].append({k: v for k, v in entry.items() if k not in merge_by_keys})
        result = []
        for k, v in out.items():
            result.append({})
            for x in k:
                result[-1][x[1]] = x[0]
            result[-1]['links'] = v

        return result