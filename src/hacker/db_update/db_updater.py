from gevent import monkey as curious_george
curious_george.patch_all(thread=False, select=False)
import grequests
from definitions import BATCH_SIZE, REQUESTS_TIMEOUT, WEBDRIVER_TIMEOUT
from db_manager.db_manager import DbManager
from hacker.db_update.cve_populator import CvePopulator
from hacker.db_update.link_collector import LinkCollector
from table_objects.vulnerability.vulnerability_info import VulnerabilityInfo
import re
import sys
import time
import os
import requests
import math
from os import path
from datetime import datetime
from operator import itemgetter
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import NoSuchElementException, TimeoutException, ElementClickInterceptedException
from alive_progress import alive_bar


class DbUpdater:

    def __init__(self, hostname, user, password, schema_name):
        self.hostname = hostname
        self.user = user
        self.password = password
        self.schema_name = schema_name

    def __batch_populate_cve_list(self, cves):
        populator = CvePopulator()

        vuln_list = []
        cve_list = []
        nvd_links = []
        nvd_data = []
        cvedetails_links = []
        cvedetails_data = []
        snyk_data = []
        jira_links = []
        jira_data = []

        for cve in cves:
            cve_list.append(cve["cve"])
            if cve["nvd"] != "":
                nvd_links.append(cve["nvd"])
            if cve["cvedetails"] != "":
                cvedetails_links.append(cve["cvedetails"])
            # Multithread requests are not used with snyk because manual clicking is needed
            if cve["snyk"] != "":
                pass
                driver_exe = 'chromedriver'
                options = Options()
                options.add_argument("--headless")
                options.add_experimental_option('excludeSwitches', ['enable-logging'])
                service = Service(log_path=path.devnull)
                driver = webdriver.Chrome(driver_exe, options=options, service=service)
                driver.set_page_load_timeout(WEBDRIVER_TIMEOUT)
                driver.get(cve["snyk"])
                soup = ""
                cve_id = ""
                try:
                    button_snyk = driver.find_element(by=By.XPATH, value='//button[@data-snyk-test="DetailsBox: expand"]')
                    button_snyk.click()
                    button_nvd = driver.find_element(by=By.CLASS_NAME, value="vendorcvss")
                    button_nvd.click()
                    soup = BeautifulSoup(driver.page_source, 'lxml')
                except (NoSuchElementException, ElementClickInterceptedException):
                    req = requests.get(cve["snyk"])
                    soup = BeautifulSoup(req.text, "lxml")
                except TimeoutException:
                    pass

                if soup.find("a", id = re.compile(r"^CVE-")):
                    cve_id = soup.find("a", id = re.compile(r"^CVE-")).contents[0].strip()
                snyk_data.append({"cve": cve_id, "data": populator.populate_snyk_data(soup)})
            if cve["jira"] != "":
                jira_links.append(cve["jira"])

        #try:
        nvd_results = grequests.map((grequests.get(u) for u in nvd_links), size=10)
        for page in nvd_results:
            soup = BeautifulSoup(page.text, "lxml")
            if soup.find(attrs={"data-testid": "vuln-cve-dictionary-entry"}):
                cve = soup.find(attrs={"data-testid": "vuln-cve-dictionary-entry"}).string.strip()
                nvd_data.append({"cve" : cve, "data" : populator.populate_nvd_data(soup)})              
        #except:
            #pass

        #try:
        cvedetails_results = grequests.map((grequests.get(u) for u in cvedetails_links), size=10)
        for page in cvedetails_results:
            soup = BeautifulSoup(page.text, "lxml")
            h1 = soup.find("h1")
            cve = h1.find("a").contents[0].strip()
            cvedetails_data.append({"cve" : cve, "data" : populator.populate_cvedetails_data(soup)})
        #except:
            #pass

        #try:
        jira_results = grequests.map((grequests.get(u) for u in jira_links), size=10)
        for page in jira_results:
            soup = BeautifulSoup(page.text, "lxml")
            cve = ""
            issue_details = soup.find("ul", id="issuedetails")
            issue_elements = []
            if issue_details:
                issue_elements = issue_details.findAll("li")
            if len(issue_elements) > 7:
                label_containers = issue_elements[7].findAll("li")
                for container in label_containers:
                    if "CVE" in container.find("span").contents[0].strip():
                        cve = container.find("span").contents[0].strip()

            jira_data.append({"cve" : cve, "data" : populator.populate_jira_data(soup)})
        #except:
            #pass

        for cve in cve_list:
            vuln = VulnerabilityInfo()
            vuln.cve = cve
            if any(x["cve"] == cve for x in nvd_data):
                vuln.nvd_data = next(x["data"] for x in nvd_data if x["cve"] == cve)
            if any(x["cve"] == cve for x in cvedetails_data):
                vuln.cvedetails_data = next(x["data"] for x in cvedetails_data if x["cve"] == cve)
            if any(x["cve"] == cve for x in snyk_data):
                vuln.snyk_data = next(x["data"] for x in snyk_data if x["cve"] == cve)
            if any(x["cve"] == cve for x in jira_data):
                vuln.jira_data = next(x["data"] for x in jira_data if x["cve"] == cve)

            vuln_list.append(vuln)

        return vuln_list

    def __batch_update_tables(self, cve_batch):
        manager = DbManager(self.hostname, self.user, self.password, self.schema_name)

        cves = []
        vulnerabilities = []
        nvd_links = []
        nvd_tags = []
        nvd_weakness_enumerations = []
        cvedetails_links = []
        cvedetails_affected_products = []
        cvedetails_affected_versions_by_product = []
        snyk_links = []
        jira_affected_versions = []
        jira_fix_versions = []
        jira_components = []
        jira_labels = []
        jira_attachments = []
        jira_links = []

        for vulnerability in cve_batch:           
            temp_vuln = (vulnerability.cve, vulnerability.fixed_commit_hash, datetime.now().isoformat(), \
                vulnerability.nvd_data.nvd_description, vulnerability.nvd_data.nvd_published_date, \
                vulnerability.nvd_data.nvd_last_modified_date, vulnerability.nvd_data.nvd_source, \
                vulnerability.nvd_data.nvd_cvss3_nist_name, vulnerability.nvd_data.nvd_cvss3_nist_score, \
                vulnerability.nvd_data.nvd_cvss3_nist_severity, vulnerability.nvd_data.nvd_cvss3_nist_vector, \
                vulnerability.nvd_data.nvd_cvss3_cna_name, vulnerability.nvd_data.nvd_cvss3_cna_score, \
                vulnerability.nvd_data.nvd_cvss3_cna_severity, vulnerability.nvd_data.nvd_cvss3_cna_vector,
                vulnerability.nvd_data.nvd_cvss2_nist_name, vulnerability.nvd_data.nvd_cvss2_nist_score, \
                vulnerability.nvd_data.nvd_cvss2_nist_severity, vulnerability.nvd_data.nvd_cvss2_nist_vector, \
                vulnerability.nvd_data.nvd_cvss2_cna_name, vulnerability.nvd_data.nvd_cvss2_cna_score, \
                vulnerability.nvd_data.nvd_cvss2_cna_severity, vulnerability.nvd_data.nvd_cvss2_cna_vector, \
                vulnerability.cvedetails_data.cvedetails_published_date, vulnerability.cvedetails_data.cvedetails_last_modified_date, \
                vulnerability.cvedetails_data.cvedetails_score, vulnerability.cvedetails_data.cvedetails_confidentiality_impact, \
                vulnerability.cvedetails_data.cvedetails_integrity_impact, vulnerability.cvedetails_data.cvedetails_availability_impact, \
                vulnerability.cvedetails_data.cvedetails_access_complexity, vulnerability.cvedetails_data.cvedetails_authentication, \
                vulnerability.cvedetails_data.cvedetails_gained_access, vulnerability.cvedetails_data.cvedetails_cwe_id, \
                vulnerability.snyk_data.snyk_name, vulnerability.snyk_data.snyk_published_date, \
                vulnerability.snyk_data.snyk_how_to_fix, \
                vulnerability.snyk_data.snyk_exploit_maturity, vulnerability.snyk_data.snyk_score, \
                vulnerability.snyk_data.snyk_attack_complexity, vulnerability.snyk_data.snyk_attack_vector, \
                vulnerability.snyk_data.snyk_privileges_required, vulnerability.snyk_data.snyk_user_interaction, \
                vulnerability.snyk_data.snyk_scope, vulnerability.snyk_data.snyk_confidentiality_impact, \
                vulnerability.snyk_data.snyk_integrity_impact, vulnerability.snyk_data.snyk_availability_impact, \
                vulnerability.snyk_data.snyk_nvd_score, vulnerability.snyk_data.snyk_nvd_attack_complexity, \
                vulnerability.snyk_data.snyk_nvd_attack_vector, vulnerability.snyk_data.snyk_nvd_privileges_required, \
                vulnerability.snyk_data.snyk_nvd_user_interaction, vulnerability.snyk_data.snyk_nvd_exploit_maturity, \
                vulnerability.snyk_data.snyk_nvd_scope, vulnerability.snyk_data.snyk_nvd_confidentiality_impact, \
                vulnerability.snyk_data.snyk_nvd_integrity_impact, vulnerability.snyk_data.snyk_nvd_availability_impact, \
                vulnerability.snyk_data.snyk_vulnerability_overview, \
                vulnerability.jira_data.type, vulnerability.jira_data.priority, \
                vulnerability.jira_data.version_introduced, vulnerability.jira_data.symptom_severity, \
                vulnerability.jira_data.status, vulnerability.jira_data.resolution, \
                vulnerability.jira_data.assignee, vulnerability.jira_data.reporter, \
                vulnerability.jira_data.affected_customers, vulnerability.jira_data.watchers, \
                vulnerability.jira_data.date_created, vulnerability.jira_data.date_updated, \
                vulnerability.jira_data.date_resolved)           
            
            vulnerabilities.append(temp_vuln)

            for link in vulnerability.nvd_data.nvd_hyperlinks:
                temp_link = (vulnerability.cve, link.link)
                nvd_links.append(temp_link)

                for tag in link.tags:
                    temp_tag = (vulnerability.cve, link.link, tag)
                    nvd_tags.append(temp_tag)

            for we in vulnerability.nvd_data.nvd_weakness_enumeration:
                temp_we = (vulnerability.cve, we.cwe_id, we.cwe_name, we.source)
                nvd_weakness_enumerations.append(temp_we)

            for link in vulnerability.cvedetails_data.cvedetails_hyperlinks:
                temp_link = (vulnerability.cve, link)
                cvedetails_links.append(temp_link)

            for ap in vulnerability.cvedetails_data.cvedetails_affected_products:
                temp_ap = (vulnerability.cve, ap.product_type, ap.vendor, ap.product, \
                    ap.version, ap.update, ap.edition, ap.language)
                cvedetails_affected_products.append(temp_ap)

            for avp in vulnerability.cvedetails_data.cvedetails_affected_versions:
                temp_avp = (vulnerability.cve, avp.vendor, avp.product, avp.vulnerable_versions)
                cvedetails_affected_versions_by_product.append(temp_avp)

            for link in vulnerability.snyk_data.snyk_hyperlinks:
                temp_link = (vulnerability.cve, link)
                snyk_links.append(temp_link)

            for version in vulnerability.jira_data.affected_versions:
                temp_version = (vulnerability.cve, version)
                jira_affected_versions.append(temp_version)

            for version in vulnerability.jira_data.fix_versions:
                temp_version = (vulnerability.cve, version)
                jira_fix_versions.append(temp_version)

            for component in vulnerability.jira_data.components:
                temp_component = (vulnerability.cve, component)
                jira_components.append(temp_component)

            for label in vulnerability.jira_data.labels:
                temp_label = (vulnerability.cve, version)
                jira_labels.append(temp_label)

            for attachment in vulnerability.jira_data.attachments:
                temp_attachment = (vulnerability.cve, attachment)
                jira_attachments.append(temp_attachment)

            for link in vulnerability.jira_data.issue_links:
                temp_link = (vulnerability.cve, link)
                jira_links.append(temp_link)

            cves.append((vulnerability.cve,))

        manager.insert_vulnerabilities(vulnerabilities)
        manager.insert_nvd_hyperlinks(nvd_links)
        manager.insert_nvd_tags(nvd_tags)
        manager.insert_nvd_weakness_enumeration(nvd_weakness_enumerations)
        manager.insert_cvedetails_hyperlinks(cvedetails_links)
        manager.insert_cvedetails_affected_products(cvedetails_affected_products)
        manager.insert_cvedetails_affected_versions_by_product(cvedetails_affected_versions_by_product)
        manager.insert_snyk_hyperlinks(snyk_links)
        manager.insert_jira_affected_versions(jira_affected_versions)
        manager.insert_jira_fix_versions(jira_fix_versions)
        manager.insert_jira_components(jira_components)
        manager.insert_jira_labels(jira_labels)
        manager.insert_jira_attachments(jira_attachments)
        manager.insert_jira_issue_links(jira_links)
        manager.delete_cve_to_download(cves)

    def __insert_cve_objects(self, cve_list):
        manager = DbManager(self.hostname, self.user, self.password, self.schema_name)

        print("CVEs to download:", len(cve_list))
        batches = math.ceil(len(cve_list) / BATCH_SIZE)
        print("Downloading batches...")
        with alive_bar(batches) as bar:
            while(len(cve_list) > 0):         
                cve_batch = cve_list[0:BATCH_SIZE] if len(cve_list) >= BATCH_SIZE else cve_list
                cve_list = cve_list[BATCH_SIZE:] if len (cve_list) >= BATCH_SIZE else []
        
                self.__batch_update_tables(self.__batch_populate_cve_list(cve_batch))

                bar()

    def populate_cve_cache(self, clear_cache):
        manager = DbManager(self.hostname, self.user, self.password, self.schema_name)

        if clear_cache:
            manager.delete_cache()

        cves_to_insert = []
        collector = LinkCollector()
        cves = collector.get_cve_to_insert()

        for cve in cves:
            nvd = ""
            cvedetails = ""
            snyk = ""
            jira = ""

            links = cve["links"]
            for link in links:
                if "nvd" in link:
                    nvd = link["nvd"]
                if "cvedetails" in link:
                    cvedetails = link["cvedetails"]
                if "snyk" in link:
                    snyk = link["snyk"]
                if "jira" in link:
                    jira = link["jira"] 

            temp_cve = (cve["cve"], nvd, cvedetails, snyk, jira)
            cves_to_insert.append(temp_cve)

        cves_already_present = [cve["cve"] for cve in manager.get_cve_list()]
        unique_cve_to_insert = [cve for cve in cves_to_insert if cve[0] not in cves_already_present]
        manager.insert_cve_to_download(unique_cve_to_insert)

    def update_db(self):
        manager = DbManager(self.hostname, self.user, self.password, self.schema_name)
        collector = LinkCollector()

        #cves_to_download = manager.get_cve_to_download()
        cves_to_download = sorted(manager.get_cve_to_download(), key=itemgetter('cve'), reverse=True)
        if cves_to_download:
            self.__insert_cve_objects(cves_to_download)
        else:
            print("Cache is empty, run populate_cache before trying to update the database")

    def __print_vulnerability_snyk(self, vuln):
        print("SNYK:")
        print(vuln.snyk_name)
        print(vuln.snyk_published_date)
        print(vuln.snyk_cwe_id)
        print(vuln.snyk_how_to_fix)
        print(vuln.snyk_exploit_maturity)
        print(vuln.snyk_score)
        print(vuln.snyk_attack_complexity)
        print(vuln.snyk_attack_vector)
        print(vuln.snyk_privileges_required)
        print(vuln.snyk_user_interaction)
        print(vuln.snyk_scope)
        print(vuln.snyk_confidentiality_impact)
        print(vuln.snyk_integrity_impact)
        print(vuln.snyk_availability_impact)
        print(vuln.snyk_nvd_score)
        print(vuln.snyk_nvd_attack_complexity)
        print(vuln.snyk_nvd_attack_vector)
        print(vuln.snyk_nvd_privileges_required)
        print(vuln.snyk_nvd_user_interaction)
        print(vuln.snyk_nvd_exploit_maturity)
        print(vuln.snyk_nvd_scope)
        print(vuln.snyk_nvd_confidentiality_impact)
        print(vuln.snyk_nvd_integrity_impact)
        print(vuln.snyk_nvd_availability_impact)
        print(vuln.snyk_hyperlinks)