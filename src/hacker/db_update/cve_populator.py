from src.table_objects.nvd.nvd_data import NvdData
from src.table_objects.nvd.nvd_hyperlink import NvdHyperlink
from src.table_objects.nvd.nvd_weakness_enumeration import NvdWeaknessEnumeration
from src.table_objects.nvd.nvd_affected_configuration import NvdAffectedConfiguration
from src.table_objects.nvd.nvd_affected_configuration_description import NvdAffectedConfigurationDescription
from src.table_objects.cvedetails.cvedetails_data import CvedetailsData
from src.table_objects.cvedetails.cvedetails_affected_product import CvedetailsAffectedProduct
from src.table_objects.cvedetails.cvedetails_affected_versions_by_product import CvedetailsAffectedVersionsByProduct
from src.table_objects.snyk.snyk_data import SnykData
from src.table_objects.jira.jira_data import JiraData
from bs4 import BeautifulSoup
from datetime import datetime
import re


class CvePopulator:

    def __init__(self):
        pass

    def populate_nvd_data(self, soup):
        nvd_data = NvdData()

        if soup.find(attrs={"data-testid": "vuln-description"}):
            nvd_data.nvd_description = soup.find(attrs={"data-testid": "vuln-description"}).string
        if soup.find(attrs={"data-testid": "vuln-published-on"}):
            nvd_data.nvd_published_date = datetime.strptime(soup.find(attrs={"data-testid": "vuln-published-on"}).string,'%m/%d/%Y')
        if soup.find(attrs={"data-testid": "vuln-last-modified-on"}):
            nvd_data.nvd_last_modified_date = datetime.strptime(soup.find(attrs={"data-testid": "vuln-last-modified-on"}).string,'%m/%d/%Y')
        if soup.find(attrs={"data-testid": "vuln-current-description-source"}):
            nvd_data.nvd_source = soup.find(attrs={"data-testid": "vuln-current-description-source"}).string
        if soup.find(attrs={"data-testid": "vuln-cvss3-source-nvd"}):
            nvd_data.nvd_cvss3_nist_name = soup.find(attrs={"data-testid": "vuln-cvss3-source-nvd"}).string
        if soup.find("a", id="Cvss3NistCalculatorAnchor"):
            nvd_data.nvd_cvss3_nist_score = soup.find("a", id="Cvss3NistCalculatorAnchor").string.split(' ')[0]
            nvd_data.nvd_cvss3_nist_severity = soup.find("a", id="Cvss3NistCalculatorAnchor").string.split(' ')[1]      
        if soup.find(attrs={"data-testid": "vuln-cvss3-nist-vector"}):
            nvd_data.nvd_cvss3_nist_vector = soup.find(attrs={"data-testid": "vuln-cvss3-nist-vector"}).string
        if soup.find(attrs={"data-testid": "vuln-cvss3-source-cna"}):
            nvd_data.nvd_cvss3_cna_name = soup.find(attrs={"data-testid": "vuln-cvss3-source-cna"}).string
        if soup.find("a", id="Cvss3CnaCalculatorAnchor"):
            nvd_data.nvd_cvss3_cna_score = soup.find("a", id="Cvss3CnaCalculatorAnchor").string.split(' ')[0]
            nvd_data.nvd_cvss3_cna_severity = soup.find("a", id="Cvss3CnaCalculatorAnchor").string.split(' ')[1]
        if soup.find(attrs={"data-testid": "vuln-cvss3-cna-vector"}):
            nvd_data.nvd_cvss3_cna_vector = soup.find(attrs={"data-testid": "vuln-cvss3-cna-vector"}).string
        if soup.find(attrs={"data-testid": "vuln-cvss2-source-nvd"}):
            nvd_data.nvd_cvss2_nist_name = soup.find(attrs={"data-testid": "vuln-cvss2-source-nvd"}).string
        if soup.find("a", id="Cvss2CalculatorAnchor"):
            nvd_data.nvd_cvss2_nist_score = soup.find("a", id="Cvss2CalculatorAnchor").string.split(' ')[0]
            nvd_data.nvd_cvss2_nist_severity = soup.find("a", id="Cvss2CalculatorAnchor").string.split(' ')[1]
        if soup.find(attrs={"data-testid": "vuln-cvss2-panel-vector"}):
            nvd_data.nvd_cvss2_nist_vector = soup.find(attrs={"data-testid": "vuln-cvss2-panel-vector"}).string
        if soup.find(attrs={"data-testid": "vuln-cvss2-source-cna"}):
            nvd_data.nvd_cvss2_cna_name = soup.find(attrs={"data-testid": "vuln-cvss2-source-cna"}).string
        if soup.find("a", id="Cvss2CnaCalculatorAnchor"):
            nvd_data.nvd_cvss2_cna_score = soup.find("a", id="Cvss2CnaCalculatorAnchor").string.split(' ')[0]
            nvd_data.nvd_cvss2_cna_severity = soup.find("a", id="Cvss2CnaCalculatorAnchor").string.split(' ')[1]
        if soup.find(attrs={"data-testid": "vuln-cvss2-cna-vector"}):
            nvd_data.nvd_cvss2_cna_vector = soup.find(attrs={"data-testid": "vuln-cvss2-cna-vector"}).string
        
        hyperlink_elements = soup.findAll(attrs={"data-testid": re.compile(r"^vuln-hyperlinks-link")})
        tag_elements = soup.findAll(attrs={"data-testid": re.compile(r"^vuln-hyperlinks-resType")})   
        for i in range(len(hyperlink_elements)):
            hyperlink = NvdHyperlink()
            hyperlink.link = hyperlink_elements[i].string if hyperlink_elements[i] else ""
            if len(tag_elements) > i:
                tags = tag_elements[i].findAll(class_="badge")
                for tag in tags:
                    hyperlink.tags.append(tag.string)
            nvd_data.nvd_hyperlinks.append(hyperlink)

        cwe_elements = soup.findAll(attrs={"data-testid": re.compile(r"^vuln-CWEs-link")})
        cwe_sources = soup.findAll(attrs={"data-testid": re.compile(r"^vuln-cwes-assigner")})[1::2]      
        for i in range(len(cwe_elements)):      
            if i % 2 == 0:
                weakness_enumeration = NvdWeaknessEnumeration
                if cwe_elements[i].find("a", href=True):
                    weakness_enumeration.cwe_id = cwe_elements[i].find("a", href=True).string
                if len(cwe_elements) > i + 1:
                    weakness_enumeration.cwe_name = cwe_elements[i + 1].string
                if len(cwe_sources) > i:
                    # Removes non-printable characters and newline
                    weakness_enumeration.source = bytes.decode(cwe_sources[i].text.encode("ascii", errors="ignore")).strip("\n")
                nvd_data.nvd_weakness_enumeration.append(weakness_enumeration)
        
        return nvd_data

    def populate_cvedetails_data(self, soup):
        cvedetails_data = CvedetailsData()
        data_table = soup.find(lambda tag: tag.name=='table' and tag.has_attr('id') and tag['id']=="cvssscorestable") 
        data_table_rows = data_table.findAll(lambda tag: tag.name=='tr')
        
        if soup.find("div", class_="cvssbox"):
            cvedetails_data.cvedetails_score = soup.find("div", class_="cvssbox").string

        if len(data_table_rows) > 1:
            row_confidentiality_impact = data_table_rows[1]
            td = row_confidentiality_impact.find("td")
            if td.select("span:first-child"):
                cvedetails_data.cvedetails_confidentiality_impact = td.select("span:first-child")[0].string

        if len(data_table_rows) > 2:
            row_integrity_impact = data_table_rows[2]
            td = row_integrity_impact.find("td")
            if td.select("span:first-child"):
                cvedetails_data.cvedetails_integrity_impact = td.select("span:first-child")[0].string

        if len(data_table_rows) > 3:
            row_availability_impact = data_table_rows[3]
            td = row_availability_impact.find("td")
            if td.select("span:first-child"):
                cvedetails_data.cvedetails_availability_impact = td.select("span:first-child")[0].string

        if len(data_table_rows) > 4:
            row_access_complexity = data_table_rows[4]
            td = row_access_complexity.find("td")
            if td.select("span:first-child"):
                cvedetails_data.cvedetails_access_complexity = td.select("span:first-child")[0].string
        
        if len(data_table_rows) > 5:
            row_authentication = data_table_rows[5]
            td = row_authentication.find("td")
            if td.select("span:first-child"):
                cvedetails_data.cvedetails_authentication = td.select("span:first-child")[0].string

        if len(data_table_rows) > 6:
            row_gained_access = data_table_rows[6]
            td = row_gained_access.find("td")
            if td.select("span:first-child"):
                cvedetails_data.cvedetails_gained_access = td.select("span:first-child")[0].string

        if len(data_table_rows) > 7:
            row_vulnerability_types = data_table_rows[7]
            td = row_vulnerability_types.find("td")
            if td:
                for span in td.findAll("span"):       
                    cvedetails_data.cvedetails_vulnerability_types.append(span.text)

        if len(data_table_rows) > 8:
            row_cwe_id = data_table_rows[8]
            td = row_cwe_id.find("td")
            if td:
                cvedetails_data.cvedetails_cwe_id = td.string

        affected_products_table = soup.find("table", id="vulnprodstable")
        if affected_products_table:
            trs = affected_products_table.findAll("tr")[1:]
            for tr in trs:
                affected_product = CvedetailsAffectedProduct()
                tds = tr.findAll("td")
                if len(td) > 1:
                    affected_product.product_type = tds[1].string.strip()
                if len(td) > 2:
                    affected_product.vendor = tds[2].find("a").string.strip()
                if len(td) > 3:
                    affected_product.product = tds[3].find("a").string.strip()
                if len(td) > 4:
                    affected_product.version = tds[4].string.strip()
                if len(td) > 5:
                    affected_product.update = tds[5].string.strip()
                if len(td) > 6:
                    affected_product.edition = tds[6].string.strip()
                if len(td) > 7:
                    affected_product.language = tds[7].string.strip()
                cvedetails_data.cvedetails_affected_products.append(affected_product)

        affected_versions_table = soup.find("table", id="vulnversconuttable")
        if affected_versions_table:
            trs = affected_versions_table.findAll("tr")[1:]
            for tr in trs:
                affected_version = CvedetailsAffectedVersionsByProduct()
                tds = tr.findAll("td")
                if len(td) > 0:
                    affected_version.vendor = tds[0].find("a").string.strip()
                if len(td) > 1:
                    affected_version.product = tds[1].find("a").string.strip()
                if len(td) > 2:
                    affected_version.vulnerable_versions = tds[2].string.strip()
                cvedetails_data.cvedetails_affected_versions.append(affected_version)

        hyperlinks_table = soup.find("table", id="vulnrefstable")
        if hyperlinks_table:
            trs = hyperlinks_table.findAll("tr")
            for tr in trs:
                cvedetails_data.cvedetails_hyperlinks.append(tr.find("a")["href"])

        return cvedetails_data

    def populate_snyk_data(self, soup):
        snyk_data = SnykData()

        if soup.find("h1", class_="vue--heading title"):
            snyk_data.snyk_name = soup.find("h1", class_="vue--heading title").contents[0].strip()
        if soup.find("h4", class_="vue--heading date"):
            snyk_data.snyk_published_date = datetime.strptime(re.subn("Introduced: ", "", soup.find("h4", class_="vue--heading date").string.strip())[0], "%d %b %Y")
        if soup.find("a", id = re.compile(r"^CWE")):
            snyk_data.snyk_cwe_id = soup.find("a", id = re.compile(r"^CWE")).contents[0].strip()

        how_to_fix_block = soup.find("div", class_="vue--block vuln-page__instruction-block vue--block--instruction")        
        if how_to_fix_block:
            how_to_fix = how_to_fix_block.find("div", class_="vue--markdown-to-html markdown-description")
            if how_to_fix:
                snyk_data.snyk_how_to_fix = re.sub('<[^<]+?>', '', str(how_to_fix.find("p")))

        if soup.find(attrs={"data-snyk-test": "severity widget score"}):
            snyk_data.snyk_score = soup.find(attrs={"data-snyk-test": "severity widget score"}).get("data-snyk-test-score")

        snyk_block = soup.find("div", class_="cvss-details")

        if snyk_block:
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Exploit Maturity"}):
                snyk_exploit_maturity_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Exploit Maturity"})
                if snyk_exploit_maturity_block:
                    if snyk_exploit_maturity_block.find("strong"):
                        snyk_data.snyk_exploit_maturity = snyk_exploit_maturity_block.find("strong").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Complexity"}):
                snyk_attack_complexity_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Complexity"})
                if snyk_attack_complexity_block:
                    if snyk_attack_complexity_block.find("strong"):
                        snyk_data.snyk_attack_complexity = snyk_attack_complexity_block.find("strong").string.strip()

            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Availability"}):
                snyk_availability_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Availability"})
                if snyk_availability_block:
                    if snyk_availability_block.find("span", class_="vue--badge__text"):
                        snyk_data.snyk_availability_impact = snyk_availability_block.find("span", class_="vue--badge__text").string.strip()

            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Vector"}):
                snyk_attack_vector_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Vector"})
                if snyk_attack_vector_block:
                    if snyk_attack_vector_block.find("strong"):
                        snyk_data.snyk_attack_vector = snyk_attack_vector_block.find("strong").string.strip()

            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Privileges Required"}):
                snyk_privileges_required_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Privileges Required"})
                if snyk_privileges_required_block:
                    if snyk_privileges_required_block.find("strong"):
                        snyk_data.snyk_privileges_required= snyk_privileges_required_block.find("strong").string.strip()

            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: User Interaction"}):
                snyk_user_interaction_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: User Interaction"})
                if snyk_user_interaction_block:
                    if snyk_user_interaction_block.find("strong"):
                        snyk_data.snyk_user_interaction = snyk_user_interaction_block.find("strong").string.strip()

            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Scope"}):
                snyk_scope_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Scope"})
                if snyk_scope_block:
                    if snyk_scope_block.find("strong"):
                        snyk_data.snyk_scope = snyk_scope_block.find("strong").string.strip()

            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Confidentiality"}):
                snyk_confidentiality_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Confidentiality"})
                if snyk_confidentiality_block:
                    if snyk_confidentiality_block.find("strong"):
                        snyk_data.snyk_confidentiality_impact = snyk_confidentiality_block.find("strong").string.strip()

            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Integrity"}):
                snyk_integrity_block = snyk_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Integrity"})
                if snyk_integrity_block:
                    if snyk_integrity_block.find("strong"):
                        snyk_data.snyk_integrity_impact = snyk_integrity_block.find("strong").string.strip()

        vendor_block = soup.find("div", class_="vendorcvss")

        if vendor_block:
            if soup.find(attrs={"data-snyk-test": "VendorCvssCard: Badge"}):
                snyk_data.snyk_nvd_score = vendor_block.find(attrs={"data-snyk-test": "VendorCvssCard: Badge"}).contents[0].strip()
    
            if soup.find(attrs={"data-snyk-test": "VendorCvssCard: Badge"}):
                vendor_score_block = vendor_block.find(attrs={"data-snyk-test": "VendorCvssCard: Badge"})
                if vendor_score_block:
                    if vendor_score_block.find("span"):
                        snyk_data.snyk_nvd_score = vendor_score_block.find("span").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Complexity"}):
                vendor_attack_complexity_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Complexity"})
                if vendor_attack_complexity_block:
                    if vendor_attack_complexity_block.find("strong"):
                        snyk_data.snyk_nvd_attack_complexity = vendor_attack_complexity_block.find("strong").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Availability"}):
                vendor_availability_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Availability"})
                if vendor_availability_block:
                    if vendor_availability_block.find("span", class_="vue--badge__text"):
                        snyk_data.snyk_nvd_availability_impact = vendor_availability_block.find("span", class_="vue--badge__text").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Vector"}):
                vendor_attack_vector_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Attack Vector"})
                if vendor_attack_vector_block:
                    if vendor_attack_vector_block.find("strong"):
                        snyk_data.snyk_nvd_attack_vector = vendor_attack_vector_block.find("strong").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Privileges Required"}):
                vendor_privileges_required_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Privileges Required"})
                if vendor_privileges_required_block:
                    if vendor_privileges_required_block.find("strong"):
                        snyk_data.snyk_nvd_privileges_required = vendor_privileges_required_block.find("strong").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: User Interaction"}):
                vendor_user_interaction_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: User Interaction"})
                if vendor_user_interaction_block:
                    if vendor_user_interaction_block.find("strong"):
                        snyk_data.snyk_nvd_user_interaction = vendor_user_interaction_block.find("strong").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Scope"}):
                vendor_scope_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Scope"})
                if vendor_scope_block:
                    if vendor_scope_block.find("strong"):
                        snyk_data.snyk_nvd_scope = vendor_scope_block.find("strong").string.strip()
    
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Confidentiality"}):
                vendor_confidentiality_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Confidentiality"})
                if vendor_confidentiality_block:
                    if vendor_confidentiality_block.find("strong"):
                        snyk_data.snyk_nvd_confidentiality_impact = vendor_confidentiality_block.find("strong").string.strip()
            
            if soup.find(attrs={"data-snyk-test": "CvssDetailsItem: Integrity"}):
                vendor_integrity_block = vendor_block.find(attrs={"data-snyk-test": "CvssDetailsItem: Integrity"})
                if vendor_integrity_block:
                    if vendor_integrity_block.find("strong"):
                        snyk_data.snyk_nvd_integrity_impact = vendor_integrity_block.find("strong").string.strip()

        container = soup.find("div", class_="vue--layout-container vuln-page__body-wrapper grid-wrapper")
        if container:
            left_container = container.find("div", class_="left")
            if left_container:
                sections = left_container.findAll("div", class_="markdown-section")
                for section in sections:
                    if section.find("h2", class_="vue--heading heading").contents[0].strip() == "References":
                        links = section.findAll("a")
                        for link in links:
                            snyk_data.snyk_hyperlinks.append(link['href'])

        return snyk_data

    def populate_jira_data(self, soup):
        jira_data = JiraData()

        issue_details = soup.find("ul", id="issuedetails")
        issue_elements = []
        if issue_details:
            issue_elements = issue_details.findAll("li")

        index = 0
        for element in issue_elements:
            if index == 0:
                jira_data.type = element.find("span").contents[2].strip()
            elif index == 1:
                jira_data.status = element.find('span', {"data-tooltip": True}).contents[0].strip()
            elif index == 2:
                jira_data.priority = element.find("span").contents[2].strip()
            elif index == 3:
                jira_data.resolution = element.find("span", id="resolution-val").contents[0].strip()
            elif index == 4:
                version_fields = element.findAll("span", id="versions-field")
                for version in version_fields:                   
                    jira_data.affected_versions.append(version.find("span").contents[0].strip())
            elif index == 5:
                version_fields = element.findAll("span", id="fixVersions-field")
                for version in version_fields:                   
                    jira_data.fix_versions.append(version.find("a").contents[0].strip())
            elif index == 6:
                component_fields = element.findAll("span", id="components-field")
                for component in component_fields:                   
                    jira_data.components.append(component.find("a").contents[0].strip())
            elif index == 7:
                label_containers = element.findAll("li")
                for container in label_containers:
                    jira_data.labels.append(container.find("span").contents[0].strip())

            index = index + 1       
        
        if soup.find("strong", {"title" : "Introduced in Version"}):
            jira_data.version_introduced = soup.find("strong", {"title" : "Introduced in Version"}).findNext().contents[0].strip()
        if soup.find("strong", {"title" : "Symptom Severity"}):
            jira_data.symptom_severity = soup.find("strong", {"title" : "Symptom Severity"}).findNext().contents[0].strip()        
        
        jira_data.attachments = []

        links_container = soup.find("div", class_="links-container")
        if links_container:
            links = links_container.findAll("a", class_="link-title")
            if links:
                for link in links:
                    jira_data.issue_links.append(link["href"])

        if soup.find("span", id="assignee-val"):
            jira_data.assignee = soup.find("span", id="assignee-val").contents[2].strip()
        if soup.find("span", id="reporter-val"):
            reporter_val = soup.find("span", id="reporter-val")
            jira_data.reporter = reporter_val.select("span:first-child")[0].contents[2].strip()
        if soup.find("aui-badge", id="vote-data"):
            jira_data.affected_customers = soup.find("aui-badge", id="vote-data").contents[0].strip()
        if soup.find("aui-badge", id="watcher-data"):
            jira_data.watchers = soup.find("aui-badge", id="watcher-data").contents[0].strip()

        date_created = soup.find("span", {"data-name" : "Created"})
        if date_created:
            if "ago" not in date_created.find("time").contents[0].strip():
                jira_data.date_created = datetime.strptime(date_created.find("time").contents[0].strip(), "%d/%b/%Y %I:%M %p")

        date_updated = soup.find("span", {"data-name" : "Updated"})
        if date_updated:
            if "ago" not in date_updated.find("time").contents[0].strip():
                jira_data.date_updated = datetime.strptime(date_updated.find("time").contents[0].strip(), "%d/%b/%Y %I:%M %p")

        date_resolved = soup.find("span", {"data-name" : "Resolved"})
        if date_resolved:
            if "ago" not in date_resolved.find("time").contents[0].strip():
                jira_data.date_resolved = datetime.strptime(date_resolved.find("time").contents[0].strip(), "%d/%b/%Y %I:%M %p")

        return jira_data