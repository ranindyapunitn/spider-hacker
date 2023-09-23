import mysql.connector
import sys
from mysql.connector.errors import DatabaseError
from mysql.connector import errorcode
from src.db_manager.queries import Queries
from src.table_objects.vulnerability.vulnerability_info import VulnerabilityInfo
from src.table_objects.nvd.nvd_data import NvdData
from src.table_objects.nvd.nvd_hyperlink import NvdHyperlink
from src.table_objects.nvd.nvd_weakness_enumeration import NvdWeaknessEnumeration
from src.table_objects.nvd.nvd_affected_configuration import NvdAffectedConfiguration
from src.table_objects.cvedetails.cvedetails_data import CvedetailsData
from src.table_objects.cvedetails.cvedetails_affected_product import CvedetailsAffectedProduct
from src.table_objects.cvedetails.cvedetails_affected_versions_by_product import CvedetailsAffectedVersionsByProduct
from src.table_objects.snyk.snyk_data import SnykData
from src.table_objects.jira.jira_data import JiraData


"""
This class contains all the methods that directly read/write to database
"""

class DbManager:

    def __init__(self, hostname, user, password, schema_name):
        try:
            self.connection = mysql.connector.connect(host=hostname, user=user, password=password)
        except DatabaseError as ex:
            print(ex)
            sys.exit()

        self.schema_name = schema_name

    def create_new_db(self):
        tables = {}
        tables["cve_to_download"] = (Queries.create_table_cve_to_download())  
        tables["vulnerabilitites"] = (Queries.create_table_vulnerabilities())  
        tables["nvd_hyperlinks"] = (Queries.create_table_nvd_hyperlinks())
        tables["nvd_tags"] = (Queries.create_table_nvd_tags())
        tables["nvd_weakness_enumeration"] = (Queries.create_table_nvd_weakness_enumeration())
        tables["nvd_affected_configurations"] = (Queries.create_table_nvd_affected_configurations())
        tables["cvedetails_affected_products"] = (Queries.create_table_cvedetails_affected_products())
        tables["cvedetails_affected_versions_by_product"] = (Queries.create_table_cvedetails_affected_versions_by_product())
        tables["cvedetails_hyperlinks"] = (Queries.create_table_cvedetails_hyperlinks())
        tables["snyk_hyperlinks"] = (Queries.create_table_snyk_hyperlinks())
        tables["jira_affected_versions"] = (Queries.create_table_jira_affected_versions())
        tables["jira_fix_versions"] = (Queries.create_table_jira_fix_versions())
        tables["jira_components"] = (Queries.create_table_jira_components())
        tables["jira_labels"] = (Queries.create_table_jira_labels())
        tables["jira_attachments"] = (Queries.create_table_jira_attachments())
        tables["jira_issue_links"] = (Queries.create_table_jira_issue_links())

        try:
            cursor = self.connection.cursor()
            cursor.execute(Queries.drop_old_schema().format(self.schema_name))
            cursor.execute(Queries.create_schema().format(self.schema_name))

            for table_name in tables:
                table_query = tables[table_name]
                print("    Creating table {}".format(table_name), end='\n')
                cursor.execute(table_query.format(self.schema_name))
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def delete_db(self):
        try:
            cursor = self.connection.cursor()
            cursor.execute(Queries.drop_old_schema().format(self.schema_name))
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def get_cve_list(self):
        cves = []
        try:
            cursor = self.connection.cursor()
            cursor.execute(Queries.get_cve_list().format(self.schema_name))
            result_set = cursor.fetchall()
            
            for row in result_set:
                cve = {}
                cve["cve"] = row[0]
                cve["last_updated"] = row[1]

                cves.append(cve)
        except mysql.connector.Error as err:
            print(err.msg)

        return cves

    def get_vulnerabilities(self):
        vulnerabilities = []

        try:
            cursor = self.connection.cursor()
            cursor.execute(Queries.get_vulnerabilities().format(self.schema_name))
            result_set = cursor.fetchall()
            
            for row in result_set:
                vuln = VulnerabilityInfo()
                vuln.cve = row[0]
                vuln.fixed_commit_hash = row[1]
                vuln.last_updated = row[2]
                vuln.nvd_data.nvd_description = row[3]
                vuln.nvd_data.nvd_published_date = row[4]
                vuln.nvd_data.nvd_last_modified_date = row[5]
                vuln.nvd_data.nvd_source = row[6]
                vuln.nvd_data.nvd_cvss3_nist_name = row[7]
                vuln.nvd_data.nvd_cvss3_nist_score = row[8]
                vuln.nvd_data.nvd_cvss3_nist_severity = row[9]
                vuln.nvd_data.nvd_cvss3_nist_vector = row[10]
                vuln.nvd_data.nvd_cvss3_cna_name = row[11]
                vuln.nvd_data.nvd_cvss3_cna_score = row[12]
                vuln.nvd_data.nvd_cvss3_cna_severity = row[13]
                vuln.nvd_data.nvd_cvss3_cna_vector = row[14]
                vuln.nvd_data.nvd_cvss2_nist_name = row[15]
                vuln.nvd_data.nvd_cvss2_nist_score = row[16]
                vuln.nvd_data.nvd_cvss2_nist_severity = row[17]
                vuln.nvd_data.nvd_cvss2_nist_vector = row[18]
                vuln.nvd_data.nvd_cvss2_cna_name = row[19]
                vuln.nvd_data.nvd_cvss2_cna_score = row[20]
                vuln.nvd_data.nvd_cvss2_cna_severity = row[21]
                vuln.nvd_data.nvd_cvss2_cna_vector = row[22]
                vuln.cvedetails_data.cvedetails_published_date = row[23]
                vuln.cvedetails_data.cvedetails_last_modified_date = row[24]
                vuln.cvedetails_data.cvedetails_score = row[25]
                vuln.cvedetails_data.cvedetails_confidentiality_impact = row[26]
                vuln.cvedetails_data.cvedetails_integrity_impact = row[27]
                vuln.cvedetails_data.cvedetails_availability_impact = row[28]
                vuln.cvedetails_data.cvedetails_access_complexity = row[29]
                vuln.cvedetails_data.cvedetails_authentication = row[30]
                vuln.cvedetails_data.cvedetails_gained_access = row[31]
                vuln.cvedetails_data.cvedetails_cwe_id = row[32]
                vuln.snyk_data.snyk_name = row[33]
                vuln.snyk_data.snyk_published_date = row[34]
                vuln.snyk_data.snyk_how_to_fix = row[35]
                vuln.snyk_data.snyk_exploit_maturity = row[36]
                vuln.snyk_data.snyk_score = row[37]
                vuln.snyk_data.snyk_attack_complexity = row[38]
                vuln.snyk_data.snyk_attack_vector = row[39]
                vuln.snyk_data.snyk_privileges_required = row[40]
                vuln.snyk_data.snyk_user_interaction = row[41]
                vuln.snyk_data.snyk_scope = row[42]
                vuln.snyk_data.snyk_confidentiality_impact = row[43]
                vuln.snyk_data.snyk_integrity_impact = row[44]
                vuln.snyk_data.snyk_availability_impact = row[45]
                vuln.snyk_data.snyk_nvd_score = row[46]
                vuln.snyk_data.snyk_nvd_attack_complexity = row[47]
                vuln.snyk_data.snyk_nvd_attack_vector = row[48]
                vuln.snyk_data.snyk_nvd_privileges_required = row[49]
                vuln.snyk_data.snyk_nvd_user_interaction = row[50]
                vuln.snyk_data.snyk_nvd_exploit_maturity = row[51]
                vuln.snyk_data.snyk_nvd_scope = row[52]
                vuln.snyk_data.snyk_nvd_confidentiality_impact = row[53]
                vuln.snyk_data.snyk_nvd_integrity_impact = row[54]
                vuln.snyk_data.snyk_nvd_availability_impact = row[55]
                vuln.snyk_data.snyk_vulnerability_overview = row[56]
                vuln.jira_data.type = row[57]
                vuln.jira_data.priority = row[58]
                vuln.jira_data.version_introduced = row[59]
                vuln.jira_data.symptom_severity = row[60]
                vuln.jira_data.status = row[61]
                vuln.jira_data.resolution = row[62]
                vuln.jira_data.assignee = row[63]
                vuln.jira_data.reporter = row[64]
                vuln.jira_data.affected_customers = row[65]
                vuln.jira_data.watchers = row[66]
                vuln.jira_data.date_created = row[67]
                vuln.jira_data.date_updated = row[68]
                vuln.jira_data.date_resolved = row[69]

                vulnerabilities.append(vuln)
        except mysql.connector.Error as err:
            print(err.msg)

        return vulnerabilities

    def insert_cve_to_download(self, cve_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_cve_to_download().format(self.schema_name)
            
            cursor.executemany(query, cve_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def get_cve_to_download(self):
        cves = []
        try:
            cursor = self.connection.cursor()
            cursor.execute(Queries.get_cve_to_download().format(self.schema_name))
            result_set = cursor.fetchall()
            
            for row in result_set:
                cve = {}
                cve["cve"] = row[0]
                cve["nvd"] = row[1]
                cve["cvedetails"] = row[2]
                cve["snyk"] = row[3]
                cve["jira"] = row[4]
                cve["mitre"] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + row[0]

                cves.append(cve)
        except mysql.connector.Error as err:
            print(err.msg)

        return cves

    def delete_cve_to_download(self, cve_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.delete_cve_to_download().format(self.schema_name)
            
            cursor.executemany(query, cve_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def delete_cache(self):
        try:
            cursor = self.connection.cursor()
            cursor.execute(Queries.delete_cache().format(self.schema_name))
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_vulnerabilities(self, vulnerability_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_vulnerability().format(self.schema_name)
            
            cursor.executemany(query, vulnerability_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_nvd_hyperlinks(self, hyperlink_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_nvd_hyperlink().format(self.schema_name)
            
            cursor.executemany(query, hyperlink_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_nvd_tags(self, tag_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_nvd_tag().format(self.schema_name)
            
            cursor.executemany(query, tag_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_nvd_weakness_enumeration(self, we_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_nvd_weakness_enumeration().format(self.schema_name)
            
            cursor.executemany(query, we_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_nvd_affected_configuration(self, ac_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_nvd_affected_configuration().format(self.schema_name)
            
            cursor.executemany(query, ac_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_cvedetails_hyperlinks(self, link_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_cvedetails_hyperlinks().format(self.schema_name)
            
            cursor.executemany(query, link_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_cvedetails_affected_products(self, ap_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_cvedetails_affected_products().format(self.schema_name)
            
            cursor.executemany(query, ap_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_cvedetails_affected_versions_by_product(self, avp_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_cvedetails_affected_versions_by_product().format(self.schema_name)
            
            cursor.executemany(query, avp_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_snyk_hyperlinks(self, link_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_snyk_hyperlinks().format(self.schema_name)
            
            cursor.executemany(query, link_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_jira_affected_versions(self, av_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_jira_affected_versions().format(self.schema_name)
            
            cursor.executemany(query, av_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_jira_fix_versions(self, fv_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_jira_fix_versions().format(self.schema_name)
            
            cursor.executemany(query, fv_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_jira_components(self, component_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_jira_components().format(self.schema_name)
            
            cursor.executemany(query, component_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_jira_labels(self, label_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_jira_labels().format(self.schema_name)
            
            cursor.executemany(query, label_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_jira_attachments(self, attachment_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_jira_attachments().format(self.schema_name)
            
            cursor.executemany(query, attachment_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()

    def insert_jira_issue_links(self, link_list):
        cursor = self.connection.cursor()
        try:
            query = Queries.insert_jira_issue_links().format(self.schema_name)
            
            cursor.executemany(query, link_list)
            self.connection.commit()
        except mysql.connector.Error as err:
            print(err.msg)

        cursor.close()