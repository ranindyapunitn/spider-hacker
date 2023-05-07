import mysql.connector
import sys
from mysql.connector.errors import DatabaseError
from mysql.connector import errorcode
from src.db_manager.queries import Queries


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