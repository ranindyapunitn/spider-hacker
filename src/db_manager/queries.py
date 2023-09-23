"""
This class contains the text of all queries that are executed by the program
"""

class Queries:

    #
    # CREATE/DELETE TABLES
    #

    @classmethod
    def create_table_cve_to_download(cls):
        return  """CREATE TABLE {}.`CVE_TO_DOWNLOAD` (
            `CVE`                                 NVARCHAR(20)    NOT NULL,
            `NVD`                                 NVARCHAR(512)   NULL,
            `CVEDETAILS`                          NVARCHAR(512)   NULL,
            `SNYK`                                NVARCHAR(512)   NULL,
            `JIRA`                                NVARCHAR(512)   NULL,
            PRIMARY KEY (`CVE`)
            )"""

    @classmethod
    def create_table_vulnerabilities(cls):
        return """CREATE TABLE {}.`VULNERABILITIES` (
            `CVE`                                NVARCHAR(20)    NOT NULL,
            `FIXED_COMMIT_HASH`                  NVARCHAR(50)    NULL,
            `LAST_UPDATED`                       DATETIME        NULL,
            `NVD_DESCRIPTION`                    TEXT            NULL,
            `NVD_PUBLISHED_DATE`                 DATETIME        NULL,
            `NVD_LAST_MODIFIED_DATE`             TEXT            NULL,
            `NVD_SOURCE`                         TEXT            NULL,
            `NVD_CVSS3_NIST_NAME`                TEXT            NULL,
            `NVD_CVSS3_NIST_SCORE`               TEXT            NULL,
            `NVD_CVSS3_NIST_SEVERITY`            TEXT            NULL,
            `NVD_CVSS3_NIST_VECTOR`              TEXT            NULL,
            `NVD_CVSS3_CNA_NAME`                 TEXT            NULL,
            `NVD_CVSS3_CNA_SCORE`                TEXT            NULL,
            `NVD_CVSS3_CNA_SEVERITY`             TEXT            NULL,
            `NVD_CVSS3_CNA_VECTOR`               TEXT            NULL,
            `NVD_CVSS2_NIST_NAME`                TEXT            NULL,
            `NVD_CVSS2_NIST_SCORE`               TEXT            NULL,
            `NVD_CVSS2_NIST_SEVERITY`            TEXT            NULL,
            `NVD_CVSS2_NIST_VECTOR`              TEXT            NULL,
            `NVD_CVSS2_CNA_NAME`                 TEXT            NULL,
            `NVD_CVSS2_CNA_SCORE`                TEXT            NULL,
            `NVD_CVSS2_CNA_SEVERITY`             TEXT            NULL,
            `NVD_CVSS2_CNA_VECTOR`               TEXT            NULL,
            `CVEDETAILS_PUBLISHED_DATE`          DATETIME        NULL,
            `CVEDETAILS_LAST_MODIFIED_DATE`      DATETIME        NULL,
            `CVEDETAILS_SCORE`                   TEXT            NULL,
            `CVEDETAILS_CONFIDENTIALITY_IMPACT`  TEXT            NULL,
            `CVEDETAILS_INTEGRITY_IMPACT`        TEXT            NULL,
            `CVEDETAILS_AVAILABILITY_IMPACT`     TEXT            NULL,
            `CVEDETAILS_ACCESS_COMPLEXITY`       TEXT            NULL,
            `CVEDETAILS_AUTHENTICATION`          TEXT            NULL,
            `CVEDETAILS_GAINED_ACCESS`           TEXT            NULL,
            `CVEDETAILS_CWE_ID`                  TEXT            NULL,
            `CVEDETAILS_VULNERABILITY_TYPES`     TEXT            NULL,
            `SNYK_NAME`                          TEXT            NULL,
            `SNYK_PUBLISHED_DATE`                DATETIME        NULL,
            `SNYK_HOW_TO_FIX`                    TEXT            NULL,
            `SNYK_EXPLOIT_MATURITY`              TEXT            NULL,
            `SNYK_SCORE`                         TEXT            NULL,
            `SNYK_ATTACK_COMPLEXITY`             TEXT            NULL,
            `SNYK_ATTACK_VECTOR`                 TEXT            NULL,
            `SNYK_PRIVILEGES_REQUIRED`           TEXT            NULL,
            `SNYK_USER_INTERACTION`              TEXT            NULL,
            `SNYK_SCOPE`                         TEXT            NULL,
            `SNYK_CONFIDENTIALITY_IMPACT`        TEXT            NULL,
            `SNYK_INTEGRITY_IMPACT`              TEXT            NULL,
            `SNYK_AVAILABILITY_IMPACT`           TEXT            NULL,
            `SNYK_NVD_SCORE`                     TEXT            NULL,
            `SNYK_NVD_ATTACK_COMPLEXITY`         TEXT            NULL,
            `SNYK_NVD_ATTACK_VECTOR`             TEXT            NULL,
            `SNYK_NVD_PRIVILEGES_REQUIRED`       TEXT            NULL,
            `SNYK_NVD_USER_INTERACTION`          TEXT            NULL,
            `SNYK_NVD_EXPLOIT_MATURITY`          TEXT            NULL,
            `SNYK_NVD_SCOPE`                     TEXT            NULL,
            `SNYK_NVD_CONFIDENTIALITY_IMPACT`    TEXT            NULL,
            `SNYK_NVD_INTEGRITY_IMPACT`          TEXT            NULL,
            `SNYK_NVD_AVAILABILITY_IMPACT`       TEXT            NULL,
            `SNYK_OVERVIEW`                      TEXT            NULL,
            `JIRA_TYPE`                          TEXT            NULL,
            `JIRA_PRIORITY`                      TEXT            NULL,
            `JIRA_VERSION_INTRODUCED`            TEXT            NULL,
            `JIRA_SYMPTOM_SEVERITY`              TEXT            NULL,
            `JIRA_STATUS`                        TEXT            NULL,
            `JIRA_RESOLUTION`                    TEXT            NULL,
            `JIRA_ASSIGNEE`                      TEXT            NULL,
            `JIRA_REPORTER`                      TEXT            NULL,
            `JIRA_AFFECTED_CUSTOMERS`            INT             NULL,
            `JIRA_WATCHERS`                      INT             NULL,
            `JIRA_DATE_CREATED`                  DATETIME        NULL,
            `JIRA_DATE_UPDATED`                  DATETIME        NULL,
            `JIRA_DATE_RESOLVED`                 DATETIME        NULL,
            `MITRE_DATE`                         DATETIME        NULL,
            PRIMARY KEY (`CVE`)
            )"""

    @classmethod
    def create_table_nvd_hyperlinks(cls):
        return  """CREATE TABLE {}.`NVD_HYPERLINKS` (
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `LINK`                               NVARCHAR(512)   NOT NULL,
            PRIMARY KEY (`VULNERABILITY_ID`, `LINK`)
            )"""

    @classmethod
    def create_table_nvd_tags(cls):
        return """CREATE TABLE {}.`NVD_TAGS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `HYPERLINK_ID`                       NVARCHAR(512)   NOT NULL,
            `TAG_DESCRIPTION`                    TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_nvd_weakness_enumeration(cls):
        return """CREATE TABLE {}.`NVD_WEAKNESS_ENUMERATION` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `CWE_ID`                             TEXT            NULL,
            `CWE_NAME`                           TEXT            NULL,
            `SOURCE`                             TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_nvd_affected_configurations(cls):
        return """CREATE TABLE {}.`NVD_AFFECTED_CONFIGURATIONS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `VERSION_FROM_INCLUDING`             TEXT            NULL,
            `VERSION_FROM_EXCLUDING`             TEXT            NULL,
            `VERSION_UPTO_INCLUDING`             TEXT            NULL,
            `VERSION_UPTO_EXCLUDING`             TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_cvedetails_affected_products(cls):
        return """CREATE TABLE {}.`CVEDETAILS_AFFECTED_PRODUCTS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `PRODUCT_TYPE`                       TEXT            NULL,
            `VENDOR`                             TEXT            NULL,
            `PRODUCT`                            TEXT            NULL,
            `VERSION`                            TEXT            NULL,
            `UPDATE`                             TEXT            NULL,
            `EDITION`                            TEXT            NULL,
            `LANGUAGE`                           TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_cvedetails_affected_versions_by_product(cls):
        return """CREATE TABLE {}.`CVEDETAILS_AFFECTED_VERSIONS_BY_PRODUCT` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `VENDOR`                             TEXT            NULL,
            `PRODUCT`                            TEXT            NULL,
            `VULNERABLE_VERSIONS`                TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_cvedetails_hyperlinks(cls):
        return """CREATE TABLE {}.`CVEDETAILS_HYPERLINKS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `LINK`                               TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_snyk_hyperlinks(cls):
        return """CREATE TABLE {}.`SNYK_HYPERLINKS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `LINK`                               TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_jira_affected_versions(cls):
        return """CREATE TABLE {}.`JIRA_AFFECTED_VERSIONS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `VERSION`                            TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_jira_fix_versions(cls):
        return """CREATE TABLE {}.`JIRA_FIX_VERSIONS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `VERSION`                            TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_jira_components(cls):
        return """CREATE TABLE {}.`JIRA_COMPONENTS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `COMPONENT`                          TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_jira_labels(cls):
        return """CREATE TABLE {}.`JIRA_LABELS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `LABEL`                              TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_jira_attachments(cls):
        return """CREATE TABLE {}.`JIRA_ATTACHMENTS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `ATTACHMENT_LINK`                    TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def create_table_jira_issue_links(cls):
        return """CREATE TABLE {}.`JIRA_ISSUE_LINKS` (
            `ID`                                 INT             NOT NULL    AUTO_INCREMENT,
            `VULNERABILITY_ID`                   NVARCHAR(20)    NOT NULL,
            `ISSUE_LINK`                         TEXT            NULL,
            PRIMARY KEY (`ID`)
            )"""

    @classmethod
    def drop_old_schema(cls):
        return "DROP SCHEMA IF EXISTS {}"

    @classmethod
    def create_schema(cls):
        return "CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'"

    #
    # GET INFO FROM DB
    #

    @classmethod
    def get_cve_to_download(cls):
        return """SELECT `CVE`,
            `NVD`,
            `CVEDETAILS`,
            `SNYK`,
            `JIRA`
            FROM {}.`CVE_TO_DOWNLOAD`"""

    @classmethod
    def get_cve_list(cls):
        return """SELECT `CVE`, 
            `LAST_UPDATED`
            FROM {}.`VULNERABILITIES`"""

    @classmethod
    def get_vulnerabilities(cls):
        return """SELECT `CVE`,
            `FIXED_COMMIT_HASH`,
            `LAST_UPDATED`,
            `NVD_DESCRIPTION`,
            `NVD_PUBLISHED_DATE`,
            `NVD_LAST_MODIFIED_DATE`,
            `NVD_SOURCE`,
            `NVD_CVSS3_NIST_NAME`,
            `NVD_CVSS3_NIST_SCORE`,
            `NVD_CVSS3_NIST_SEVERITY`,
            `NVD_CVSS3_NIST_VECTOR`,
            `NVD_CVSS3_CNA_NAME`, 
            `NVD_CVSS3_CNA_SCORE`,
            `NVD_CVSS3_CNA_SEVERITY`,
            `NVD_CVSS3_CNA_VECTOR`,
            `NVD_CVSS2_NIST_NAME`,
            `NVD_CVSS2_NIST_SCORE`,
            `NVD_CVSS2_NIST_SEVERITY`,
            `NVD_CVSS2_NIST_VECTOR`,
            `NVD_CVSS2_CNA_NAME`, 
            `NVD_CVSS2_CNA_SCORE`,
            `NVD_CVSS2_CNA_SEVERITY`,
            `NVD_CVSS2_CNA_VECTOR`,
            `CVEDETAILS_PUBLISHED_DATE`,
            `CVEDETAILS_LAST_MODIFIED_DATE`,
            `CVEDETAILS_SCORE`,
            `CVEDETAILS_CONFIDENTIALITY_IMPACT`,
            `CVEDETAILS_INTEGRITY_IMPACT`,
            `CVEDETAILS_AVAILABILITY_IMPACT`,
            `CVEDETAILS_ACCESS_COMPLEXITY`,
            `CVEDETAILS_AUTHENTICATION`,
            `CVEDETAILS_GAINED_ACCESS`,
            `CVEDETAILS_CWE_ID`,
            `CVEDETAILS_VULNERABILITY_TYPES`,
            `SNYK_NAME`,
            `SNYK_PUBLISHED_DATE`,
            `SNYK_HOW_TO_FIX`,
            `SNYK_EXPLOIT_MATURITY`,
            `SNYK_SCORE`,
            `SNYK_ATTACK_COMPLEXITY`,
            `SNYK_ATTACK_VECTOR`,
            `SNYK_PRIVILEGES_REQUIRED`,
            `SNYK_USER_INTERACTION`,
            `SNYK_SCOPE`,
            `SNYK_CONFIDENTIALITY_IMPACT`,
            `SNYK_INTEGRITY_IMPACT`,
            `SNYK_AVAILABILITY_IMPACT`,
            `SNYK_NVD_SCORE`,
            `SNYK_NVD_ATTACK_COMPLEXITY`,
            `SNYK_NVD_ATTACK_VECTOR`,
            `SNYK_NVD_PRIVILEGES_REQUIRED`,
            `SNYK_NVD_USER_INTERACTION`,
            `SNYK_NVD_EXPLOIT_MATURITY`,
            `SNYK_NVD_SCOPE`,
            `SNYK_NVD_CONFIDENTIALITY_IMPACT`,
            `SNYK_NVD_INTEGRITY_IMPACT`,
            `SNYK_NVD_AVAILABILITY_IMPACT`,
            `SNYK_OVERVIEW`,
            `JIRA_TYPE`,
            `JIRA_PRIORITY`,
            `JIRA_VERSION_INTRODUCED`,
            `JIRA_SYMPTOM_SEVERITY`,
            `JIRA_STATUS`,
            `JIRA_RESOLUTION`,
            `JIRA_ASSIGNEE`,
            `JIRA_REPORTER`,
            `JIRA_AFFECTED_CUSTOMERS`,
            `JIRA_WATCHERS`,
            `JIRA_DATE_CREATED`,
            `JIRA_DATE_UPDATED`,
            `JIRA_DATE_RESOLVED`,
            `MITRE_DATE`
            FROM {}.`VULNERABILITIES`"""

    @classmethod
    def get_nvd_hyperlinks(cls):
        return """SELECT `VULNERABILITY_ID`,
            `LINK`
            FROM {}.`NVD_HYPERLINKS`"""

    @classmethod
    def get_nvd_tag(cls):
        return """SELECT `VULNERABILITY_ID`,
            `HYPERLINK_ID`,
            `TAG_DESCRIPTION`
            FROM {}.`NVD_TAGS`"""

    @classmethod
    def get_nvd_weakness_enumeration(cls):
        return """SELECT `VULNERABILITY_ID`,
            `CWE_ID`,
            `CWE_NAME`,
            `SOURCE`
            FROM {}.`NVD_WEAKNESS_ENUMERATION`"""

    @classmethod
    def get_nvd_affected_configuration(cls):
        return """SELECT `VULNERABILITY_ID`,
            `VERSION_FROM_INCLUDING`,
            `VERSION_FROM_EXCLUDING`,
            `VERSION_UPTO_INCLUDING`,
            `VERSION_UPTO_EXCLUDING`,
            FROM {}.`NVD_AFFECTED_CONFIGURATIONS`"""

    @classmethod
    def get_cvedetails_hyperlinks(cls):
        return """SELECT `VULNERABILITY_ID`,
            `LINK`
            FROM {}.`CVEDETAILS_HYPERLINKS`"""

    @classmethod
    def get_cvedetails_affected_products(cls):
        return """SELECT `VULNERABILITY_ID`,
            `PRODUCT_TYPE`,
            `VENDOR`,
            `PRODUCT`,
            `VERSION`,
            `UPDATE`,
            `EDITION`,
            `LANGUAGE`
            FROM {}.`CVEDETAILS_AFFECTED_PRODUCTS`"""

    @classmethod
    def get_cvedetails_affected_versions_by_product(cls):
        return """SELECT
            `VULNERABILITY_ID`,
            `VENDOR`,
            `PRODUCT`,
            `VULNERABLE_VERSIONS`
            FROM {}.`CVEDETAILS_AFFECTED_VERSIONS_BY_PRODUCT`"""

    @classmethod
    def get_snyk_hyperlinks(cls):
        return """SELECT `VULNERABILITY_ID`,
            `LINK`
            FROM {}.`SNYK_HYPERLINKS`"""

    @classmethod
    def get_jira_affected_versions(cls):
        return """SELECT `VULNERABILITY_ID`,
            `VERSION`
            FROM {}.`JIRA_AFFECTED_VERSIONS`"""

    @classmethod
    def get_jira_fix_versions(cls):
        return """SELECT `VULNERABILITY_ID`,
            `VERSION`
            FROM {}.`JIRA_FIX_VERSIONS`"""

    @classmethod
    def get_jira_components(cls):
        return """SELECT `VULNERABILITY_ID`,
            `COMPONENT`
            FROM {}.`JIRA_COMPONENTS`"""

    @classmethod
    def get_jira_labels(cls):
        return """SELECT `VULNERABILITY_ID`,
            `LABEL`
            FROM {}.`JIRA_LABELS`"""

    @classmethod
    def get_jira_attachments(cls):
        return """SELECT `VULNERABILITY_ID`,
            `ATTACHMENT_LINK`
            FROM {}.`JIRA_ATTACHMENTS`"""

    @classmethod
    def get_jira_issue_links(cls):
        return """SELECT `VULNERABILITY_ID`,
            `ISSUE_LINK`
            FROM {}.`JIRA_ISSUE_LINKS`"""

    #
    # DATABASE POPULATION
    #

    @classmethod
    def insert_cve_to_download(cls):
        return """INSERT INTO {}.`CVE_TO_DOWNLOAD`(
            `CVE`,
            `NVD`,
            `CVEDETAILS`,
            `SNYK`,
            `JIRA`
            )
            VALUES (%s, %s, %s, %s, %s)"""

    @classmethod
    def delete_cve_to_download(cls):
        return """DELETE FROM {}.`CVE_TO_DOWNLOAD`
            WHERE `CVE` = %s"""

    @classmethod
    def delete_cache(cls):
        return """DELETE FROM {}.`CVE_TO_DOWNLOAD`"""

    @classmethod
    def insert_vulnerability(cls):
        return """INSERT INTO {}.`VULNERABILITIES`(
            `CVE`,
            `FIXED_COMMIT_HASH`,
            `LAST_UPDATED`,
            `NVD_DESCRIPTION`,
            `NVD_PUBLISHED_DATE`,
            `NVD_LAST_MODIFIED_DATE`,
            `NVD_SOURCE`,
            `NVD_CVSS3_NIST_NAME`,
            `NVD_CVSS3_NIST_SCORE`,
            `NVD_CVSS3_NIST_SEVERITY`,
            `NVD_CVSS3_NIST_VECTOR`,
            `NVD_CVSS3_CNA_NAME`, 
            `NVD_CVSS3_CNA_SCORE`,
            `NVD_CVSS3_CNA_SEVERITY`,
            `NVD_CVSS3_CNA_VECTOR`,
            `NVD_CVSS2_NIST_NAME`,
            `NVD_CVSS2_NIST_SCORE`,
            `NVD_CVSS2_NIST_SEVERITY`,
            `NVD_CVSS2_NIST_VECTOR`,
            `NVD_CVSS2_CNA_NAME`, 
            `NVD_CVSS2_CNA_SCORE`,
            `NVD_CVSS2_CNA_SEVERITY`,
            `NVD_CVSS2_CNA_VECTOR`,
            `CVEDETAILS_PUBLISHED_DATE`,
            `CVEDETAILS_LAST_MODIFIED_DATE`,
            `CVEDETAILS_SCORE`,
            `CVEDETAILS_CONFIDENTIALITY_IMPACT`,
            `CVEDETAILS_INTEGRITY_IMPACT`,
            `CVEDETAILS_AVAILABILITY_IMPACT`,
            `CVEDETAILS_ACCESS_COMPLEXITY`,
            `CVEDETAILS_AUTHENTICATION`,
            `CVEDETAILS_GAINED_ACCESS`,
            `CVEDETAILS_CWE_ID`,
            `CVEDETAILS_VULNERABILITY_TYPES`,
            `SNYK_NAME`,
            `SNYK_PUBLISHED_DATE`,
            `SNYK_HOW_TO_FIX`,
            `SNYK_EXPLOIT_MATURITY`,
            `SNYK_SCORE`,
            `SNYK_ATTACK_COMPLEXITY`,
            `SNYK_ATTACK_VECTOR`,
            `SNYK_PRIVILEGES_REQUIRED`,
            `SNYK_USER_INTERACTION`,
            `SNYK_SCOPE`,
            `SNYK_CONFIDENTIALITY_IMPACT`,
            `SNYK_INTEGRITY_IMPACT`,
            `SNYK_AVAILABILITY_IMPACT`,
            `SNYK_NVD_SCORE`,
            `SNYK_NVD_ATTACK_COMPLEXITY`,
            `SNYK_NVD_ATTACK_VECTOR`,
            `SNYK_NVD_PRIVILEGES_REQUIRED`,
            `SNYK_NVD_USER_INTERACTION`,
            `SNYK_NVD_EXPLOIT_MATURITY`,
            `SNYK_NVD_SCOPE`,
            `SNYK_NVD_CONFIDENTIALITY_IMPACT`,
            `SNYK_NVD_INTEGRITY_IMPACT`,
            `SNYK_NVD_AVAILABILITY_IMPACT`,
            `SNYK_OVERVIEW`,
            `JIRA_TYPE`,
            `JIRA_PRIORITY`,
            `JIRA_VERSION_INTRODUCED`,
            `JIRA_SYMPTOM_SEVERITY`,
            `JIRA_STATUS`,
            `JIRA_RESOLUTION`,
            `JIRA_ASSIGNEE`,
            `JIRA_REPORTER`,
            `JIRA_AFFECTED_CUSTOMERS`,
            `JIRA_WATCHERS`,
            `JIRA_DATE_CREATED`,
            `JIRA_DATE_UPDATED`,
            `JIRA_DATE_RESOLVED`,
            `MITRE_DATE`
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

    @classmethod
    def insert_nvd_hyperlink(cls):
        return """INSERT INTO {}.`NVD_HYPERLINKS`(
            `VULNERABILITY_ID`,
            `LINK`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_nvd_tag(cls):
        return """INSERT INTO {}.`NVD_TAGS`(
            `VULNERABILITY_ID`,
            `HYPERLINK_ID`,
            `TAG_DESCRIPTION`
            )
            VALUES (%s, %s, %s)"""

    @classmethod
    def insert_nvd_weakness_enumeration(cls):
        return """INSERT INTO {}.`NVD_WEAKNESS_ENUMERATION`(
            `VULNERABILITY_ID`,
            `CWE_ID`,
            `CWE_NAME`,
            `SOURCE`
            )
            VALUES (%s, %s, %s, %s)"""

    @classmethod
    def insert_nvd_affected_configuration(cls):
        return """INSERT INTO {}.`NVD_AFFECTED_CONFIGURATIONS`(
            `VULNERABILITY_ID`,
            `VERSION_FROM_INCLUDING`,
            `VERSION_FROM_EXCLUDING`,
            `VERSION_UPTO_INCLUDING`,
            `VERSION_UPTO_EXCLUDING`
            )
            VALUES (%s, %s, %s, %s, %s)"""

    @classmethod
    def insert_cvedetails_hyperlinks(cls):
        return """INSERT INTO {}.`CVEDETAILS_HYPERLINKS`(
            `VULNERABILITY_ID`,
            `LINK`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_cvedetails_affected_products(cls):
        return """INSERT INTO {}.`CVEDETAILS_AFFECTED_PRODUCTS`(
            `VULNERABILITY_ID`,
            `PRODUCT_TYPE`,
            `VENDOR`,
            `PRODUCT`,
            `VERSION`,
            `UPDATE`,
            `EDITION`,
            `LANGUAGE`
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""

    @classmethod
    def insert_cvedetails_affected_versions_by_product(cls):
        return """INSERT INTO {}.`CVEDETAILS_AFFECTED_VERSIONS_BY_PRODUCT`(
            `VULNERABILITY_ID`,
            `VENDOR`,
            `PRODUCT`,
            `VULNERABLE_VERSIONS`
            )
            VALUES (%s, %s, %s, %s)"""

    @classmethod
    def insert_snyk_hyperlinks(cls):
        return """INSERT INTO {}.`SNYK_HYPERLINKS`(
            `VULNERABILITY_ID`,
            `LINK`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_jira_affected_versions(cls):
        return """INSERT INTO {}.`JIRA_AFFECTED_VERSIONS`(
            `VULNERABILITY_ID`,
            `VERSION`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_jira_fix_versions(cls):
        return """INSERT INTO {}.`JIRA_FIX_VERSIONS`(
            `VULNERABILITY_ID`,
            `VERSION`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_jira_components(cls):
        return """INSERT INTO {}.`JIRA_COMPONENTS`(
            `VULNERABILITY_ID`,
            `COMPONENT`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_jira_labels(cls):
        return """INSERT INTO {}.`JIRA_LABELS`(
            `VULNERABILITY_ID`,
            `LABEL`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_jira_attachments(cls):
        return """INSERT INTO {}.`JIRA_ATTACHMENTS`(
            `VULNERABILITY_ID`,
            `ATTACHMENT_LINK`
            )
            VALUES (%s, %s)"""

    @classmethod
    def insert_jira_issue_links(cls):
        return """INSERT INTO {}.`JIRA_ISSUE_LINKS`(
            `VULNERABILITY_ID`,
            `ISSUE_LINK`
            )
            VALUES (%s, %s)"""