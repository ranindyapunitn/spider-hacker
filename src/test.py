from hacker.db_update.db_updater import DbUpdater
from hacker.db_create.db_creator import DbCreator
from wakepy import set_keepawake, unset_keepawake
import time

def test():
    set_keepawake(keep_screen_awake=False)
    start_time = time.time()

    #creator = DbCreator('localhost', 'root', 'root', 'test')
    #creator.create_db()

    updater = DbUpdater('localhost', 'root', 'root', 'test')
    #updater.populate_cve_cache(True)
    updater.update_db()

        #with open("C:\\Users\\micha\\Documents\\output.txt", "a", encoding="utf-8") as f:
            #for vuln in cve_list:
                #print(vuln.cve, file=f)
                #print(vuln.fixed_commit_hash, file=f)
                #print(vuln.last_updated, file=f)
                #self.__print_vulnerability_nvd(vuln.nvd_data, f)
                #self.__print_vulnerability_cvedetails(vuln.cvedetails_data, f)
                #self.__print_vulnerability_snyk(vuln.snyk_data, f)
                #self.__print_vulnerability_jira(vuln.jira_data, f)
        #print(self.__get_cve_to_insert_jira())
        #self.__get_cve_to_insert()

    print("--- %s minutes ---" % ((time.time() - start_time) / 60))
    unset_keepawake()

def __print_vulnerability_nvd(self, vulnerability, f):
    print("NVD:", file=f)
    print(vulnerability.nvd_description, file=f)
    print(vulnerability.nvd_published_date, file=f)
    print(vulnerability.nvd_last_modified_date, file=f)
    print(vulnerability.nvd_source, file=f)
    print(vulnerability.nvd_cvss3_nist_name, file=f)
    print(vulnerability.nvd_cvss3_nist_score, file=f)
    print(vulnerability.nvd_cvss3_nist_severity, file=f)
    print(vulnerability.nvd_cvss3_nist_vector, file=f)
    print(vulnerability.nvd_cvss3_cna_name, file=f)
    print(vulnerability.nvd_cvss3_cna_score, file=f)
    print(vulnerability.nvd_cvss3_cna_severity, file=f)
    print(vulnerability.nvd_cvss3_cna_vector, file=f)
    print(vulnerability.nvd_cvss2_nist_name, file=f)
    print(vulnerability.nvd_cvss2_nist_score, file=f)
    print(vulnerability.nvd_cvss2_nist_severity, file=f)
    print(vulnerability.nvd_cvss2_nist_vector, file=f)
    print("hyperlinks:", file=f)
    for hyperlink in vulnerability.nvd_hyperlinks:
        print("    " + hyperlink.link, file=f)
        for tag in hyperlink.tags:
            print("        " + tag, file=f)
    print("cwe:", file=f)
    for weakness_enumeration in vulnerability.nvd_weakness_enumeration:
        print("    cwe description:", file=f)
        print("        " + weakness_enumeration.cwe_id, file=f)
        print("        " + weakness_enumeration.cwe_name, file=f)
        print("        " + weakness_enumeration.source, file=f)

def __print_vulnerability_cvedetails(self, vuln, f):
    print("CVEDETAILS:", file=f)
    print(vuln.cvedetails_score, file=f)
    print(vuln.cvedetails_confidentiality_impact, file=f)
    print(vuln.cvedetails_integrity_impact, file=f)
    print(vuln.cvedetails_availability_impact, file=f)
    print(vuln.cvedetails_access_complexity, file=f)
    print(vuln.cvedetails_authentication, file=f)
    print(vuln.cvedetails_gained_access, file=f)
    print(vuln.cvedetails_vulnerability_types, file=f)
    print(vuln.cvedetails_cwe_id, file=f)
    print("Affected Products:", file=f)
    for affected_product in vuln.cvedetails_affected_products:
        print("    " + affected_product.product_type, file=f)
        print("    " + affected_product.vendor, file=f)
        print("    " + affected_product.product, file=f)
        print("    " + affected_product.version, file=f)
        print("    " + affected_product.update, file=f)
        print("    " + affected_product.edition, file=f)
        print("    " + affected_product.language, file=f)
    print("Affected Versions:", file=f)
    for affected_version in vuln.cvedetails_affected_versions:          
        print("    " + affected_version.vendor, file=f)
        print("    " + affected_version.product, file=f)
        print("    " + affected_version.vulnerable_versions, file=f)
    print(vuln.cvedetails_hyperlinks, file=f)

def __print_vulnerability_snyk(self, vuln, f):
    print("SNYK:", file=f)
    print(vuln.snyk_name, file=f)
    print(vuln.snyk_published_date, file=f)
    print(vuln.snyk_cwe_id, file=f)
    print(vuln.snyk_how_to_fix, file=f)
    print(vuln.snyk_exploit_maturity, file=f)
    print(vuln.snyk_score, file=f)
    print(vuln.snyk_attack_complexity, file=f)
    print(vuln.snyk_attack_vector, file=f)
    print(vuln.snyk_privileges_required, file=f)
    print(vuln.snyk_user_interaction, file=f)
    print(vuln.snyk_scope, file=f)
    print(vuln.snyk_confidentiality_impact, file=f)
    print(vuln.snyk_integrity_impact, file=f)
    print(vuln.snyk_availability_impact, file=f)
    print(vuln.snyk_nvd_score, file=f)
    print(vuln.snyk_nvd_attack_complexity, file=f)
    print(vuln.snyk_nvd_attack_vector, file=f)
    print(vuln.snyk_nvd_privileges_required, file=f)
    print(vuln.snyk_nvd_user_interaction, file=f)
    print(vuln.snyk_nvd_exploit_maturity, file=f)
    print(vuln.snyk_nvd_scope, file=f)
    print(vuln.snyk_nvd_confidentiality_impact, file=f)
    print(vuln.snyk_nvd_integrity_impact, file=f)
    print(vuln.snyk_nvd_availability_impact, file=f)
    print(vuln.snyk_hyperlinks, file=f)

def __print_vulnerability_jira(self, vuln, f):
    print("JIRA:", file=f)
    print(vuln.type, file=f)
    print(vuln.priority, file=f)
    print(vuln.affected_versions, file=f)
    print(vuln.fix_versions, file=f)
    print(vuln.components, file=f)
    print(vuln.labels, file=f)
    print(vuln.version_introduced, file=f)
    print(vuln.symptom_severity, file=f)
    print(vuln.status, file=f)
    print(vuln.resolution, file=f)
    print(vuln.attachments, file=f)
    print(vuln.issue_links, file=f)
    print(vuln.assignee, file=f)
    print(vuln.reporter, file=f)
    print(vuln.affected_customers, file=f)
    print(vuln.watchers, file=f)
    print(vuln.date_created, file=f)
    print(vuln.date_updated, file=f)
    print(vuln.date_resolved, file=f)

test()