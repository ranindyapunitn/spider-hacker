import mysql.connector
from mysql.connector.errors import DatabaseError
from mysql.connector import errorcode


def getDescriptions(connection, cve_list):
    descriptions = []
    try:
        cve_list = tuple(cve_list)
        cursor = connection.cursor()
        placeholder= '?'
        placeholders= ', '.join(placeholder for unused in cve_list)
        query= "SELECT cve, nvd_description FROM test_final.vulnerabilities WHERE cve IN {}".format(cve_list)
        cursor.execute(query)
        result_set = cursor.fetchall()
            
        for row in result_set:
            descriptions.append({"cve": row[0], "description": row[1]})
    except mysql.connector.Error as err:
        print(err.msg)

    return descriptions

def getSnykDescriptions(connection, cve_list):
    descriptions = []
    try:
        cve_list = tuple(cve_list)
        cursor = connection.cursor()
        placeholder= '?'
        placeholders= ', '.join(placeholder for unused in cve_list)
        query= "SELECT cve, snyk_overview FROM test_final.vulnerabilities WHERE cve IN {}".format(cve_list)
        cursor.execute(query)
        result_set = cursor.fetchall()
            
        for row in result_set:
            descriptions.append({"cve": row[0], "description": row[1]})
    except mysql.connector.Error as err:
        print(err.msg)

    return descriptions

def getCvss(connection, cve):
    cvss_list = {}
    try:
        cursor = connection.cursor()
        query= "SELECT nvd_cvss3_nist_vector, nvd_cvss3_cna_vector, nvd_cvss2_nist_vector FROM test_final.vulnerabilities WHERE cve = '{}'".format(cve)
        cursor.execute(query)
        result_set = cursor.fetchall()
            
        for row in result_set:
            cvss_list = {"nvd_cvss3_nist_vector": row[0], "nvd_cvss3_cna_vector": row[1], "nvd_cvss2_nist_vector": row[2]}
    except mysql.connector.Error as err:
        print(err.msg)

    return cvss_list

def insertIntoCacheTest(connection):
    try:
        cursor = connection.cursor()
        query= """INSERT INTO test_4.cve_to_download (cve, nvd)
            VALUES('CVE-2019-16335', 'https://nvd.nist.gov/vuln/detail/CVE-2019-16335'),
            ('CVE-2012-0881', 'https://nvd.nist.gov/vuln/detail/CVE-2012-0881'),
            ('CVE-2018-11797', 'https://nvd.nist.gov/vuln/detail/CVE-2018-11797'),
            ('CVE-2020-9484', 'https://nvd.nist.gov/vuln/detail/CVE-2020-9484'),
            ('CVE-2021-21274', 'https://nvd.nist.gov/vuln/detail/CVE-2021-21274'),
            ('CVE-2018-1325', 'https://nvd.nist.gov/vuln/detail/CVE-2018-1325')"""
        cursor.execute(query)
        connection.commit()
            
    except mysql.connector.Error as err:
        print(err.msg)

def insertIntoCache(connection):
    try:
        cursor = connection.cursor()
        query = """INSERT INTO test_final_nvd.cve_to_download(
            `CVE`,
            `NVD`
            )
            VALUES (%s, %s)"""

        lines = []
        with open("chatgpt_proxy/prospector_cve_list.txt") as file:
            lines = [line.strip() for line in file]

        cve_list = []
        for line in lines:
            element = (line, 'https://nvd.nist.gov/vuln/detail/' + line)
            cve_list.append(element)

        cursor.executemany(query, cve_list)
        connection.commit()
    except mysql.connector.Error as err:
        print(err.msg)

def getVulnerabilityTypes(connection, cve):
    vulnerabilityTypes = ""
    try:
        cursor = connection.cursor()
        query= "SELECT cvedetails_vulnerability_types FROM test_final.vulnerabilities WHERE cve = '{}'".format(cve)
        cursor.execute(query)
        result_set = cursor.fetchall()
            
        for row in result_set:
            vulnerabilityTypes = row[0].strip()
    except mysql.connector.Error as err:
        print(err.msg)

    return vulnerabilityTypes

def getAffectedConfigurations(connection, cve):
    configurations = []
    try:
        cursor = connection.cursor()
        query= """SELECT version_from_including, 
                        version_from_excluding, 
                        version_upto_including,
                        version_upto_excluding
                    FROM test_final_nvd.nvd_affected_configurations 
                    WHERE vulnerability_id = '{}'""".format(cve)
        cursor.execute(query)
        result_set = cursor.fetchall()
            
        for row in result_set:
            configurations.append({"version_from_including": row[0], "version_from_excluding": row[1], \
                "version_upto_including": row[2],"version_upto_excluding": row[3]})
    except mysql.connector.Error as err:
        print(err.msg + " " + query)

    return configurations

def getCveOnSnyk(connection):
    try:
        lines = []
        with open("chatgpt_proxy/cve_list_temp") as file:
            lines = [ "'" + line.strip() + "'" for line in file]

        print(", ".join(lines))
        cursor = connection.cursor()
        query = """SELECT CVE
                    FROM test_final.vulnerabilities
                    WHERE YEAR(SNYK_PUBLISHED_DATE) >= 2017
                    AND CVE IN ({li})
            """.format(li=", ".join(lines))

        result_set = cursor.fetchall()

        for row in result_set:
                cve = row[0]
                print(cve)
    except mysql.connector.Error as err:
        print(err.msg)
