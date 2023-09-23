import openai
import json
from types import SimpleNamespace
import requests
from packaging.version import Version
from src.chatgpt_proxy.proxy_db import getCvss
from src.chatgpt_proxy.proxy_db import getVulnerabilityTypes
from src.chatgpt_proxy.proxy_db import getAffectedConfigurations
import mysql.connector
import re
from googlesearch import search


connection = mysql.connector.connect(host="localhost", user="root", password="root")

def getUrls():
    ret_list = []
    response_list = getChatGptResponseFromFile()

    for resp in response_list:
        resp["json"] = resp["json"].strip()

        try:
            json_deserialized = json.loads(resp["json"], object_hook=lambda d: SimpleNamespace(**d))
            print(resp["cve"].strip())

            affected_product = json_deserialized.affected_product
            if not affected_product.github_url:
                result_list = search(affected_product.package_name + " github")
                for result in result_list:
                    if result.startswith("https://github.com/") and result != "https://github.com/":
                        ret_list.append(result)
                        print(result.strip())
                        break
        except:
            print("not")
            continue      

    print("\n\nFinal number: " + str(len(ret_list)))

def createVersionIntervals():
    combined_list = []
    with open("chatgpt_proxy/results_final.json", "r") as file:
        result = json.load(file)

        affected_versions_res = result["affected_versions_true_list"]
        fix_versions = result["fix_versions_true_list"]
        combined_list = list(set(affected_versions_res) & set(fix_versions))

    if combined_list:
        print(len(combined_list))
        print("\n\n")

        response_list = getChatGptResponseFromFile()

        for resp in response_list:
            resp_json = resp["json"].strip()
            cve = resp["cve"].strip()            
            
            if cve in combined_list:
                json_deserialized = json.loads(resp["json"], object_hook=lambda d: SimpleNamespace(**d))

                affected_product = json_deserialized.affected_product
                fix_versions = affected_product.fix_versions
                affected_versions = affected_product.affected_versions
                version_intervals = []

                print(cve)
                print(fix_versions)
                print(affected_versions)

                for version in fix_versions:
                    version_match = re.match(r"\s*[\d\.]+\d", version)
                    version_string = ""
                    if version_match:
                        version_string = version_match.group(0)
                        if version_string:
                            closer_aff_version = "0.0"
                            for aff_version in affected_versions:
                                aff_version_match = re.match(r"\s*[\d\.]+\d", aff_version)
                                aff_version_string = ""
                                if aff_version_match:
                                    aff_version_string = aff_version_match.group(0)
                                    if aff_version_string:
                                        if Version(aff_version_string) >= Version(closer_aff_version) and \
                                            Version(aff_version_string) < Version(version_string):
                                            closer_aff_version = aff_version_string

                            if Version(closer_aff_version) > Version("0.0"):
                                version_intervals.append(closer_aff_version + ":" + version_string)

                print(version_intervals)
                print("\n\n")

def sendOtherPrompt():
    openai.api_key = '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'

    prompt = """
        please provide, with sources, a description of what is a software vulnerability data source, like nvd, cvedetails or snyk."""

    completion = openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])
    print(completion.choices[0].message.content)

def sendPrompt(cve_list):
    openai.api_key = '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'
    chatgpt_response_list = []
    
    index = 1
    for cve in cve_list:
        prompt = """
        please return only the json in the answer and no other text.

        please provide url of the github repository and put it into "github_url" field.

        please extract relevant keywords from the text.

        please extract the vulnerability type from the text.

        complete the following json schema:

        {{
        "affected_product": {{
        "package_name": "",
        "github_url": "",
        "fix_versions": [],
        "affected_versions": [],
        "version_intervals" : []
        }},
        "related_products": [ ],
        "vulnerability_type": "",
        "vulnerability_type_details": "",
        "keywords": [],
        "code_info": {{
        "vulnerable_file_names" : [],
        "vulnerable_function_names": [],
        "vulnerable_component_names": [],
        "exception_names": [""],
        "vulnerable_code_lines": [],
        "vulnerable_command_names": [],
        "parameters": [""],
        }},
        "exploit_info": {{
            "proof_of_concept": "",
            "privileges_required": "",
            "exploit_maturity": ""
        }},
        "other_info": {{
            "workaround": "",
            "product_description": "",
            "component_additional_info": "",
            "is_cve_disputed": "",
            "is_cve_rejected" : "",
            "referenced_cve": []
        }}
        }}

        by extracting the information from the following text:

        {}
        """.format(cve["description"])

        completion = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": prompt}])
        chatgpt_response_list.append({"cve": cve["cve"], "description": cve["description"], "json": completion.choices[0].message.content})
        print(index)

        with open("chatgpt_proxy/chatgpt_response.txt", "a") as file:
            file.write(cve["cve"] + "\n")
            file.write(cve["description"] + "\n")
            file.write(completion.choices[0].message.content.replace("\n", "\t") + "\n")
            file.write("\n")

        index = index + 1

    return chatgpt_response_list

def getProspectorCveList():
    with open("chatgpt_proxy/prospector_cve_list_sorted.txt") as file:
        #lines = [line.strip() for line in file]
        return file.read().splitlines()

def getProspectorNvdSnykCveList():
    with open("chatgpt_proxy/cve_list_temp") as file:
        #lines = [line.strip() for line in file]
        return file.read().splitlines()

#def sortProspectorCveList():
    #lines = []
    #with open("chatgpt_proxy/prospector_cve_list.txt") as file:
        #lines = file.read().splitlines()

    #lines.sort()
    #with open('chatgpt_proxy/prospector_cve_list_sorted.txt', 'w') as outfile:
        #outfile.write('\n'.join(i for i in lines))

def getChatGptResponseFromFile():
    response_list = []

    with open("chatgpt_proxy/chatgpt_response.txt", "r") as file:
        index = 0
        cve = ""
        description = ""
        json = ""
        for line in file:
            if index == 0:
                cve = line
            if index == 1:
                description = line
            if index == 2:
                json = line
            if index == 3:
                response_list.append({"cve": cve, "description": description, "json": json})
                index = -1

            index = index + 1
    return response_list

def fillGithubUrl():
    response_list = []
    cve_list = getChatGptResponseFromFile()

    for element in cve_list:
        json_deserialized = json.loads(element["json"].strip(), object_hook=lambda d: SimpleNamespace(**d))
        github_url = affected_product.github_url
        resp = requests.get(github_url)
            #if resp.status_code != 200:

        response_list.append(element)

    #with open("chatgpt_proxy/chatgpt_response_filled.txt", "w") as file:


def createEmptyValidationJson():
    validated_json = {}

    validated_json["package_name_true"] = 0
    validated_json["package_name_false"] = 0
    validated_json["package_name_empty"] = 0
    validated_json["package_name_true_percentage"] = ""
    validated_json["package_name_false_percentage"] = ""
    validated_json["package_name_empty_percentage"] = ""
    validated_json["package_name_true_list"] = []
    validated_json["package_name_false_list"] = []
    validated_json["package_name_empty_list"] = []

    validated_json["github_url_true"] = 0
    validated_json["github_url_false"] = 0
    validated_json["github_url_empty"] = 0
    validated_json["github_url_true_percentage"] = ""
    validated_json["github_url_false_percentage"] = ""
    validated_json["github_url_empty_percentage"] = ""
    validated_json["github_url_true_list"] = []
    validated_json["github_url_false_list"] = []
    validated_json["github_url_empty_list"] = []

    validated_json["fix_versions_true"] = 0
    validated_json["fix_versions_false"] = 0
    validated_json["fix_versions_empty"] = 0
    validated_json["fix_versions_invalid"] = 0
    validated_json["fix_versions_true_percentage"] = ""
    validated_json["fix_versions_false_percentage"] = ""
    validated_json["fix_versions_empty_percentage"] = ""
    validated_json["fix_versions_true_list"] = []
    validated_json["fix_versions_false_list"] = []
    validated_json["fix_versions_empty_list"] = []
    validated_json["fix_versions_invalid_list"] = []

    validated_json["affected_versions_true"] = 0
    validated_json["affected_versions_false"] = 0
    validated_json["affected_versions_empty"] = 0
    validated_json["affected_versions_invalid"] = 0
    validated_json["affected_versions_true_percentage"] = ""
    validated_json["affected_versions_false_percentage"] = ""
    validated_json["affected_versions_empty_percentage"] = ""
    validated_json["affected_versions_true_list"] = []
    validated_json["affected_versions_false_list"] = []
    validated_json["affected_versions_empty_list"] = []
    validated_json["affected_versions_invalid_list"] = []

    validated_json["version_intervals_true"] = 0
    validated_json["version_intervals_false"] = 0
    validated_json["version_intervals_empty"] = 0
    validated_json["version_intervals_true_percentage"] = ""
    validated_json["version_intervals_false_percentage"] = ""
    validated_json["version_intervals_empty_percentage"] = ""
    validated_json["version_intervals_true_list"] = []
    validated_json["version_intervals_false_list"] = []
    validated_json["version_intervals_empty_list"] = []

    validated_json["related_products_true"] = 0
    validated_json["related_products_false"] = 0
    validated_json["related_products_empty"] = 0
    validated_json["related_products_true_percentage"] = ""
    validated_json["related_products_false_percentage"] = ""
    validated_json["related_products_empty_percentage"] = ""
    validated_json["related_products_true_list"] = []
    validated_json["related_products_false_list"] = []
    validated_json["related_products_empty_list"] = []

    validated_json["vulnerability_type_true"] = 0
    validated_json["vulnerability_type_false"] = 0
    validated_json["vulnerability_type_empty"] = 0
    validated_json["vulnerability_type_true_percentage"] = ""
    validated_json["vulnerability_type_false_percentage"] = ""
    validated_json["vulnerability_type_empty_percentage"] = ""
    validated_json["vulnerability_type_true_list"] = []
    validated_json["vulnerability_type_false_list"] = []
    validated_json["vulnerability_type_empty_list"] = []

    validated_json["vulnerability_type_details_true"] = 0
    validated_json["vulnerability_type_details_false"] = 0
    validated_json["vulnerability_type_details_empty"] = 0
    validated_json["vulnerability_type_details_true_percentage"] = ""
    validated_json["vulnerability_type_details_false_percentage"] = ""
    validated_json["vulnerability_type_details_empty_percentage"] = ""
    validated_json["vulnerability_type_details_true_list"] = []
    validated_json["vulnerability_type_details_false_list"] = []
    validated_json["vulnerability_type_details_empty_list"] = []

    validated_json["keywords_true"] = 0
    validated_json["keywords_false"] = 0
    validated_json["keywords_empty"] = 0
    validated_json["keywords_true_percentage"] = ""
    validated_json["keywords_false_percentage"] = ""
    validated_json["keywords_empty_percentage"] = ""
    validated_json["keywords_true_list"] = []
    validated_json["keywords_false_list"] = []
    validated_json["keywords_empty_list"] = []

    validated_json["vulnerable_file_names_true"] = 0
    validated_json["vulnerable_file_names_false"] = 0
    validated_json["vulnerable_file_names_empty"] = 0
    validated_json["vulnerable_file_names_true_percentage"] = ""
    validated_json["vulnerable_file_names_false_percentage"] = ""
    validated_json["vulnerable_file_names_empty_percentage"] = ""
    validated_json["vulnerable_file_names_true_list"] = []
    validated_json["vulnerable_file_names_false_list"] = []
    validated_json["vulnerable_file_names_empty_list"] = []

    validated_json["vulnerable_function_names_true"] = 0
    validated_json["vulnerable_function_names_false"] = 0
    validated_json["vulnerable_function_names_empty"] = 0
    validated_json["vulnerable_function_names_true_percentage"] = ""
    validated_json["vulnerable_function_names_false_percentage"] = ""
    validated_json["vulnerable_function_names_empty_percentage"] = ""
    validated_json["vulnerable_function_names_true_list"] = []
    validated_json["vulnerable_function_names_false_list"] = []
    validated_json["vulnerable_function_names_empty_list"] = []

    validated_json["vulnerable_component_names_true"] = 0
    validated_json["vulnerable_component_names_false"] = 0
    validated_json["vulnerable_component_names_empty"] = 0
    validated_json["vulnerable_component_names_true_percentage"] = ""
    validated_json["vulnerable_component_names_false_percentage"] = ""
    validated_json["vulnerable_component_names_empty_percentage"] = ""
    validated_json["vulnerable_component_names_true_list"] = []
    validated_json["vulnerable_component_names_false_list"] = []
    validated_json["vulnerable_component_names_empty_list"] = []

    validated_json["exception_names_true"] = 0
    validated_json["exception_names_false"] = 0
    validated_json["exception_names_empty"] = 0
    validated_json["exception_names_true_percentage"] = ""
    validated_json["exception_names_false_percentage"] = ""
    validated_json["exception_names_empty_percentage"] = ""
    validated_json["exception_names_true_list"] = []
    validated_json["exception_names_false_list"] = []
    validated_json["exception_names_empty_list"] = []

    validated_json["vulnerable_code_lines_true"] = 0
    validated_json["vulnerable_code_lines_false"] = 0
    validated_json["vulnerable_code_lines_empty"] = 0
    validated_json["vulnerable_code_lines_true_percentage"] = ""
    validated_json["vulnerable_code_lines_false_percentage"] = ""
    validated_json["vulnerable_code_lines_empty_percentage"] = ""
    validated_json["vulnerable_code_lines_true_list"] = []
    validated_json["vulnerable_code_lines_false_list"] = []
    validated_json["vulnerable_code_lines_empty_list"] = []

    validated_json["vulnerable_command_names_true"] = 0
    validated_json["vulnerable_command_names_false"] = 0
    validated_json["vulnerable_command_names_empty"] = 0
    validated_json["vulnerable_command_names_true_percentage"] = ""
    validated_json["vulnerable_command_names_false_percentage"] = ""
    validated_json["vulnerable_command_names_empty_percentage"] = ""
    validated_json["vulnerable_command_names_true_list"] = []
    validated_json["vulnerable_command_names_false_list"] = []
    validated_json["vulnerable_command_names_empty_list"] = []

    validated_json["parameters_true"] = 0
    validated_json["parameters_false"] = 0
    validated_json["parameters_empty"] = 0
    validated_json["parameters_true_percentage"] = ""
    validated_json["parameters_false_percentage"] = ""
    validated_json["parameters_empty_percentage"] = ""
    validated_json["parameters_true_list"] = []
    validated_json["parameters_false_list"] = []
    validated_json["parameters_empty_list"] = []

    validated_json["proof_of_concept_true"] = 0
    validated_json["proof_of_concept_false"] = 0
    validated_json["proof_of_concept_empty"] = 0
    validated_json["proof_of_concept_true_percentage"] = ""
    validated_json["proof_of_concept_false_percentage"] = ""
    validated_json["proof_of_concept_empty_percentage"] = ""
    validated_json["proof_of_concept_true_list"] = []
    validated_json["proof_of_concept_false_list"] = []
    validated_json["proof_of_concept_empty_list"] = []

    validated_json["privileges_required_true"] = 0
    validated_json["privileges_required_false"] = 0
    validated_json["privileges_required_empty"] = 0
    validated_json["privileges_required_true_percentage"] = ""
    validated_json["privileges_required_false_percentage"] = ""
    validated_json["privileges_required_empty_percentage"] = ""
    validated_json["privileges_required_true_list"] = []
    validated_json["privileges_required_false_list"] = []
    validated_json["privileges_required_empty_list"] = []

    validated_json["exploit_maturity_true"] = 0
    validated_json["exploit_maturity_false"] = 0
    validated_json["exploit_maturity_empty"] = 0
    validated_json["exploit_maturity_true_percentage"] = ""
    validated_json["exploit_maturity_false_percentage"] = ""
    validated_json["exploit_maturity_empty_percentage"] = ""
    validated_json["exploit_maturity_true_list"] = []
    validated_json["exploit_maturity_false_list"] = []
    validated_json["exploit_maturity_empty_list"] = []

    validated_json["workaround_true"] = 0
    validated_json["workaround_false"] = 0
    validated_json["workaround_empty"] = 0
    validated_json["workaround_true_percentage"] = ""
    validated_json["workaround_false_percentage"] = ""
    validated_json["workaround_empty_percentage"] = ""
    validated_json["workaround_true_list"] = []
    validated_json["workaround_false_list"] = []
    validated_json["workaround_empty_list"] = []

    validated_json["product_description_true"] = 0
    validated_json["product_description_false"] = 0
    validated_json["product_description_empty"] = 0
    validated_json["product_description_true_percentage"] = ""
    validated_json["product_description_false_percentage"] = ""
    validated_json["product_description_empty_percentage"] = ""
    validated_json["product_description_true_list"] = []
    validated_json["product_description_false_list"] = []
    validated_json["product_description_empty_list"] = []

    validated_json["component_additional_info_true"] = 0
    validated_json["component_additional_info_false"] = 0
    validated_json["component_additional_info_empty"] = 0
    validated_json["component_additional_info_true_percentage"] = ""
    validated_json["component_additional_info_false_percentage"] = ""
    validated_json["component_additional_info_empty_percentage"] = ""
    validated_json["component_additional_info_true_list"] = []
    validated_json["component_additional_info_false_list"] = []
    validated_json["component_additional_info_empty_list"] = []

    validated_json["is_cve_disputed_true"] = 0
    validated_json["is_cve_disputed_false"] = 0
    validated_json["is_cve_disputed_empty"] = 0
    validated_json["is_cve_disputed_true_percentage"] = ""
    validated_json["is_cve_disputed_false_percentage"] = ""
    validated_json["is_cve_disputed_empty_percentage"] = ""
    validated_json["is_cve_disputed_true_list"] = []
    validated_json["is_cve_disputed_false_list"] = []
    validated_json["is_cve_disputed_empty_list"] = []

    validated_json["is_cve_rejected_true"] = 0
    validated_json["is_cve_rejected_false"] = 0
    validated_json["is_cve_rejected_empty"] = 0
    validated_json["is_cve_rejected_true_percentage"] = ""
    validated_json["is_cve_rejected_false_percentage"] = ""
    validated_json["is_cve_rejected_empty_percentage"] = ""
    validated_json["is_cve_rejected_true_list"] = []
    validated_json["is_cve_rejected_false_list"] = []
    validated_json["is_cve_rejected_empty_list"] = []

    validated_json["referenced_cve_true"] = 0
    validated_json["referenced_cve_false"] = 0
    validated_json["referenced_cve_empty"] = 0
    validated_json["referenced_cve_true_percentage"] = ""
    validated_json["referenced_cve_false_percentage"] = ""
    validated_json["referenced_cve_empty_percentage"] = ""
    validated_json["referenced_cve_true_list"] = []
    validated_json["referenced_cve_false_list"] = []
    validated_json["referenced_cve_empty_list"] = []

    return validated_json

def validateJson(cve_list):
    validated_json = createEmptyValidationJson()

    for element in cve_list:
        element["cve"] = element["cve"].strip()
        element["description"] = element["description"].strip()
        element["json"] = element["json"].strip()

        try:
            json_deserialized = json.loads(element["json"], object_hook=lambda d: SimpleNamespace(**d))
            print(element["cve"])
        except:
            print(element["cve"])
            continue

        affected_product = json_deserialized.affected_product

        # validate package name
        package_name = affected_product.package_name
        if not package_name:
            validated_json["package_name_empty"] = validated_json["package_name_empty"] + 1
            #validated_json["package_name_empty_list"].append(element["cve"])
        elif package_name in element["description"]:
            validated_json["package_name_true"] = validated_json["package_name_true"] + 1
            validated_json["package_name_true_list"].append(element["cve"])
        else:
            validated_json["package_name_false"] = validated_json["package_name_false"] + 1
            validated_json["package_name_false_list"].append(element["cve"])

        # validate repository url
        #repository_url = affected_product.repository_url
        #if not repository_url:
            #validated_json["repository_url"] = "empty"
        #else:
            #resp = requests.get(repository_url)
            #if resp.status_code != 200:
                #validated_json["repository_url"] = "false"
            #else:
                #validated_json["repository_url"] = "true"

        # validate github url
        github_url = affected_product.github_url
        if not github_url:
            validated_json["github_url_empty"] = validated_json["github_url_empty"] + 1
            #validated_json["github_url_empty_list"].append(element["cve"])
        else:
            resp = requests.get(github_url)
            if resp.status_code != 200:
                validated_json["github_url_false"] = validated_json["github_url_false"] + 1
                validated_json["github_url_false_list"].append(element["cve"])
            else:
                validated_json["github_url_true"] = validated_json["github_url_true"] + 1
                validated_json["github_url_true_list"].append(element["cve"])

        affected_configurations = getAffectedConfigurations(connection, element["cve"])

        # validate fix versions
        fix_versions = affected_product.fix_versions
        if not fix_versions or (len(fix_versions) > 0 and not fix_versions[0]) or isAffectedConfigEmpty(affected_configurations, True):
            validated_json["fix_versions_empty"] = validated_json["fix_versions_empty"] + 1
            validated_json["fix_versions_empty_list"].append(element["cve"])
        else:
            versions_upto_including = [x["version_upto_including"] for x in affected_configurations if x["version_upto_including"]]
            versions_upto_excluding = [x["version_upto_excluding"] for x in affected_configurations if x["version_upto_excluding"]]
            for fix_version in fix_versions:
                try:
                    version = re.match(r"\s*[\d\.]+\d", fix_version)
                    if version:
                        version = version.group(0)
                    else:
                        validated_json["fix_versions_empty"] = validated_json["fix_versions_empty"] + 1
                        validated_json["fix_versions_empty_list"].append(element["cve"])
                        break
                    if not (version in versions_upto_excluding \
                        or len([x for x in versions_upto_including if Version(x) < Version(version)]) > 0):
                        validated_json["fix_versions_false"] = validated_json["fix_versions_false"] + 1
                        validated_json["fix_versions_false_list"].append(element["cve"])
                        break
                except:
                    validated_json["fix_versions_invalid"] = validated_json["fix_versions_invalid"] + 1
                    validated_json["fix_versions_invalid_list"].append(element["cve"])
                    break

            if element["cve"] not in validated_json["fix_versions_false_list"] and \
                element["cve"] not in validated_json["fix_versions_empty_list"]  and \
                element["cve"] not in validated_json["fix_versions_invalid_list"]:
                validated_json["fix_versions_true"] = validated_json["fix_versions_true"] + 1
                validated_json["fix_versions_true_list"].append(element["cve"])
                    
        # validate affected versions
        affected_versions = affected_product.affected_versions
        if not affected_versions or (len(affected_versions) > 0 and not affected_versions[0]) or isAffectedConfigEmpty(affected_configurations, False):
            validated_json["affected_versions_empty"] = validated_json["affected_versions_empty"] + 1
            validated_json["affected_versions_empty_list"].append(element["cve"])
        else:
            for version in affected_versions:
                version_match = re.match(r"\s*[\d\.]+\d", version)
                version_string = ""
                if version_match:
                    version_string = re.match(r"\s*[\d\.]+\d", version).group(0)
                if not version_string:
                    validated_json["affected_versions_empty"] = validated_json["affected_versions_empty"] + 1
                    validated_json["affected_versions_empty_list"].append(element["cve"])
                    break
                elif any(x in version for x in ["<", "below", "lower"]) and version_string:
                    try:
                        true_count = 0
                        for configuration in affected_configurations:
                            if Version(version_string) <= Version(configuration["version_upto_including"]) or \
                                Version(version_string) < Version(configuration["version_upto_excluding"]):
                                if (not configuration["version_from_including"] or \
                                    Version(version_string) >= Version(configuration["version_from_including"])) or \
                                    (not configuration["version_from_excluding"] or \
                                    Version(version_string) > Version(configuration["version_from_excluding"])):
                                    true_count = true_count + 1
                                    break
                        if true_count == 0:
                            validated_json["affected_versions_false"] = validated_json["affected_versions_false"] + 1
                            validated_json["affected_versions_false_list"].append(element["cve"])
                            break
                    except:
                        validated_json["affected_versions_invalid"] = validated_json["affected_versions_invalid"] + 1
                        validated_json["affected_versions_invalid_list"].append(element["cve"])
                        break
                elif any(x in version for x in [">", "above", "higher", "greater"]) and version_string:
                    try:
                        true_count = 0
                        for configuration in affected_configurations:
                            if Version(version_string) >= Version(configuration["version_from_including"]) or \
                                Version(version_string) > Version(configuration["version_from_excluding"]):
                                if (not configuration["version_upto_including"] or \
                                    Version(version_string) <= Version(configuration["version_upto_including"])) or \
                                    (not configuration["version_upto_excluding"] or \
                                    Version(version_string) < Version(configuration["version_upto_excluding"])):
                                    true_count = true_count + 1
                                    break
                        if true_count == 0:
                            validated_json["affected_versions_false"] = validated_json["affected_versions_false"] + 1
                            validated_json["affected_versions_false_list"].append(element["cve"])
                            break
                    except:
                        validated_json["affected_versions_invalid"] = validated_json["affected_versions_invalid"] + 1
                        validated_json["affected_versions_invalid_list"].append(element["cve"])
                        break
                else:
                    try:
                        true_count = 0
                        for configuration in affected_configurations:
                            if version_string == configuration["version_from_including"] or \
                                version_string == configuration["version_upto_including"] or \
                                (configuration["version_from_including"] and Version(version_string) > Version(configuration["version_from_including"])) or \
                                (configuration["version_from_excluding"] and Version(version_string) > Version(configuration["version_from_excluding"])) or \
                                (configuration["version_upto_including"] and Version(version_string) < Version(configuration["version_upto_including"])) or \
                                (configuration["version_upto_excluding"] and Version(version_string) < Version(configuration["version_upto_excluding"])):
                                    true_count = true_count + 1
                                    break
                        if true_count == 0:
                            validated_json["affected_versions_false"] = validated_json["affected_versions_false"] + 1
                            validated_json["affected_versions_false_list"].append(element["cve"])
                            break
                    except:
                        validated_json["affected_versions_invalid"] = validated_json["affected_versions_invalid"] + 1
                        validated_json["affected_versions_invalid_list"].append(element["cve"])
                        break                    

            if element["cve"] not in validated_json["affected_versions_false_list"] and \
                element["cve"] not in validated_json["affected_versions_empty_list"]  and \
                element["cve"] not in validated_json["affected_versions_invalid_list"]:
                validated_json["affected_versions_true"] = validated_json["affected_versions_true"] + 1
                validated_json["affected_versions_true_list"].append(element["cve"])

        # validate version intervals
        version_intervals = affected_product.version_intervals

        # validate related products (LIST)
        related_products = json_deserialized.related_products
        if not related_products or (len(related_products) > 0 and not related_products[0]):
            validated_json["related_products_empty"] = validated_json["related_products_empty"] + 1
            #validated_json["related_products_empty_list"].append(element["cve"])
        else:
            for product in related_products:
                if product not in element["description"]:
                    validated_json["related_products_false"] = validated_json["related_products_false"] + 1
                    validated_json["related_products_false_list"].append(element["cve"])
                    break
            if not element["cve"] in validated_json["related_products_false_list"]:
                validated_json["related_products_true"] = validated_json["related_products_true"] + 1
                validated_json["related_products_true_list"].append(element["cve"])

        # validate vulnerability_type
        vulnerability_type = json_deserialized.vulnerability_type
        vuln_types = getVulnerabilityTypes(connection, element["cve"])
        if vulnerability_type:
            if vuln_types:
                types = vuln_types.split("|")
                false_count = 0
                for type_ in types:
                    if vulnerability_type.lower() not in type_.strip().lower():
                        false_count = false_count + 1
                if false_count >= len(types):
                    validated_json["vulnerability_type_false"] = validated_json["vulnerability_type_false"] + 1
                    validated_json["vulnerability_type_false_list"].append(element["cve"])
                else:
                    validated_json["vulnerability_type_true"] = validated_json["vulnerability_type_true"] + 1
                    validated_json["vulnerability_type_true_list"].append(element["cve"])
            else:
                validated_json["vulnerability_type_empty"] = validated_json["vulnerability_type_empty"] + 1
                validated_json["vulnerability_type_empty_list"].append(element["cve"]) 
        else:
            validated_json["vulnerability_type_empty"] = validated_json["vulnerability_type_empty"] + 1
            validated_json["vulnerability_type_empty_list"].append(element["cve"])

        # validate vulnerability type details
        vulnerability_type_details = json_deserialized.vulnerability_type_details
        if not vulnerability_type_details:
            validated_json["vulnerability_type_details_empty"] = validated_json["vulnerability_type_details_empty"] + 1
            #validated_json["vulnerability_type_details_empty_list"].append(element["cve"])
        elif vulnerability_type_details in element["description"]:
            validated_json["vulnerability_type_details_true"] = validated_json["vulnerability_type_details_true"] + 1
            validated_json["vulnerability_type_details_true_list"].append(element["cve"])
        else:
            validated_json["vulnerability_type_details_false"] = validated_json["vulnerability_type_details_false"] + 1
            validated_json["vulnerability_type_details_false_list"].append(element["cve"])

        # validate keywords (LIST)
        keywords = json_deserialized.keywords
        if not keywords or (len(keywords) > 0 and not keywords[0]):
            validated_json["keywords_empty"] = validated_json["keywords_empty"] + 1
            #validated_json["keywords_empty_list"].append(element["cve"])
        else:
            for product in keywords:
                if product not in element["description"]:
                    validated_json["keywords_false"] = validated_json["keywords_false"] + 1
                    validated_json["keywords_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["keywords_false_list"]:
                validated_json["keywords_true"] = validated_json["keywords_true"] + 1
                validated_json["keywords_true_list"].append(element["cve"])

        code_info = json_deserialized.code_info

        # validate vulnerable file names (LIST)
        vulnerable_file_names = code_info.vulnerable_file_names
        validated_json["vulnerable_file_names"] = []
        if not vulnerable_file_names or (len(vulnerable_file_names) > 0 and not vulnerable_file_names[0]):
            validated_json["vulnerable_file_names_empty"] = validated_json["vulnerable_file_names_empty"] + 1
            #validated_json["vulnerable_file_names_empty_list"].append(element["cve"])
        else:
            for product in vulnerable_file_names:
                if product not in element["description"]:
                    validated_json["vulnerable_file_names_false"] = validated_json["vulnerable_file_names_false"] + 1
                    validated_json["vulnerable_file_names_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["vulnerable_file_names_false_list"]:
                validated_json["vulnerable_file_names_true"] = validated_json["vulnerable_file_names_true"] + 1
                validated_json["vulnerable_file_names_true_list"].append(element["cve"])

        # validate vulnerable function names (LIST)
        vulnerable_function_names = code_info.vulnerable_function_names
        validated_json["vulnerable_function_names"] = []
        if not vulnerable_function_names or (len(vulnerable_function_names) > 0 and not vulnerable_function_names[0]):
            validated_json["vulnerable_function_names_empty"] = validated_json["vulnerable_function_names_empty"] + 1
            #validated_json["vulnerable_function_names_empty_list"].append(element["cve"])
        else:
            for product in vulnerable_function_names:
                if product not in element["description"]:
                    validated_json["vulnerable_function_names_false"] = validated_json["vulnerable_function_names_false"] + 1
                    validated_json["vulnerable_function_names_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["vulnerable_function_names_false_list"]:
                validated_json["vulnerable_function_names_true"] = validated_json["vulnerable_function_names_true"] + 1
                validated_json["vulnerable_function_names_true_list"].append(element["cve"])

        # validate vulnerable component names (LIST)
        vulnerable_component_names = code_info.vulnerable_component_names
        if not vulnerable_component_names or (len(vulnerable_component_names) > 0 and not vulnerable_component_names[0]):
            validated_json["vulnerable_component_names_empty"] = validated_json["vulnerable_component_names_empty"] + 1
            #validated_json["vulnerable_component_names_empty_list"].append(element["cve"])
        else:
            for product in vulnerable_component_names:
                if product not in element["description"]:
                    validated_json["vulnerable_component_names_false"] = validated_json["vulnerable_component_names_false"] + 1
                    validated_json["vulnerable_component_names_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["vulnerable_component_names_false_list"]:
                validated_json["vulnerable_component_names_true"] = validated_json["vulnerable_component_names_true"] + 1
                validated_json["vulnerable_component_names_true_list"].append(element["cve"])

        # validate exception_names (LIST)
        exception_names = code_info.exception_names
        validated_json["exception_names"] = []
        if not exception_names or (len(exception_names) > 0 and not exception_names[0]):
            validated_json["exception_names_empty"] = validated_json["exception_names_empty"] + 1
            #validated_json["exception_names_empty_list"].append(element["cve"])
        else:
            for product in exception_names:
                if product not in element["description"]:
                    validated_json["exception_names_false"] = validated_json["exception_names_false"] + 1
                    validated_json["exception_names_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["exception_names_false_list"]:
                validated_json["exception_names_true"] = validated_json["exception_names_true"] + 1
                validated_json["exception_names_true_list"].append(element["cve"])

        # validate vulnerable_code_lines (LIST)
        vulnerable_code_lines = code_info.vulnerable_code_lines
        if not vulnerable_code_lines or (len(vulnerable_code_lines) > 0 and not vulnerable_code_lines[0]):
            validated_json["vulnerable_code_lines_empty"] = validated_json["vulnerable_code_lines_empty"] + 1
            #validated_json["vulnerable_code_lines_empty_list"].append(element["cve"])
        else:
            for product in vulnerable_code_lines:
                if product not in element["description"]:
                    validated_json["vulnerable_code_lines_false"] = validated_json["vulnerable_code_lines_false"] + 1
                    validated_json["vulnerable_code_lines_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["vulnerable_code_lines_false_list"]:
                validated_json["vulnerable_code_lines_true"] = validated_json["vulnerable_code_lines_true"] + 1
                validated_json["vulnerable_code_lines_true_list"].append(element["cve"])

        # validate parameters (LIST)
        parameters = code_info.parameters
        if not parameters or (len(parameters) > 0 and not parameters[0]):
            validated_json["parameters_empty"] = validated_json["parameters_empty"] + 1
            #validated_json["parameters_empty_list"].append(element["cve"])
        else:
            for product in parameters:
                if product not in element["description"]:
                    validated_json["parameters_false"] = validated_json["parameters_false"] + 1
                    validated_json["parameters_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["parameters_false_list"]:
                validated_json["parameters_true"] = validated_json["parameters_true"] + 1
                validated_json["parameters_true_list"].append(element["cve"])

        exploit_info = json_deserialized.exploit_info

        # validate proof of concept
        proof_of_concept = exploit_info.proof_of_concept
        if not proof_of_concept:
            validated_json["proof_of_concept_empty"] = validated_json["proof_of_concept_empty"] + 1
            #validated_json["proof_of_concept_empty_list"].append(element["cve"])
        elif proof_of_concept in element["description"]:
            validated_json["proof_of_concept_true"] = validated_json["proof_of_concept_true"] + 1
            validated_json["proof_of_concept_true_list"].append(element["cve"])
        else:
            validated_json["proof_of_concept_false"] = validated_json["proof_of_concept_false"] + 1
            validated_json["proof_of_concept_false_list"].append(element["cve"])

        # validate privileges required
        privileges_required = exploit_info.privileges_required
        cvss_list = getCvss(connection, element["cve"])
        cvss = ""

        if not cvss_list:
            cvss = ""
        elif cvss_list["nvd_cvss3_nist_vector"]:
            cvss = cvss_list["nvd_cvss3_nist_vector"]
        elif cvss_list["nvd_cvss3_cna_vector"]:
            cvss = cvss_list["nvd_cvss3_cna_vector"]
        elif cvss_list["nvd_cvss2_nist_vector"]:
            cvss = cvss_list["nvd_cvss2_nist_vector"]

        if not privileges_required or not cvss:
            validated_json["privileges_required_empty"] = validated_json["privileges_required_empty"] + 1
            validated_json["privileges_required_empty_list"].append(element["cve"])
        else:
            validation_result = validatePrivileges(cvss, privileges_required)
            if validation_result == "true":
                validated_json["privileges_required_true"] = validated_json["privileges_required_true"] + 1
                validated_json["privileges_required_true_list"].append(element["cve"])
            if validation_result == "false":
                validated_json["privileges_required_false"] = validated_json["privileges_required_false"] + 1
                validated_json["privileges_required_false_list"].append(element["cve"])
            if validation_result == "empty":
                validated_json["privileges_required_empty"] = validated_json["privileges_required_empty"] + 1
                validated_json["privileges_required_empty_list"].append(element["cve"])

        # validate exploit maturity
        exploit_maturity = exploit_info.exploit_maturity

        other_info = json_deserialized.other_info

        # validate workaround
        workaround = other_info.workaround
        if not workaround:
            validated_json["workaround_empty"] = validated_json["workaround_empty"] + 1
            #validated_json["workaround_empty_list"].append(element["cve"])
        elif workaround in element["description"]:
            validated_json["workaround_true"] = validated_json["workaround_true"] + 1
            validated_json["workaround_true_list"].append(element["cve"])
        else:
            validated_json["workaround_false"] = validated_json["workaround_false"] + 1
            validated_json["workaround_false_list"].append(element["cve"])

        # validate product description
        product_description = other_info.product_description
        if not product_description:
            validated_json["product_description_empty"] = validated_json["product_description_empty"] + 1
            #validated_json["product_description_empty_list"].append(element["cve"])
        elif workaround in element["description"]:
            validated_json["product_description_true"] = validated_json["product_description_true"] + 1
            validated_json["product_description_true_list"].append(element["cve"])
        else:
            validated_json["product_description_false"] = validated_json["product_description_false"] + 1
            validated_json["product_description_false_list"].append(element["cve"])

        # validate additional component info
        component_additional_info = other_info.component_additional_info
        if not component_additional_info:
            validated_json["component_additional_info_empty"] = validated_json["component_additional_info_empty"] + 1
            #validated_json["component_additional_info_empty_list"].append(element["cve"])
        elif workaround in element["description"]:
            validated_json["component_additional_info_true"] = validated_json["component_additional_info_true"] + 1
            validated_json["component_additional_info_true_list"].append(element["cve"])
        else:
            validated_json["component_additional_info_false"] = validated_json["component_additional_info_false"] + 1
            validated_json["component_additional_info_false_list"].append(element["cve"])

        # validate cve_disputed
        is_cve_disputed = other_info.is_cve_disputed
        if not is_cve_disputed:
            validated_json["is_cve_disputed_empty"] = validated_json["is_cve_disputed_empty"] + 1
            #validated_json["is_cve_disputed_empty_list"].append(element["cve"])
        elif workaround in element["description"]:
            validated_json["is_cve_disputed_true"] = validated_json["is_cve_disputed_true"] + 1
            validated_json["is_cve_disputed_true_list"].append(element["cve"])
        else:
            validated_json["is_cve_disputed_false"] = validated_json["is_cve_disputed_false"] + 1
            validated_json["is_cve_disputed_list"].append(element["cve"])

        # validate additional component info
        is_cve_rejected = other_info.is_cve_rejected
        if not is_cve_rejected:
            validated_json["is_cve_rejected_empty"] = validated_json["is_cve_rejected_empty"] + 1
            #validated_json["is_cve_rejected_empty_list"].append(element["cve"])
        elif workaround in element["description"]:
            validated_json["is_cve_rejected_true"] = validated_json["is_cve_rejected_true"] + 1
            validated_json["is_cve_rejected_true_list"].append(element["cve"])
        else:
            validated_json["is_cve_rejected_false"] = validated_json["is_cve_rejected_false"] + 1
            validated_json["is_cve_rejected_false_list"].append(element["cve"])

        # validate related cve (LIST)
        referenced_cve = other_info.referenced_cve
        if not referenced_cve or (len(referenced_cve) > 0 and not referenced_cve[0]):
            validated_json["referenced_cve_empty"] = validated_json["referenced_cve_empty"] + 1
            validated_json["referenced_cve_empty_list"].append(element["cve"])
        else:
            for product in referenced_cve:
                if product not in element["description"]:
                    validated_json["referenced_cve_false"] = validated_json["referenced_cve_false"] + 1
                    validated_json["referenced_cve_false_list"].append(element["cve"])
                    break
            if element["cve"] not in validated_json["referenced_cve_false_list"]:
                validated_json["referenced_cve_true"] = validated_json["referenced_cve_true"] + 1
                validated_json["referenced_cve_true_list"].append(element["cve"])

    validated_json["package_name_true_percentage"] = percentage(validated_json["package_name_true"])
    validated_json["package_name_false_percentage"] = percentage(validated_json["package_name_false"])
    validated_json["package_name_empty_percentage"] = percentage(validated_json["package_name_empty"])
    validated_json["package_name_total"] = validated_json["package_name_true"] \
        + validated_json["package_name_false"] + validated_json["package_name_empty"]

    validated_json["github_url_true_percentage"] = percentage(validated_json["github_url_true"])
    validated_json["github_url_false_percentage"] = percentage(validated_json["github_url_false"])
    validated_json["github_url_empty_percentage"] = percentage(validated_json["github_url_empty"])
    validated_json["github_url_total"] = validated_json["github_url_true"] \
        + validated_json["github_url_false"] + validated_json["github_url_empty"]

    validated_json["fix_versions_true_percentage"] = percentage(validated_json["fix_versions_true"])
    validated_json["fix_versions_false_percentage"] = percentage(validated_json["fix_versions_false"])
    validated_json["fix_versions_empty_percentage"] = percentage(validated_json["fix_versions_empty"])
    validated_json["fix_versions_total"] = validated_json["fix_versions_true"] \
        + validated_json["fix_versions_false"] + validated_json["fix_versions_empty"] \
        + validated_json["fix_versions_invalid"]

    validated_json["affected_versions_true_percentage"] = percentage(validated_json["affected_versions_true"])
    validated_json["affected_versions_false_percentage"] = percentage(validated_json["affected_versions_false"])
    validated_json["affected_versions_empty_percentage"] = percentage(validated_json["affected_versions_empty"])
    validated_json["affected_versions_total"] = validated_json["affected_versions_true"] \
        + validated_json["affected_versions_false"] + validated_json["affected_versions_empty"] \
        + validated_json["affected_versions_invalid"]

    validated_json["related_products_true_percentage"] = percentage(validated_json["related_products_true"])
    validated_json["related_products_false_percentage"] = percentage(validated_json["related_products_false"])
    validated_json["related_products_empty_percentage"] = percentage(validated_json["related_products_empty"])
    validated_json["related_products_total"] = validated_json["related_products_true"] \
        + validated_json["related_products_false"] + validated_json["related_products_empty"]

    validated_json["vulnerability_type_true_percentage"] = percentage(validated_json["vulnerability_type_true"])
    validated_json["vulnerability_type_false_percentage"] = percentage(validated_json["vulnerability_type_false"])
    validated_json["vulnerability_type_empty_percentage"] = percentage(validated_json["vulnerability_type_empty"])
    validated_json["vulnerability_type_total"] = validated_json["vulnerability_type_true"] \
        + validated_json["vulnerability_type_false"] + validated_json["vulnerability_type_empty"]

    validated_json["vulnerability_type_details_true_percentage"] = percentage(validated_json["vulnerability_type_details_true"])
    validated_json["vulnerability_type_details_false_percentage"] = percentage(validated_json["vulnerability_type_details_false"])
    validated_json["vulnerability_type_details_empty_percentage"] = percentage(validated_json["vulnerability_type_details_empty"])
    validated_json["vulnerability_type_details_total"] = validated_json["vulnerability_type_details_true"] \
        + validated_json["vulnerability_type_details_false"] + validated_json["vulnerability_type_details_empty"]

    validated_json["keywords_true_percentage"] = percentage(validated_json["keywords_true"])
    validated_json["keywords_false_percentage"] = percentage(validated_json["keywords_false"])
    validated_json["keywords_empty_percentage"] = percentage(validated_json["keywords_empty"])
    validated_json["keywords_total"] = validated_json["keywords_true"] \
        + validated_json["keywords_false"] + validated_json["keywords_empty"]

    validated_json["vulnerable_file_names_true_percentage"] = percentage(validated_json["vulnerable_file_names_true"])
    validated_json["vulnerable_file_names_false_percentage"] = percentage(validated_json["vulnerable_file_names_false"])
    validated_json["vulnerable_file_names_empty_percentage"] = percentage(validated_json["vulnerable_file_names_empty"])
    validated_json["vulnerable_file_names_total"] = validated_json["vulnerable_file_names_true"] \
        + validated_json["vulnerable_file_names_false"] + validated_json["vulnerable_file_names_empty"]

    validated_json["vulnerable_function_names_true_percentage"] = percentage(validated_json["vulnerable_function_names_true"])
    validated_json["vulnerable_function_names_false_percentage"] = percentage(validated_json["vulnerable_function_names_false"])
    validated_json["vulnerable_function_names_empty_percentage"] = percentage(validated_json["vulnerable_function_names_empty"])
    validated_json["vulnerable_function_names_total"] = validated_json["vulnerable_function_names_true"] \
        + validated_json["vulnerable_function_names_false"] + validated_json["vulnerable_function_names_empty"]

    validated_json["vulnerable_component_names_true_percentage"] = percentage(validated_json["vulnerable_component_names_true"])
    validated_json["vulnerable_component_names_false_percentage"] = percentage(validated_json["vulnerable_component_names_false"])
    validated_json["vulnerable_component_names_empty_percentage"] = percentage(validated_json["vulnerable_component_names_empty"])
    validated_json["vulnerable_component_names_total"] = validated_json["vulnerable_component_names_true"] \
        + validated_json["vulnerable_component_names_false"] + validated_json["vulnerable_component_names_empty"]

    validated_json["exception_names_true_percentage"] = percentage(validated_json["exception_names_true"])
    validated_json["exception_names_false_percentage"] = percentage(validated_json["exception_names_false"])
    validated_json["exception_names_empty_percentage"] = percentage(validated_json["exception_names_empty"])
    validated_json["exception_names_total"] = validated_json["exception_names_true"] \
        + validated_json["exception_names_false"] + validated_json["exception_names_empty"]

    validated_json["vulnerable_code_lines_true_percentage"] = percentage(validated_json["vulnerable_code_lines_true"])
    validated_json["vulnerable_code_lines_false_percentage"] = percentage(validated_json["vulnerable_code_lines_false"])
    validated_json["vulnerable_code_lines_empty_percentage"] = percentage(validated_json["vulnerable_code_lines_empty"])
    validated_json["vulnerable_code_lines_total"] = validated_json["vulnerable_code_lines_true"] \
        + validated_json["vulnerable_code_lines_false"] + validated_json["vulnerable_code_lines_empty"]

    validated_json["vulnerable_command_names_true_percentage"] = percentage(validated_json["vulnerable_command_names_true"])
    validated_json["vulnerable_command_names_false_percentage"] = percentage(validated_json["vulnerable_command_names_false"])
    validated_json["vulnerable_command_names_empty_percentage"] = percentage(validated_json["vulnerable_command_names_empty"])
    validated_json["vulnerable_command_names_total"] = validated_json["vulnerable_command_names_true"] \
        + validated_json["vulnerable_command_names_false"] + validated_json["vulnerable_command_names_empty"]

    validated_json["parameters_true_percentage"] = percentage(validated_json["parameters_true"])
    validated_json["parameters_false_percentage"] = percentage(validated_json["parameters_false"])
    validated_json["parameters_empty_percentage"] = percentage(validated_json["parameters_empty"])
    validated_json["parameters_total"] = validated_json["parameters_true"] \
        + validated_json["parameters_false"] + validated_json["parameters_empty"]

    validated_json["proof_of_concept_true_percentage"] = percentage(validated_json["proof_of_concept_true"])
    validated_json["proof_of_concept_false_percentage"] = percentage(validated_json["proof_of_concept_false"])
    validated_json["proof_of_concept_empty_percentage"] = percentage(validated_json["proof_of_concept_empty"])
    validated_json["proof_of_concept_total"] = validated_json["proof_of_concept_true"] \
        + validated_json["proof_of_concept_false"] + validated_json["proof_of_concept_empty"]

    validated_json["privileges_required_true_percentage"] = percentage(validated_json["privileges_required_true"])
    validated_json["privileges_required_false_percentage"] = percentage(validated_json["privileges_required_false"])
    validated_json["privileges_required_empty_percentage"] = percentage(validated_json["privileges_required_empty"])
    validated_json["privileges_required_total"] = validated_json["privileges_required_true"] \
        + validated_json["privileges_required_false"] + validated_json["privileges_required_empty"]

    validated_json["exploit_maturity_true_percentage"] = percentage(validated_json["exploit_maturity_true"])
    validated_json["exploit_maturity_false_percentage"] = percentage(validated_json["exploit_maturity_false"])
    validated_json["exploit_maturity_empty_percentage"] = percentage(validated_json["exploit_maturity_empty"])
    validated_json["exploit_maturity_total"] = validated_json["exploit_maturity_true"] \
        + validated_json["exploit_maturity_false"] + validated_json["exploit_maturity_empty"]

    validated_json["workaround_true_percentage"] = percentage(validated_json["workaround_true"])
    validated_json["workaround_false_percentage"] = percentage(validated_json["workaround_false"])
    validated_json["workaround_empty_percentage"] = percentage(validated_json["workaround_empty"])
    validated_json["workaround_total"] = validated_json["workaround_true"] \
        + validated_json["workaround_false"] + validated_json["workaround_empty"]

    validated_json["product_description_true_percentage"] = percentage(validated_json["product_description_true"])
    validated_json["product_description_false_percentage"] = percentage(validated_json["product_description_false"])
    validated_json["product_description_empty_percentage"] = percentage(validated_json["product_description_empty"])
    validated_json["product_description_total"] = validated_json["product_description_true"] \
        + validated_json["product_description_false"] + validated_json["product_description_empty"]

    validated_json["component_additional_info_true_percentage"] = percentage(validated_json["component_additional_info_true"])
    validated_json["component_additional_info_false_percentage"] = percentage(validated_json["component_additional_info_false"])
    validated_json["component_additional_info_empty_percentage"] = percentage(validated_json["component_additional_info_empty"])
    validated_json["component_additional_info_total"] = validated_json["component_additional_info_true"] \
        + validated_json["component_additional_info_false"] + validated_json["component_additional_info_empty"]

    validated_json["is_cve_disputed_true_percentage"] = percentage(validated_json["is_cve_disputed_true"])
    validated_json["is_cve_disputed_false_percentage"] = percentage(validated_json["is_cve_disputed_false"])
    validated_json["is_cve_disputed_empty_percentage"] = percentage(validated_json["is_cve_disputed_empty"])
    validated_json["is_cve_disputed_total"] = validated_json["is_cve_disputed_true"] \
        + validated_json["is_cve_disputed_false"] + validated_json["is_cve_disputed_empty"]

    validated_json["is_cve_rejected_true_percentage"] = percentage(validated_json["is_cve_rejected_true"])
    validated_json["is_cve_rejected_false_percentage"] = percentage(validated_json["is_cve_rejected_false"])
    validated_json["is_cve_rejected_empty_percentage"] = percentage(validated_json["is_cve_rejected_empty"])
    validated_json["is_cve_rejected_total"] = validated_json["is_cve_rejected_true"] \
        + validated_json["is_cve_rejected_false"] + validated_json["is_cve_rejected_empty"]

    validated_json["referenced_cve_true_percentage"] = percentage(validated_json["referenced_cve_true"])
    validated_json["referenced_cve_false_percentage"] = percentage(validated_json["referenced_cve_false"])
    validated_json["referenced_cve_empty_percentage"] = percentage(validated_json["referenced_cve_empty"])
    validated_json["referenced_cve_total"] = validated_json["referenced_cve_true"] \
        + validated_json["referenced_cve_false"] + validated_json["referenced_cve_empty"]

    return validated_json

def percentage(part):
  return 100 * float(part)/float(1368)

def isAffectedConfigEmpty(configs, fix):
    for config in configs:
        if config["version_upto_including"] or config["version_upto_excluding"]:
            if fix:
                return False
        if config["version_upto_including"] or config["version_upto_excluding"] or \
            config["version_from_including"] or config["version_from_including"]:
            if not fix:
                return False

    return True

def validatePrivileges(cvss, privileges):
    split_cvss = cvss.split("/")
    for elem in split_cvss:
        if "PR" in elem:
            privilege = ""
            if "N" in elem:
                privilege = "none"
            elif "L" in elem:
                privilege = "low"
            elif "M" in elem:
                privilege = "medium"
            elif "H" in elem:
                privilege = "high"            

            if privilege in privileges.lower():                
                return "true"            
            else:                
                return "false"
    return "empty"

def printChatGptResponseStats():
    response_list = getChatGptResponseFromFile()

    resp = validateJson(response_list)

    with open('chatgpt_proxy/results_final.json', 'w') as fp:
        json.dump(resp, fp, indent=4)