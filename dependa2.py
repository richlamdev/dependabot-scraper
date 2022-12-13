#!/bin/python3
#
# Basic Python script to gather dependabot alert information across all repos
# listed.
#
# There are likely more optimal methods to implement this script.
# For the short term this works.  To be revisited shortly.

import json
import pprint
import re
import csv
from datetime import datetime
from pathlib import Path


class Repo:
    def __init__(self, name, repo_dict):

        (
            state_open,
            state_fixed,
            state_dismissed,
        ) = self.get_state_data(repo_dict)

        # amend the dictionaries keys to reflect the state
        open_state = {
            f"Open {key}": value for key, value in state_open.items()
        }
        fixed_state = {
            f"Fixed {key}": value for key, value in state_fixed.items()
        }
        dismissed_state = {
            f"Dismissed {key}": value for key, value in state_dismissed.items()
        }

        # set a priority level of remediation for each repo
        priority = state_open["high"] + state_open["crit"]

        name_dict = {}
        name_dict["name"] = name
        priority_dict = {}
        priority_dict["priority"] = priority

        # returned the parsed data as a large dictionary
        self.parsed_data = {
            **name_dict,
            **open_state,
            **fixed_state,
            **dismissed_state,
            **priority_dict,
        }

    def parse_data(self, item_dict, sev_dict):

        sev_dict["total"] += 1

        if item_dict["security_advisory"]["severity"] == "critical":
            sev_dict["crit"] += 1
        elif item_dict["security_advisory"]["severity"] == "high":
            sev_dict["high"] += 1
        elif item_dict["security_advisory"]["severity"] == "medium":
            sev_dict["med"] += 1
        else:
            sev_dict["low"] += 1

        if item_dict["dependency"]["package"]["ecosystem"] == "npm":
            sev_dict["npm"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "pip":
            sev_dict["pip"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "rubygems":
            sev_dict["rubygems"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "nuget":
            sev_dict["nuget"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "maven":
            sev_dict["maven"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "composer":
            sev_dict["composer"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "rust":
            sev_dict["rust"] += 1
        else:
            sev_dict["unknown"] += 1

        return sev_dict

    def get_state_data(self, repo_dict):

        state_open = {
            "total": 0,
            "crit": 0,
            "high": 0,
            "med": 0,
            "low": 0,
            "date": "",
            "npm": 0,
            "pip": 0,
            "rubygems": 0,
            "nuget": 0,
            "maven": 0,
            "composer": 0,
            "rust": 0,
            "unknown": 0,
        }
        date_list_open = []

        state_fixed = {
            "total": 0,
            "crit": 0,
            "high": 0,
            "med": 0,
            "low": 0,
            "date": "",
            "npm": 0,
            "pip": 0,
            "rubygems": 0,
            "nuget": 0,
            "maven": 0,
            "composer": 0,
            "rust": 0,
            "unknown": 0,
        }
        date_list_fixed = []

        state_dismissed = {
            "total": 0,
            "crit": 0,
            "high": 0,
            "med": 0,
            "low": 0,
            "date": "",
            "npm": 0,
            "pip": 0,
            "rubygems": 0,
            "nuget": 0,
            "maven": 0,
            "composer": 0,
            "rust": 0,
            "unknown": 0,
        }
        date_list_dismissed = []

        for item in repo_dict:
            if item["state"] == "open":
                state_open = self.parse_data(item, state_open)

                # get earliest date of reported alert (oldest date)
                temp_pub_at_date = item["security_advisory"]["published_at"]
                date_list_open.append(
                    datetime.strptime(temp_pub_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_open["date"] = str(min(date_list_open))

            elif item["state"] == "fixed":
                state_fixed = self.parse_data(item, state_fixed)

                # get latest date of fixed alert (most recent date)
                temp_fixed_at_date = item["fixed_at"]
                date_list_fixed.append(
                    datetime.strptime(temp_fixed_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_fixed["date"] = str(max(date_list_fixed))

            elif item["state"] == "dismissed":
                state_dismissed = self.parse_data(item, state_dismissed)

                # get latest date of dismissed alert (most recent date)
                temp_dismissed_at_date = item["dismissed_at"]
                date_list_dismissed.append(
                    datetime.strptime(
                        temp_dismissed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                )
                state_dismissed["date"] = str(max(date_list_dismissed))

        return state_open, state_fixed, state_dismissed


def get_files(dir):

    repos_list = []
    repos_no_alerts = []
    repos_dependabot_disabled = []

    input_list = Path(dir).iterdir()

    # this is the wrong way to determine repo status! Todo:
    # 1. Detect repos with alerts via empty item return
    # 2. Determine disabled dependabot repo via presence of message key

    for item in input_list:
        if item.is_file():
            # remove files (repos) less than 5 bytes; likely repos without
            # dependabot alerts
            if item.stat().st_size < 5:
                repos_no_alerts.append(item)
                continue
            # remove files (repos) less than 500 bytes; likely repos with
            # dependabot disabled
            if item.stat().st_size < 500 and item.stat().st_size > 6:
                repos_dependabot_disabled.append(item)
                continue
            repos_list.append(item)

    # remove repos with no alerts from the list to check for vulns
    repos_list = list(set(repos_list) - set(repos_no_alerts))
    # remove repos with dependbot alerts disabled
    repos_list = list(set(repos_list) - set(repos_dependabot_disabled))

    return repos_list, repos_no_alerts, repos_dependabot_disabled


def validate_json(json_list):

    valid_json_files = []
    invalid_json_files = []

    for json_file in json_list:

        with open(json_file) as file:
            try:
                json.load(file)
                valid_json_files.append(json_file.name)
            except ValueError as err:
                print("invalid json file: " + str(json_file))
                invalid_json_files.append(json_file)

    # find and replace where paginate occurred during http requests
    # this regex is only valid because jq was used to reformat the returned
    # json; this is not an ideal process!
    for json_file in invalid_json_files:
        with open(json_file) as file:
            json_read = file.read()
            # match = re.findall(r"  \}\n\]\n\[", json_read)
            match = re.sub(r"  \}\n\]\n\[", r"},", json_read, count=25)

        with open(json_file, "w") as file:
            file.write(match)

    return valid_json_files, invalid_json_files


def get_org_data(
    repos_no_vulns, repos_with_vulns, repos_disabled, parsed_data
):

    num_no_vulns = len(repos_no_vulns)
    num_with_vulns = len(repos_with_vulns)
    num_disabled = len(repos_disabled)

    total_repos = num_no_vulns + num_with_vulns + num_disabled

    org_data = {
        "Total Number of Repos": total_repos,
        "Repos with alerts": num_with_vulns,
        "Repos without alerts": num_no_vulns,
        "Repos disabled alerts": num_disabled,
        "open critical": 0,
        "open high": 0,
        "open medium": 0,
        "open low": 0,
        "open npm": 0,
        "open pip": 0,
        "open rubygems": 0,
        "open nuget": 0,
        "open maven": 0,
        "open composer": 0,
        "open rust": 0,
        "open unknown": 0,
    }

    for data in range(len(parsed_data)):
        org_data["open critical"] += parsed_data[data]["open_crit"]
        org_data["open high"] += parsed_data[data]["open_high"]
        org_data["open medium"] += parsed_data[data]["open_med"]
        org_data["open low"] += parsed_data[data]["open_low"]
        org_data["open npm"] += parsed_data[data]["open_npm"]
        org_data["open pip"] += parsed_data[data]["open_pip"]
        org_data["open rubygems"] += parsed_data[data]["open_rubygems"]
        org_data["open nuget"] += parsed_data[data]["open_nuget"]
        org_data["open maven"] += parsed_data[data]["open_maven"]
        org_data["open composer"] += parsed_data[data]["open_composer"]
        org_data["open rust"] += parsed_data[data]["open_rust"]
        org_data["open unknown"] += parsed_data[data]["open_unknown"]

    return org_data


def write_csv_data(sorted_data):

    repo_header = sorted_data[0].keys()
    parsed_data_csv = "parsed_data2.csv"

    with open(parsed_data_csv, "w") as parsed_data_file:
        writer = csv.DictWriter(parsed_data_file, fieldnames=repo_header)
        writer.writeheader()
        writer.writerows(sorted_data)

    print()
    print(f"CSV of all dependabot repos written to {parsed_data_csv}")


def write_txt_data(sorted_data):

    parsed_data_txt = "parsed_data2.txt"

    with open(parsed_data_txt, "w") as parsed_data_file:
        pp = pprint.PrettyPrinter(
            depth=4, sort_dicts=False, stream=parsed_data_file
        )
        pp.pprint(sorted_data)

    print()
    print(f"Text file of all dependabot repos written to {parsed_data_txt}")


def write_org_data(org_data):

    all_repo_header = org_data.keys()
    org_data_csv = "org_data2.csv"
    with open(org_data_csv, "w") as org_data_file:
        writer = csv.DictWriter(org_data_file, fieldnames=all_repo_header)
        writer.writeheader()
        writer.writerow(org_data)
    print()
    print(f"CSV of all organization data written to {org_data_csv}")
    print()


def main():

    parsed_data = []

    input_files, files_no_alerts, files_dependabot_disabled = get_files(
        "./output"
    )
    # valid_files and invalid_files vars not used, but potentially needed
    # to track paginated requests from repos with a lot of json data
    valid_files, invalid_files = validate_json(input_files)

    for input_file in input_files:
        with open(input_file, "r") as f:
            dependa_dict = json.load(f)

        # create object for every repo
        input_file = Repo(input_file.stem, dependa_dict)
        # parsed_data.append(vars(input_file))
        parsed_data.append(input_file.parsed_data)

    print(parsed_data)
    pprint.pprint(parsed_data)
    print(str(type(parsed_data)))

    # sort the data by priority number (sum of high and critical vulns)
    sorted_data = sorted(
        parsed_data, key=lambda d: d["priority"], reverse=True
    )

    write_csv_data(sorted_data)
    write_txt_data(sorted_data)

    # org_data = get_org_data(
    # files_no_alerts, input_files, files_dependabot_disabled, parsed_data
    # )
    #
    # write_org_data(org_data)
    # print()
    # print(org_data)


if __name__ == "__main__":
    main()
