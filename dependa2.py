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

        combined_data = {
            **state_open,
            **state_fixed,
            **state_dismissed,
        }

        # returned the parsed data as a single large dictionary
        self.parsed_data = {"Name": name}
        self.parsed_data.update(combined_data)
        self.current_time = datetime.now()
        self.repo_dict = repo_dict

    def get_slo(self):

        CRIT_MAX_SLO_DAYS = 15
        crit_slo_exceeded = 0
        HIGH_MAX_SLO_DAYS = 30
        high_slo_exceeded = 0
        MED_MAX_SLO_DAYS = 60
        med_slo_exceeded = 0
        LOW_MAX_SLO_DAYS = 90
        low_slo_exceeded = 0

        for item in self.repo_dict:
            if (
                item["state"] == "open"
                and item["security_advisory"]["severity"] == "critical"
            ):
                temp_published_date = item["security_advisory"]["published_at"]
                published_date_obj = datetime.strptime(
                    temp_published_date, "%Y-%m-%dT%H:%M:%SZ"
                )

                age = self.current_time - published_date_obj
                if age.days >= CRIT_MAX_SLO_DAYS:
                    crit_slo_exceeded += 1

        total_crit = self.parsed_data["Open Crit"]

        print()
        print(crit_slo_exceeded)
        print(total_crit)

        return crit_slo_exceeded

    def get_state_data(self, repo_dict):

        # template dictionary keys; allows reuse of nested parse_data function
        state_template = {
            "Total": 0,
            "Crit": 0,
            "High": 0,
            "Med": 0,
            "Low": 0,
            "Date": "",
            "Npm": 0,
            "Pip": 0,
            "Rubygems": 0,
            "Nuget": 0,
            "Maven": 0,
            "Composer": 0,
            "Rust": 0,
            "Unknown": 0,
        }
        state_open = dict(state_template)
        date_list_open = []

        state_fixed = dict(state_template)
        date_list_fixed = []

        state_dismissed = dict(state_template)
        date_list_dismissed = []

        def parse_data(item_dict, parsed_dict):

            parsed_dict["Total"] += 1

            if item_dict["security_advisory"]["severity"] == "critical":
                parsed_dict["Crit"] += 1
            elif item_dict["security_advisory"]["severity"] == "high":
                parsed_dict["High"] += 1
            elif item_dict["security_advisory"]["severity"] == "medium":
                parsed_dict["Med"] += 1
            else:
                parsed_dict["Low"] += 1

            if item_dict["dependency"]["package"]["ecosystem"] == "npm":
                parsed_dict["Npm"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "pip":
                parsed_dict["Pip"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "rubygems":
                parsed_dict["Rubygems"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "nuget":
                parsed_dict["Nuget"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "maven":
                parsed_dict["Maven"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "composer":
                parsed_dict["Composer"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "rust":
                parsed_dict["Rust"] += 1
            else:
                parsed_dict["Unknown"] += 1

            return parsed_dict

        for item in repo_dict:
            if item["state"] == "open":
                state_open = parse_data(item, state_open)

                # keep only first reported open alert date
                temp_pub_at_date = item["security_advisory"]["published_at"]
                date_list_open.append(
                    datetime.strptime(temp_pub_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_open["Date"] = str(min(date_list_open))

            elif item["state"] == "fixed":
                state_fixed = parse_data(item, state_fixed)

                # keep only most recent fixed alert date
                temp_fixed_at_date = item["fixed_at"]
                date_list_fixed.append(
                    datetime.strptime(temp_fixed_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_fixed["Date"] = str(max(date_list_fixed))

            elif item["state"] == "dismissed":
                state_dismissed = parse_data(item, state_dismissed)

                # keep only most recent dismissed alert date
                temp_dismissed_at_date = item["dismissed_at"]
                date_list_dismissed.append(
                    datetime.strptime(
                        temp_dismissed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                )
                state_dismissed["Date"] = str(max(date_list_dismissed))

        # amend the dictionaries keys to reflect the state data
        state_open = {
            f"Open {key}": value for key, value in state_open.items()
        }
        state_fixed = {
            f"Fixed {key}": value for key, value in state_fixed.items()
        }
        state_dismissed = {
            f"Dismissed {key}": value for key, value in state_dismissed.items()
        }

        # set a priority level for remediation for open alerts
        priority = state_open["Open Crit"] + state_open["Open High"]
        state_open["Priority"] = priority

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


def write_org_data(
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
        "Open Critical": 0,
        "Open High": 0,
        "Open Medium": 0,
        "Open Low": 0,
        "Open Npm": 0,
        "Open Pip": 0,
        "Open Rubygems": 0,
        "Open Nuget": 0,
        "Open Maven": 0,
        "Open Composer": 0,
        "Open Rust": 0,
        "Open Unknown": 0,
    }

    for data in range(len(parsed_data)):
        org_data["Open Critical"] += parsed_data[data]["Open Crit"]
        org_data["Open High"] += parsed_data[data]["Open High"]
        org_data["Open Medium"] += parsed_data[data]["Open Med"]
        org_data["Open Low"] += parsed_data[data]["Open Low"]
        org_data["Open Npm"] += parsed_data[data]["Open Npm"]
        org_data["Open Pip"] += parsed_data[data]["Open Pip"]
        org_data["Open Rubygems"] += parsed_data[data]["Open Rubygems"]
        org_data["Open Nuget"] += parsed_data[data]["Open Nuget"]
        org_data["Open Maven"] += parsed_data[data]["Open Maven"]
        org_data["Open Composer"] += parsed_data[data]["Open Composer"]
        org_data["Open Rust"] += parsed_data[data]["Open Rust"]
        org_data["Open Unknown"] += parsed_data[data]["Open Unknown"]

    org_data_header = org_data.keys()
    org_data_csv = "org_data2.csv"
    with open(org_data_csv, "w") as org_data_file:
        writer = csv.DictWriter(org_data_file, fieldnames=org_data_header)
        writer.writeheader()
        writer.writerow(org_data)
    print()
    print(f"CSV of all organization data written to {org_data_csv}")
    print()


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

        input_file.get_slo()

    # sort the data by priority number (sum of high and critical vulns)
    sorted_data = sorted(
        parsed_data, key=lambda d: d["Priority"], reverse=True
    )

    write_csv_data(sorted_data)
    write_txt_data(sorted_data)

    write_org_data(
        files_no_alerts, input_files, files_dependabot_disabled, parsed_data
    )


if __name__ == "__main__":
    main()
