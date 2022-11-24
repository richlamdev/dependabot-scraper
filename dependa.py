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

        self.name = name

        (
            self.total_open,
            self.published_at,
            self.open_crit,
            self.open_high,
            self.open_med,
            self.open_low,
        ) = self.get_state_data("open", repo_dict)

        (
            self.total_fixed,
            self.fixed_at,
            self.fixed_crit,
            self.fixed_high,
            self.fixed_med,
            self.fixed_low,
        ) = self.get_state_data("fixed", repo_dict)

        (
            self.total_dismissed,
            self.dismissed_at,
            self.dismissed_crit,
            self.dismissed_high,
            self.dismissed_med,
            self.dismissed_low,
        ) = self.get_state_data("dismissed", repo_dict)

        (
            self.open_npm,
            self.open_pip,
            self.open_rubygems,
            self.open_nuget,
            self.open_maven,
            self.open_composer,
            self.open_rust,
            self.open_unknown,
        ) = self.get_eco_data("open", repo_dict)

        (
            self.fixed_npm,
            self.fixed_pip,
            self.fixed_rubygems,
            self.fixed_nuget,
            self.fixed_maven,
            self.fixed_composer,
            self.fixed_rust,
            self.fixed_unknown,
        ) = self.get_eco_data("fixed", repo_dict)

        (
            self.dismissed_npm,
            self.dismissed_pip,
            self.dismissed_rubygems,
            self.dismissed_nuget,
            self.dismissed_maven,
            self.dismissed_composer,
            self.dismissed_rust,
            self.dismissed_unknown,
        ) = self.get_eco_data("dismissed", repo_dict)

        self.priority = self.get_crit_high_sum()

    def get_language(self, item_dict, eco_dict):

        if item_dict["dependency"]["package"]["ecosystem"] == "npm":
            eco_dict["npm"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "pip":
            eco_dict["pip"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "rubygems":
            eco_dict["rubygems"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "nuget":
            eco_dict["nuget"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "maven":
            eco_dict["maven"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "composer":
            eco_dict["composer"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "rust":
            eco_dict["rust"] += 1
        else:
            eco_dict["unknown"] += 1

        return eco_dict

    def get_eco_data(self, state, repo_dict):

        get_eco_dict = {
            "npm": 0,
            "pip": 0,
            "rubygems": 0,
            "nuget": 0,
            "maven": 0,
            "composer": 0,
            "rust": 0,
            "unknown": 0,
        }

        for item in repo_dict:

            if item["state"] == state:
                if state == "open":
                    get_eco_dict = self.get_language(item, get_eco_dict)
                if state == "fixed":
                    get_eco_dict = self.get_language(item, get_eco_dict)
                if state == "dismissed":
                    get_eco_dict = self.get_language(item, get_eco_dict)

        return (
            get_eco_dict["npm"],
            get_eco_dict["pip"],
            get_eco_dict["rubygems"],
            get_eco_dict["nuget"],
            get_eco_dict["maven"],
            get_eco_dict["composer"],
            get_eco_dict["rust"],
            get_eco_dict["unknown"],
        )

    def get_state_data(self, state, repo_dict):

        total = 0
        date_list = []
        crit = 0
        high = 0
        med = 0
        low = 0
        date = ""

        for item in repo_dict:
            if item["state"] == state:
                total += 1

                if state == "open":
                    temp_pub_at_date = item["security_advisory"][
                        "published_at"
                    ]
                    date_list.append(
                        datetime.strptime(
                            temp_pub_at_date, "%Y-%m-%dT%H:%M:%SZ"
                        )
                    )
                    date = str(min(date_list))

                if state == "fixed":
                    temp_fixed_at_date = item["fixed_at"]
                    date_list.append(
                        datetime.strptime(
                            temp_fixed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                        )
                    )
                    date = str(max(date_list))

                if state == "dismissed":
                    temp_dismissed_at_date = item["dismissed_at"]
                    date_list.append(
                        datetime.strptime(
                            temp_dismissed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                        )
                    )
                    date = str(max(date_list))

                if item["security_advisory"]["severity"] == "critical":
                    crit += 1
                elif item["security_advisory"]["severity"] == "high":
                    high += 1
                elif item["security_advisory"]["severity"] == "medium":
                    med += 1
                else:
                    low += 1

        return (
            total,
            date,
            crit,
            high,
            med,
            low,
        )

    def get_crit_high_sum(self):
        return self.open_crit + self.open_high


def get_files(dir):

    repos_list = []
    repos_no_alerts = []
    repos_dependabot_disabled = []

    input_list = Path(dir).iterdir()

    for item in input_list:
        if item.is_file():
            # remove files (repos) less than 5 bytes; likely repos without dependabot alerts
            if item.stat().st_size < 5:
                repos_no_alerts.append(item)
                continue
            # remove files (repos) less than 500 bytes; likely repos with dependabot disabled
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
    # this regex is only valid because jq was used to reformat the returned json
    for json_file in invalid_json_files:
        with open(json_file) as file:
            json_read = file.read()
            # match = re.findall(r"  \}\n\]\n\[", json_read)
            match = re.sub(r"  \}\n\]\n\[", r"},", json_read, count=25)

        with open(json_file, "w") as file:
            file.write(match)

    return valid_json_files, invalid_json_files


def get_org_data(all_data):

    org_data = {
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

    for data in range(len(all_data)):
        org_data["open critical"] += all_data[data]["open_crit"]
        org_data["open high"] += all_data[data]["open_high"]
        org_data["open medium"] += all_data[data]["open_med"]
        org_data["open low"] += all_data[data]["open_low"]
        org_data["open npm"] += all_data[data]["open_npm"]
        org_data["open pip"] += all_data[data]["open_pip"]
        org_data["open rubygems"] += all_data[data]["open_rubygems"]
        org_data["open nuget"] += all_data[data]["open_nuget"]
        org_data["open maven"] += all_data[data]["open_maven"]
        org_data["open composer"] += all_data[data]["open_composer"]
        org_data["open rust"] += all_data[data]["open_rust"]
        org_data["open unknown"] += all_data[data]["open_unknown"]

    return org_data


def main():

    all_data = []

    input_files, files_no_alerts, files_dependabot_disabled = get_files(
        "./output"
    )

    valid_files, invalid_files = validate_json(input_files)

    for input_file in input_files:

        with open(input_file, "r") as f:
            dependa_dict = json.load(f)

        # create object for every repo
        input_file = Repo(input_file.stem, dependa_dict)

        all_data.append(vars(input_file))

    # sort the data by priority number (sum of high and critical vulns)
    sorted_data = sorted(all_data, key=lambda d: d["priority"], reverse=True)

    repo_header = all_data[0].keys()

    all_data_csv = "all_data.csv"

    with open(all_data_csv, "w") as all_data_file:
        writer = csv.DictWriter(all_data_file, fieldnames=repo_header)
        writer.writeheader()
        writer.writerows(sorted_data)

    print(f"CSV of all dependabot repos written to {all_data_csv}")

    all_data_txt = "all_data.txt"

    with open(all_data_txt, "w") as all_data_file:
        pp = pprint.PrettyPrinter(
            depth=4, sort_dicts=False, stream=all_data_file
        )
        pp.pprint(sorted_data)

    print(f"Text file of all dependabot repos written to {all_data_txt}")

    ####################################
    # gather repo stats across the org #
    ####################################

    total_repos = (
        len(input_files)
        + len(files_no_alerts)
        + len(files_dependabot_disabled)
    )

    print()
    print(f"Total number of repos: {str(total_repos)}")

    # print(f"Repos with dependabot alerts:\n {input_files}")
    print(f"Number of repos with dependabot alerts: {str(len(input_files))}")

    # print(f"Repos without dependabot alerts:\n {files_no_alerts}")
    print(f"Number of repos without alerts: {str(len(files_no_alerts))}")

    #    print(
    #        f"Repos with dependabot alerts disabled:\n {files_dependabot_disabled}"
    #    )
    print(
        f"Number of repos with dependabot alerts disabled: {str(len(files_dependabot_disabled))}"
    )

    repo_stats = {
        "total repos": total_repos,
        "repos with alerts": len(input_files),
        "repos without alert": len(files_no_alerts),
        "repos disabled": len(files_dependabot_disabled),
    }

    print()
    org_data = get_org_data(all_data)

    repo_stats.update(org_data)

    print(repo_stats)

    all_repo_header = repo_stats.keys()

    org_data_csv = "org_data.csv"

    with open(org_data_csv, "w") as org_data_file:
        writer = csv.DictWriter(org_data_file, fieldnames=all_repo_header)
        writer.writeheader()
        writer.writerow(repo_stats)

    print()
    print(f"CSV of all organization data written to {org_data_csv}")
    print()


if __name__ == "__main__":
    main()
