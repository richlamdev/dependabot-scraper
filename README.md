- [Dependabot Scraper](#dependabot-scraper)
  * [Introduction](#introduction)
  * [Prerequisites](#prerequisites)
  * [Quick Start](#quick-start)
  * [TODO](#todo)
  * [License](#license)
  * [Contributing](#contributing)

# Dependabot Scraper
Dependabot Information scraper for Github


## Introduction

The two scripts scrape and parse, respectively, information regarding 
dependabot alerts for Github repositories belonging to an organization.

Primary data points parsed are open, fixed, dismissed vulnerabilities, and
ecosystem (programming language) type of vulnerability.


## Prerequisites

* Bash or ZSH Shell
* [Github CLI](https://cli.github.com/manual/installation)
  * To properly read all repos a Github token with _security_events_ scope to
read private repositories is required.
* [JQ](https://stedolan.github.io/jq/download/)
* Python 3 - This was developed and tested with Python 3.10.  Likely to work 
with Python 3.6 and above.  (f-strings used in print statements)


## Quick Start

[Login](https://cli.github.com/manual/gh_auth_login) to Github via gh cli

1. ```gh auth login```

2. ```./get_all_dependabot.sh <name of organization>```\
  Eg: ```./get_all_dependabot.sh procurify```

3. ```python3 dependa.py```

4. Output (CSV) files are written to the current folder.
  * JSON files for each repo is saved to ./output folder, in the event manual
review is needed.  This data can also be viewed via Github, assuming
appropriate permissions are granted.


## Notes

1. Technically jq is unceessary for either the bash or the python script.
Jq is used to provide convenient human readable review of the json files, if 
needed.  (Otherwise all the json returns (files) are in a single line.)


## ToDo

1. Remove dependency on gh cli command and almalgamate both scripts to
a single Python script.  (potentially have this run on as an AWS Lambda and
executed via scheduled EventBridge event and forward to a platform such as
Slack)
2. Provide method to name input / output file and folder names via command line
   paramaeters.
3. Optimize code (reduce some repetitive code).
4. Generate graphics with Plotly or alternative graphing module with Python.(?)


## References

[Github CLI login](https://cli.github.com/manual/gh_auth_login)
[List oranization repos](https://docs.github.com/en/rest/repos/repos#list-organization-repositories)
[List dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)


## License

Released under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)


## Contributing

Concerns/Questions, open an issue.  Improvements, please submit a pull request.
