#/bin/bash

# usage:
#
# ./get_all_dependabot.sh <organization_name>
#
# Requires gh cli and to be logged in with appropriate permissions to read
# (retrieve) all repo from an organization
#
# Queries all of the repos from a list created, then retrieve
# any dependabot information from each repo
#
OUTPUT_DIR="./output"

function get_repos {

  TEMP_REPO_OUTPUT="$1_temp_repo_list.txt"
  REPO_OUTPUT="$1_repo_list.txt"

  echo "Getting all non-archived repos from $1."

  gh repo list "$1" -L 500 --no-archived >> "${TEMP_REPO_OUTPUT}"

  # remove all other information, make only a list of the active repos
  awk -F "\t" '{print $1}' "${TEMP_REPO_OUTPUT}"  | awk -F "/" '{print $2}' > \
  "${REPO_OUTPUT}"

  echo "List of repos written to the file ${REPO_OUTPUT}"

  rm $TEMP_REPO_OUTPUT

}


function get_dependabot_info {

  TEMP_OUTPUT="repo_temp.json"

  echo "Checking if ./output folder exists"
  if [[ ! -d "${OUTPUT_DIR}" ]]; then
    echo "Output folder does not exist, creating ${OUTPUT_DIR}"
    mkdir "${OUTPUT_DIR}"
  fi

  while IFS= read -r line; do
    echo "Obtaining dependabot information for: $line"

    gh api \
      -H "Accept: application/vnd.github+json" \
      /repos/$1/$line/dependabot/alerts --paginate > \
      "${OUTPUT_DIR}/${TEMP_OUTPUT}"

    jq -r '.' "${OUTPUT_DIR}/${TEMP_OUTPUT}" > "${OUTPUT_DIR}/${line}.json"

  done < "${REPO_OUTPUT}"

  if [[ -f "${OUTPUT_DIR}/${TEMP_OUTPUT}" ]]; then
    echo
    echo Removing temporary file "${OUTPUT_DIR}/${TEMP_OUTPUT}"
    rm "${OUTPUT_DIR}/${TEMP_OUTPUT}"
  fi

  echo
  echo "Dependabot information for each repo is stored in ${OUTPUT_DIR}"
  echo

  # remove files less than 5 bytes; repos without any dependabot alerts
  #find $OUTPUT_DIR -type f -size -5c -print0 | xargs -0 rm

  # determine repos with dependabot disabled
  # find ./input/ -type f -print0 | xargs -0 grep '"message": "Dependabot"*'
}


function test_json {
# To Do. Fix paginated via BASH instead of python script
  JSON_LIST="${1}_json_list.txt"

  find "${OUTPUT_DIR}" -type f -iname *.json > "${JSON_LIST}"

  while IFS= read -r line; do
    echo "Checking for paginated json in file: ${line}"
    VALID_JSON=$(python3 -m json.tool "${line}" > /dev/null)
    if [[ $? -ne 0 ]]; then
      echo "invalid json file: $line"
    fi
  done < "${JSON_LIST}"

}


function main {

  echo "Verifying loging status via github (gh) cli"
  GH_STATUS=$(gh auth status)
  if [[ $? -ne 0 ]]; then
    echo "Please ensure you are logged into github via github cli before running this script."
    echo
    echo "Refer to: https://cli.github.com/manual/gh_auth_login"
    exit 1
  fi

  if [ $# -eq 0 ]; then
    echo "Please provide an organization name"
    echo
    echo "Example: ./get_all_dependabot.sh google"
    exit 1
  fi

  get_repos "$@"
  get_dependabot_info "$@"
  #test_json "$@"
}


main "$@"

