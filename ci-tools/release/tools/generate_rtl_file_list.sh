#!/bin/bash
# Licensed under the Apache-2.0 license

# Constants
modify_table_title="Caliptra integrator custom RTL file list"
integration_spec_relative_path="docs/CaliptraIntegrationSpecification.md"

# Check arg count
if [ $# -ne 2 ]
  then
    echo "Usage: $(basename $0) <path_to_rtl> <output_file_list>"
	exit -1
fi

# Get args
rtl_path=$1
output_file_name=$2

rtl_src_path="$rtl_path"/src
integration_spec="$rtl_path"/"$integration_spec_relative_path"

echo "Generating RTL hash file list"

# Get list of RTL files that should be modified
# Extract this from the integration spec table
# Get the table
modify_file_table=$(cat "$integration_spec" | sed -n "/$modify_table_title/,/^# /p" | grep "|")
# Extract the file names from the table
exclude_list=$(echo "$modify_file_table" | grep -o -P '(?<=\]\(../src/)[^ ]*(?=\) *\|)')

# Make sure we were able to get a couple files from the integration spec table
# (arbitrarily decided to make sure we have at least 2)
exclude_list_count=$(echo -n "$exclude_list" | grep -c '^')
if [ $exclude_list_count -lt 2 ]
  then
    echo "$(basename $0): Error parsing integration spec for modify file list. Expected at least 2 files. Found $exclude_list_count"
	exit -1
fi

# From this point on, exit and report failure if anything fails
set -euo pipefail

# Get all files of the right types within the RTL src (only .sv, .svh, .rdl, .v, and .vh files)
file_list=$(find "$rtl_src_path" -type f -name *.sv -o -iname *.svh -o -name *.rdl -o -iname *.v -o -iname *.vh | sort)

# Remove the rtl src path to get a relative path
file_list=$(echo "$file_list" | sed "s@$rtl_src_path@@")
# Remove a leading slash if present
file_list=$(echo "$file_list" | sed "s@^/@@")

# Filter out the files from the modify list
echo "Filtering out files on exclude list"
while read line; do
	# Print the files we are removing first for a sanity check
	echo "  " $(echo "$file_list" | grep $line)
	# Update the list with the file removed
	file_list=$(echo "$file_list" | grep -v $line)
done < <(echo "$exclude_list")

# Remove all UVMF files (these are only for testing and may be removed during integration)
file_list=$(echo "$file_list" | grep -v -i "uvmf")

# Save file
echo "$file_list" > "$output_file_name"
