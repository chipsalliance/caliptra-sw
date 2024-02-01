#!/bin/bash
# Licensed under the Apache-2.0 license

# This tool is used to generate a hash over the Caliptra RTL files
# This can be used to verify the integrity of the RTL after it has been integrated
# The hash for the release is included in the release_notes.txt
# 
# Usage: rtl_hash.sh <path_to_rtl_src_dir> <rtl_file_list>
#   path_to_rtl_src_dir     Path to the Caliptra RTL files. This is the src/ directory within 
#                           the caliptra RTL repo. This may differ once integrated
#   rtl_file_list           This list of all the files that should be included in the hash
#                           is generated and packaged with the release (rtl_hash_file_list.txt)
#
# Certain files are expected to be modified during integration. These are mentioned in
# the CaliptraIntegrationSpecification.md in the RTL repo and are excluded from the rtl hash
# file list used to generate the RTL hash
#
# If any files in the list are not found, an error will be output and mention all missing files
# The hash will not be computed since it will not match the release hash with any files missing

# Exit and report failure if anything fails
set -euo pipefail

# Check arg count
if [ $# -ne 2 ]
  then
    echo "Usage: $(basename $0) <path_to_rtl_src_dir> <rtl_file_list>"
	exit -1
fi

# Get args
rtl_path=$1

# Read expected file list, prepend rtl path, and store in array
IFS=$'\n' expected_file_list=($(cat "$2" | sed "s@^@""$rtl_path""/@"))

# Make sure all files exist
missing_files=0
for file in "${expected_file_list[@]}"
do
	# Check if the file is missing
	if ! test -f "$file"; then
		# Report any missing files (and keep count)
		if [ "$missing_files" -eq 0 ]; then
			echo "Missing expected files: "
		fi
		missing_files=$(($missing_files + 1))
		echo "  $file"
	fi
done

# Calculate the hash (only if no files were missing)
if [ "$missing_files" -eq 0 ]; then
	hash=$(cat "${expected_file_list[@]}" | sha384sum | tr -d "\n *-")
	echo "$hash"
else
	echo "Failed to generate RTL hash"
	exit -1
fi

