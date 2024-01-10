import os
import subprocess
import sys

def rename_files_in_directory(directory, new_name_prefix):
    for count, filename in enumerate(os.listdir(directory)):
        old_filepath = os.path.join(directory, filename)
        new_name = new_name_prefix+filename[9:]
        new_filepath = os.path.join(directory, new_name)
        os.rename(old_filepath, new_filepath)

def create_ymls(path):
    #path = './rename_lms_files'

    for filename in os.listdir(path):
        f = open(path+'/'+filename+'.yml', "w")
        f.write('# SPDX-License-Identifier: Apache-2.0\n#\n# Licensed under the Apache License, Version 2.0 (the "License");\n# you may not use this file except in compliance with the License.\n# You may obtain a copy of the License at\n#\n# http://www.apache.org/licenses/LICENSE-2.0\n#\n# Unless required by applicable law or agreed to in writing, software\n# distributed under the License is distributed on an "AS IS" BASIS,\n# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n# See the License for the specific language governing permissions and\n# limitations under the License.\n#\n---\nseed: 1\ntestname: '+filename)
        f.close()

def create_dirs(path):
    #path = './rename_lms_files'

    for filename in os.listdir(path):
        if filename.endswith('.yml'):
            command = 'mkdir '+path+'/'+filename[:-4]+'_dir'
            subprocess.check_output(command, shell=True)
            command = 'mv '+path+'/'+filename[:-4]+' '+path+'/'+filename[:-4]+'_dir/.'
            subprocess.check_output(command, shell=True)

            command = 'mv '+path+'/'+filename+' '+path+'/'+filename[:-4]+'_dir/.'
            subprocess.check_output(command, shell=True)

def rename_dirs_in_directory(root_dir):
    for subdir in os.listdir(root_dir):
        old_name = os.path.join(root_dir, subdir)
        new_name = os.path.join(root_dir, subdir[:-4])
        os.rename(old_name, new_name)

def main():
    path_to_bin_files = sys.argv[1]
    
    #Uncomment below lines if test names need to be renamed to something else
    #new_filename_prefix = sys.argv[2]
    #rename_files_in_directory(path_to_bin_files, new_filename_prefix)
    
    create_ymls(path_to_bin_files)
    create_dirs(path_to_bin_files)
    
    rename_dirs_in_directory(path_to_bin_files)

main()
