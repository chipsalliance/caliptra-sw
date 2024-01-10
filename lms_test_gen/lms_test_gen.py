import os
import subprocess
import random
import sys

def generate_lms_tests(num_vectors):
    filename = ""

    for h in range(1,5):
        for w in range(0,4):
            filename = 'fw_test_lms_n24_w'+str(2**w)+'_h'+str(h*5)+'.rs'
            command = './target/debug/create_lms_tests --n 24 --w '+str(2**w)+' --tree-height '+str(h*5)+' --tests '+str(num_vectors)+' --filename '+filename
            subprocess.check_output(command, shell=True)
            filename = 'fw_test_lms_n32_w'+str(2**w)+'_h'+str(h*5)+'.rs'
            command = './target/debug/create_lms_tests --n 32 --w '+str(2**w)+' --tree-height '+str(h*5)+' --tests '+str(num_vectors)+' --filename '+filename
            subprocess.check_output(command, shell=True)

def main():
    num_vectors = sys.argv[1]
    generate_lms_tests(num_vectors)

main()
