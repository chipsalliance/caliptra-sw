import os
import subprocess

def update_cargo_toml_file():
    f = open("drivers/test-fw/Cargo.toml", "a")
    filename = []
    ext = '.rs'

    filename.append('fw_test_lms_n24_w')
    filename.append('fw_test_lms_n32_w')

    for file in filename:
        for h in range(1,4):
            for w in range(0,4):
                file_iter = file+str(2**w)+'_h'+str(h*5)
                f.write('[[bin]]\n')
                f.write('name = "'+file_iter+'"\n')
                f.write('path = "src/bin/'+file_iter+ext+'"\n')
                f.write('required-features = ["riscv"]\n')
                f.write('\n')

update_cargo_toml_file()

            
