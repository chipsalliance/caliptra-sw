# Generate LMS test vectors with different parameters

## generate rust files for different parameter sets
1. Clone sw repo for lms test .rs file creation: https://github.com/ericeilertson/create_lms_tests
2. Run cargo build
3. Copy lms_test_gen.py script to /create_lms_tests/ area
4. Generate required tests by running the following command:
    python3 lms_test_gen.py <number of test vectors per test>
    Sample command: python3 lms_test_gen.py 2
 
## generate bin files to test hardware accelerator
5. Copy the .rs files generated in step 3 to /caliptra-sw/drivers/test-fw/src/bin/
6. Copy lms_update_cargo.py script to caliptra-sw dir
7. Run the script to update the Cargo.toml file with the new tests. This is needed to build and generate bin files
    Python3 lms_update_cargo.py
 
8. Build tests as you normally would
    cd caliptra-sw/drivers/test-fw/
    ./build.sh
9. cd caliptra-sw
10. mkdir temp
11. Move the generated bin files to ../target/riscv32imc-unknown-none-elf/firmware/
    cp ../target/riscv32imc-unknown-none-elf/firmware/<bin file> ./temp/.

## run regression for bin files
12. Copy rename_lms_files.py script to caliptra-sw area and run to post-process the bin files in folder created in step 9
    Python3 rename_lms_files.py <path_to_bin_files>
    Sample command: python3 rename_lms_files.py ./temp
 
13. Copy final test folders from /caliptra-sw/temp/ to our Caliptra/src/integration/test_suites area
14. Update regression yml file to include tests in nightly regression