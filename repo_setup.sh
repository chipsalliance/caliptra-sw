#!/bin/bash

set -eux
ssh ocp-host -t 'git clone https://github.com/clundin25/caliptra-sw --branch=faster-timeout --depth=1'
