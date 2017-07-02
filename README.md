# README

## Build

1. Use maven

    mvn compile


## Run

1. A single file


        run.py -apk taobao.apk -cov mini_trace_xxxxx_coverage.dat


2. A list of sorted file


        run.py -apk taobao.apk -covlist listfile.txt

    The list file contains a list of coveage dat file, relative to the list file.


        |- coverage
               |
               +-listfile.txt
               +-1_mini_trace_xxxxx_coverage.dat
               +-2_mini_trace_xxxxx_coverage.dat
               +-3_mini_trace_xxxxx_coverage.dat
               +-4_mini_trace_xxxxx_coverage.dat

    The content of the list file may be:


        1_mini_trace_xxxxx_coverage.dat
        4_mini_trace_xxxxx_coverage.dat

3. Data directory produced by MoniDroid


        run.py -apk taobao.apk -moni ./com.taobao/coverage
