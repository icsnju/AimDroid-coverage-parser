#! /usr/bin/python

import os, sys, traceback, subprocess, platform

DIR=os.path.abspath(os.path.dirname(__file__))

JAVA='java'

MVN='mvn'

MAIN_CLASS='org.javelus.minitrace.android.coverage.CoverageDataParser'

CLASSPATH_FILE=os.path.join(DIR, 'classpath.' + platform.system())

if __name__ == '__main__':
    try:
        if not os.path.exists(CLASSPATH_FILE):
            cmd = [MVN, 'dependency:build-classpath', '-Dmdep.outputFile=' + CLASSPATH_FILE]
            print(' '.join(cmd))
            subprocess.check_call(cmd)
        with open(CLASSPATH_FILE, 'r') as f:
            CLASSPATH = f.read().strip()
        cmd = [JAVA, '-cp', CLASSPATH + os.pathsep + os.path.join(DIR, 'target', 'classes'), MAIN_CLASS] + sys.argv[1:]
        print(' '.join(cmd))
        subprocess.call(cmd)
    except:
        traceback.print_exc()
