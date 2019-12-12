#!/bin/bash
cd "${0%/*/*}" # set the current directory to the one above this script
mvn -Dsuite=test-suites/test-unit test