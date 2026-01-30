#!/bin/bash
# Be sure to set API_KEY, TENANT_ID, and NEW_TENANT_ID env vars
cd "${0%/*/*}" # set the current directory to the one above this script
mvn -Dsuite=test-suites/test-all test
