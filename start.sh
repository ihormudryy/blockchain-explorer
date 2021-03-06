#
#    SPDX-License-Identifier: Apache-2.0
#

#!/bin/bash
#
#Redirecting console.log to log file.
#Please visit ./logs/app to view the application logs and visit the ./logs/db to view the Database logs and visit the ./log/console for the console.log
# Log rotating for every 7 days.

rm -rf /tmp/fabric-client-kvs_peerOrg*
rm -rf ./logs/app & rm -rf ./logs/db & rm -rf ./logs/console
mkdir -p ./logs/app & mkdir -p ./logs/db & mkdir -p ./logs/console

LOG_CONSOLE_PATH="logs/console/console-$(date +%Y-%m-%d).log"
find ./logs/app -mtime +7 -type f -delete & find ./logs/db -mtime +7 -type f -delete & find ./logs/console -mtime +7 -type f -delete

echo "************************************************************************************"
echo "**************************** Hyperledger Explorer **********************************"
echo "************************************************************************************"
echo "***** Please check the log [$LOG_CONSOLE_PATH] for any error *****"
echo "************************************************************************************"

if [ $NODE_ENV = "development" ]; then
  echo "*********************************** $NODE_ENV ************************************"
  ./node_modules/.bin/nodemon main.js --ignore ./tmp/ >> $LOG_CONSOLE_PATH
else
  node main.js --watch >> $LOG_CONSOLE_PATH
fi
