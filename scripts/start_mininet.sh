#!/bin/bash

HOME_DIRECTORY=".."
CONF_DIRECTORY="${HOME_DIRECTORY}/conf"

PYTHON_DIRECTORY="${HOME_DIRECTORY}/python"
TOPOLOGY_DIRECTORY="${PYTHON_DIRECTORY}/topology"

MININET_COMMAND="python3 ${TOPOLOGY_DIRECTORY}/application.py"

#Check if required services exist
function isServiceInstalled () {
    
    status=`systemctl status $1 2> /dev/null`

    output_length=${#status}

    if [ $output_length -eq 0 ]; then
        echo "$1 is not installed"
        return 1
    else
        echo "$1 is installed"
        return 0
    fi 
}

id -u > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "ERROR: Script must be executed as root. Exiting..."
    exit 1
fi


echo -e "--------------------------Checking dependecies---------------------------\n\n"

declare -a required_services=("influxdb" "grafana-server" "telegraf")

for i in "${required_services[@]}"
do
    isServiceInstalled ${i}
    if [ $? -ne 0 ]; then
        echo "ERROR: You need to install ${i} service in order to lunch the demo application"
        exit 1
    fi
done

echo "Starting influxdb"
systemctl restart influxdb

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to launch influxdb service. Exiting..."
    exit 1
fi

diff ../conf/telegraf.conf /etc/telegraf/

if [ $? -ne 0 ]; then
    echo "Copy custom telegraf configuration to service directory"
    cp ../conf/telegraf.conf /etc/telegraf/
fi

echo "Starting telegraf"
systemctl restart telegraf

echo "Starting grafana"
systemctl restart grafana-server

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to launch Grafana service. Exiting..."
    exit 1
fi

echo "Grafana is running in http://localhost:3000"

echo -e "\n\n--------------------------Starting topology-----------------------------\n\n"

ryu-manager --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to execute ryu-manager. Exiting..."
    exit 1
fi

# Clear Mininet files
mn -c

# Launch Mininet topology
${MININET_COMMAND}