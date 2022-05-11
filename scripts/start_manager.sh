#!/bin/bash

HOME_DIRECTORY=".."
PYTHON_DIRECTORY="${HOME_DIRECTORY}/python"
SDN_DIRECTORY="${PYTHON_DIRECTORY}/sdn"

SNORT_INTERFACE="s1-snort"
SNORT_COMMAND="snort -i ${SNORT_INTERFACE} -A alert-unixsock -l /tmp -c /etc/snort/snort.lua"
SNORT_LOGS="snort.logs"

RYU_MANAGER_COMMAND="ryu-manager ${SDN_DIRECTORY}/core_controller.py ${SDN_DIRECTORY}/application.py"


function waitForSnortSocketToBeUp () {

    i=1

    while [ $i -lt 10 ]; 
    do
        `sudo lsof /tmp/snort_alert > /dev/null 2>&1`

        if [ $? -eq 0 ]; then
            return 0
        fi

        echo "Socket is not up. Retrying $i out of 10..."

        sleep 2

        i=$((i+1))
    done

    echo "Firewall Rest Service could not be launched. Exiting..."
    exit 1
}

id -u > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "ERROR: Script must be executed as root. Exiting..."
    exit 1
fi


snort_check=`snort -h`
if [ $? -ne 0 ]; then
    echo "ERROR: You need to install snort3 service in order to lunch the demo application. Exiting..."
    exit 1
fi


echo -e "Mininet topology runs with the following configuration:\n"
echo -e "-------------------------------------------------------\n\n"

ovs-vsctl show > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "ERROR: Mininet Topology is not running properly. Exiting..."
    exit 1
fi

ovs-vsctl set Bridge s1 protocols=OpenFlow13
ovs-vsctl set Bridge s2 protocols=OpenFlow13

echo "Add snort interface to Edge Switch"
ip link add name ${SNORT_INTERFACE} type dummy
ip link set ${SNORT_INTERFACE} up
ovs-vsctl add-port s1 ${SNORT_INTERFACE}

ovs-ofctl -O OpenFlow13 dump-flows s1
ovs-ofctl -O OpenFlow13 dump-flows s2

ovs-vsctl show

${RYU_MANAGER_COMMAND}

#waitForSnortSocketToBeUp

exit 0