IPMI to MQTT publisher (OOB mode)
=================================

This script instantiates a pool of workers, one for each BMC host listed in the configuration file.
At every sampling interval, a worker reads all (default) available sensors and sends
the values to the corresponding MQTT topic.

Prerequisites
--------------

This script is intended to be executed on a service node with access to the 
management and the public network. It needs the Python MQTT library and one of the  
``ipmitool/freeipmi`` commands installed.

Python 
^^^^^^^

On the service node install the required Python modules
::

    pip install -r requirements.txt


IPMI
^^^^

``Ipmitool/freeipmi`` working commands (use your distro package manager)


Configuration
-------------

SDR dump file
^^^^^^^^^^^^^

Before running the service, it is required to create the sdr file ``sdr-dump`` for the monitored system. For example, in the service folder run
::

    ipmitool -I lanplus -H <bmc-ip> -U <bmc_user> -P <bmc_password> sdr dump sdr-dump

Config file
^^^^^^^^^^^^^

Create the configuration file from the ``example_ipmi_pub.conf`` file:
::

    cp example_ipmi_pub.conf ipmi_pub.conf


Entries of the ``.conf`` file to be defined for this plugin.

MQTT_BROKER
  IP Address of the MQTT broker server.
MQTT_PORT
  Port number of the MQTT broker server.
MQTT_TOPIC    
  The initial section of the MQTT topic which define the *sensor location* as per Examon datamodel specifications
MQTT_USER
  Username of the MQTT user
MQTT_PASSWORD
  Password of the MQTT user
IPMI_SENS_TAGS   
  List (comma separated) of IPMI sensors to be collected. Leave empty to collect all sensors.
IPMI_OPTIONS
  Additional options to pass to the tool in use (common to all the BMCs)
IPMI_RENAME_LABEL
  A dictionary to be used to rename metrics returned by the tool. Useful in cases where metric names contain typos or inaccuracies.
  Example:
  Given the following output from the tool
  ::
      $ ipmitool ... sdr elist full
      Inlet Temp       | 05h | ok  | 64.96 | 18 degrees C
      Temp             | 01h | ok  |  3.1 | 36 degrees C
      Temp             | 02h | ok  |  3.2 | 37 degrees C
      ...

  We would like to rename "Temp" to "CPU1 Temp" and "CPU2 Temp". To obtain this we need to set:
  ::
  
      IPMI_RENAME_LABEL = {"Temp_01h":"CPU1 Temp", "Temp_02h":"CPU2 Temp"}

TS               
  Sampling time in seconds
LOG_FILENAME 
  Name of the log file.
PID_FILENAME     
  Name of the PID file.
BMCIP_FILENAME   
  The file containing the list of IPs and hostnames of the nodes to be monitored.
BMC_USERNAME     
  Username of the BMC user.
BMC_PASSWORD
  Password of the BMC user.   

BMC IP file
^^^^^^^^^^^^^^
The ``example_host_file`` contains the information needed by the tool in use (i.e. ``ipmitool``) to connect to each BMC in the cluster. In addition to containing the IP of the BMC and the hostname of the referenced node, it is also useful for fine-grained configuration in cases where the cluster consists of heterogeneous nodes and thus requires custom options.

The four headings in the file are:

BMC-IP
  IP Address of the BMC.
HOSTNAME
  The hostname of the node.
USER
  Username of the BMC user.
PASSWORD
  Password of the BMC user.
CUSTOM_OPTIONS
  Additional options to pass to the tool in use (i.e. the sdr file) when connecting to the BMC.


An initial file can be obtained from a given hostfile, for example:
::

    cat /etc/hosts | grep '\-bmc' | awk '{print $1 " " $3}' | tee bmc_ip_file


Options
-------
::

    usage: ipmi_pub.py [-h] [-b B] [-p P] [-t T] [-s S] [-x X] [-l L] [-L L]
                      [-f F] [-U U] [-P P] [-m M] [-r R] [-o O] [-n N]
                      {run,start,stop,restart}

    positional arguments:
      {run,start,stop,restart}
                            Run mode

    optional arguments:
      -h, --help            show this help message and exit
      -b B                  IP address of the MQTT broker
      -p P                  Port of the MQTT broker
      -t T                  MQTT topic
      -s S                  Sampling time (seconds)
      -x X                  pid filename
      -l L                  log filename
      -L L                  log level
      -f F                  BMC ip addresses filename
      -U U                  BMC username
      -P P                  BMC password
      -m M                  MQTT username
      -r R                  MQTT password
      -o O                  Additional options for the IPMI command
      -n N                  Rename IPMI labels (dictionary)



Run 
---
Execute as:   
::
    
  python ipmi_pub.py -U <username> -P <password> -f <bmc_ip_file> run

Systemd
-------
This script is intended to be used as a service under systemd. SIGINT should be 
used as the signal to cleanly stop/kill the running script.

