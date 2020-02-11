# check_redfish.py

This is a monitoring plugin to check components and
health status of systems which support Redfish.

## Requirements
* python >= 3.6
* redfish >= 2.1.4

## Installation

### RedHat based OS
* on RedHat/CentOS you need to install python3.6 and pip from EPEL first
* on RedHat/CentOS 8 systems the package name changed to `python3-pip`
```
yum install python36-pip
```

* download and install plugin
```
cd /tmp
git clone https://github.com/bb-Ricardo/check_redfish.git
cd check_redfish
pip3 install -r requirements.txt || pip install -r requirements.txt
install -m 755 check_redfish.py -D /usr/lib64/nagios/plugins/check_redfish.py
cd /tmp
rm -rf /tmp/check_redfish
```

### Icinga2
Command definitions and a service config example for Icinga2 can be found in [contrib](contrib)

## HELP
```
usage: check_redfish.py [-H HOST] [-u USERNAME] [-p PASSWORD] [-f AUTHFILE]
                        [--sessionfile SESSIONFILE]
                        [--sessionfiledir SESSIONFILEDIR] [-h] [-w WARNING]
                        [-c CRITICAL] [-v] [-d] [-m MAX] [-r RETRIES]
                        [-t TIMEOUT] [--storage] [--proc] [--memory] [--power]
                        [--temp] [--fan] [--nic] [--bmc] [--info] [--firmware]
                        [--sel] [--mel]

This is a monitoring plugin to check components and
health status of systems which support Redfish.

R.I.P. IPMI

Version: 0.0.11 (2020-02-11)

mandatory arguments:
  -H HOST, --host HOST  define the host to request. To change the port just
                        add ':portnumber' to this parameter.

authentication arguments:
  -u USERNAME, --username USERNAME
                        the login user name
  -p PASSWORD, --password PASSWORD
                        the login password
  -f AUTHFILE, --authfile AUTHFILE
                        authentication file with user name and password
  --sessionfile SESSIONFILE
                        define name of session file
  --sessionfiledir SESSIONFILEDIR
                        define directory where the plugin saves session files

optional arguments:
  -h, --help            show this help message and exit
  -w WARNING, --warning WARNING
                        set warning value
  -c CRITICAL, --critical CRITICAL
                        set critical value
  -v, --verbose         this will add all requests and responses to output
  -d, --detailed        always print detailed result
  -m MAX, --max MAX     set maximum of returned items for --sel or --mel
  -r RETRIES, --retries RETRIES
                        set number of maximum retries (default: 3)
  -t TIMEOUT, --timeout TIMEOUT
                        set number of request timeout per try/retry (default:
                        7)

query status/health informations (at least one is required):
  --storage             request storage health
  --proc                request processor health
  --memory              request memory health
  --power               request power supply health
  --temp                request temperature sensors status
  --fan                 request fan status
  --nic                 request network interface status
  --bmc                 request bmc infos and status
  --info                request system informations
  --firmware            request firmware informations
  --sel                 request System Log status
  --mel                 request Management Processor Log status

```

## General usage
multiple request commands can be combined.

### Lets start with an example
```/usr/lib64/nagios/plugins/check_redfish.py -H 10.0.0.23 -f /etc/icinga2/ilo_credentials --storage --power```
* request BMC: 10.0.0.23
* use credentials from file: /etc/icinga2/ilo_credentials
* query health of: storage, power

### Alternative HTTPS port
If you want to use a different Port then 443 then just add the port to the Host parameter.<br>
Example for Port 8443:
```
-H 127.0.0.1:8443
```

### Authentication
Credentials can be provided in **3** ways and will be checked in following order:
* using --username and --password options (credentials will be exposed in process list)
* using an auth file which includes the credentials
* add credentials to environment

#### Authentication file
An authentication credential file can be provided. The structure looks like this:
```
username=icinga
password=readonlysecret
```

#### Environment variables
these two environment vars will be checked
* CHECK_REDFISH_USERNAME
* CHECK_REDFISH_PASSWORD
```
export CHECK_REDFISH_USERNAME=icinga
export CHECK_REDFISH_PASSWORD=readonlysecret
```

### Sessions and session resumption
To avoid delays due to login on every request and flooding the event log with
login/logout messages a session resumption was implemented. If the session in the
BMC is expired a new session and session file will be created.

**IMPORTANT**<br>
To actually benefit from this feature you need to set the user session timeout in
the BMC to a higher value then your default check interval!

If your default check interval is 5 minutes then the session timout in the BMC
should be at least 6 minutes!

#### Session file name and location
Per default a session file will be crated in the *system/user default temp path*.
These defaults can be changed with following options:

Use ```--sessionfiledir```to define where the session files should be stored
Use ```--sessionfile``` to specify the name of the session file for this particular system

#### Example
options like this:

```--sessionfiledir /var/plugin/tmp --sessionfile my-hostname.session```

results in following session file:

```/var/plugin/tmp/my-hostname.session```

### WARNING and CRITICAL
you can use warning and critical with following commands:

**--mel** (values are passed as "days")<br>
define after how many days event log entries which have a != OK severity shouldn't
be alerted anymore. On HPE systems it is not possible to set management event log entries
as cleared. So entries with a severity of warning would alarm forever. This way they change
state while they age.

**--sel** (values are passed as "days")<br>
works the same way as stated above for HPE systems just for SEL on Huawei systems

Example: ```--mel --critical 1 --warning 3```

* Entries with a != OK severity which are not older then 24 hours are reported as CRITICAL
* Entries with a != OK severity which are not older then 72 hours are reported as WARNING
* Any entries with a != OK severity which are older then 72 hours will be roprted as OK

### Detailed
Health status by default will be reported as a summary:

```[OK]: All power supplies (2) are in good condition|'ps_1'=122 'ps_2'=109```

If multiline output by default is preferred the option ```--detailed``` needs to be added
```
[OK]: Power supply 1 (865408-B21) status is: Ok
[OK]: Power supply 2 (865408-B21) status is: Ok|'ps_1'=121 'ps_2'=109
```

### Debugging
Use option ```--verbose``` to check for connection problems.
All redfish requests and responses will be printed.

### Max option
This option can be used to limit the results output for event log entries requested
by **--mel** and **--sel**

### Timeout and Retries
Sometimes an iLO4 BMC can be very slow in answering Redfish request. To avoid getting "retries exhausted"
alarms you can increase the number of retries and/or the timeout. The timeout defines the seconds after each
try/retry times out. If you increase theses values make sure to also adjust the ```check_timeout``` setting
in your [Icinga2 service definition](contrib/icinga2_hw_service_checks_example.conf). The total runtime of
this plugin (if all retries fail) can be calculated like this: (1. try + num retries) * timeout

The default number of retries is set to 3 and the default timeout is set to 7. In case all retries fail then
the plugin would be finished after 28 seconds.

```(1 + 3) * 7 = 28```

## Known limitations
* On HPE iLO4 a maximum of 30 entries will be returned for the commands
**--mel** and **--sel**
* On HPE systems the nic status is reported unreliable
* On Lenovo systems the commands **--mel** and **--sel** are not implemented due to
issues with timeouts
* On Huawei systems the command **--mel** is not implemented
* For **--storage** components which report a Status.Health as **None**
will be treated as **OK** if Status.State is set to **Enabled**

## Supported Systems
This plugin is currently tested with following systems

### Hewlett Packard Enterprise
Almost all Server which have iLO4 (2.50) or iLO5 (1.20) should work
* ProLiant BL460c Gen8
* ProLiant DL360p Gen8
* ProLiant DL360 Gen9
* ProLiant DL360 Gen10
* ProLiant DL380p Gen8
* ProLiant DL380 Gen9
* ProLiant DL380 Gen10
* ProLiant DL560 Gen10
* ProLiant DL580 Gen8
* ProLiant DL580 Gen9

### Lenovo
* ThinkSystem SR650 (BMC Version 2.12)

### Dell
* PowerEdge R630 (iDRAC Version 2.70.70.70)
* PowerEdge R740 (iDRAC Version 3.32.32.32)
* PowerEdge R930 (iDRAC Version 2.70.70.70)

### Huawei
* TaiShan 2280 V2 (iBMC Version 3.63)

### Fujitsu
* PRIMERGY RX2540 M5 (iRMC Version 2.50P)

## License
>You can check out the full license [here](LICENSE.txt)

This project is licensed under the terms of the **MIT** license.
