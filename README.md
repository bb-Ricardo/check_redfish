# check_redfish.py

This is a monitoring/inventory plugin to check components and
health status of systems which support Redfish.
It will also create an inventory of all components of a system.

### NetBox import support
You are also able to import the inventory files into [NetBox](https://github.com/netbox-community/netbox)
using [netbox-sync](https://github.com/bb-Ricardo/netbox-sync).

## Requirements
* python >= 3.6
* redfish >= 2.1.4

## Installation

### RedHat based OS
* on RedHat/CentOS you need to install python3.6 and pip from EPEL first
* on RedHat/CentOS 8 systems the package name changed to `python3-pip`
```bash
yum install python36-pip
```

* download and install plugin
```bash
cd /usr/lib64/nagios/plugins/
git clone https://github.com/bb-Ricardo/check_redfish.git
cd check_redfish
pip3 install -r requirements.txt || pip install -r requirements.txt
```

### Install on any OS with python3.6+ pip
Install with pip from git
```bash
pip install git+https://github.com/bb-Ricardo/check_redfish

```

Install with pip from git into virtual environment
```bash
python3 -m venv /opt/check_redfish
/opt/check_redfish/bin/pip install git+https://github.com/bb-Ricardo/check_redfish
mkdir -p /usr/lib64/nagios/plugins/check_redfish/
ln -s /opt/check_redfish/bin/check_redfish /usr/lib64/nagios/plugins/check_redfish/check_redfish.py
```

### Icinga2 and Grafana
Command definitions and a service config example for Icinga2 can be found in [contrib](contrib).
There is also an InfluxDB dashboard for some metrics included.

## HELP
```
usage: check_redfish.py [-H HOST] [-u USERNAME] [-p PASSWORD] [-f AUTHFILE]
                        [--sessionfile SESSIONFILE]
                        [--sessionfiledir SESSIONFILEDIR] [--sessionlock]
                        [--nosession] [-h] [-w WARNING] [-c CRITICAL] [-v]
                        [-d] [-m MAX] [-r RETRIES] [-t TIMEOUT]
                        [--log_exclude LOG_EXCLUDE] [--ignore_missing_ps]
                        [--ignore_unavailable_resources]
                        [--ignore_unknown_on_critical_or_warning]
                        [--enable_bmc_security_warning] [--storage] [--proc]
                        [--memory] [--power] [--temp] [--fan] [--nic] [--bmc]
                        [--info] [--firmware] [--sel] [--mel] [--all] [-i]
                        [--inventory_id INVENTORY_ID]
                        [--inventory_name INVENTORY_NAME]
                        [--inventory_file INVENTORY_FILE]

This is a monitoring/inventory plugin to check components and
health status of systems which support Redfish.
It will also create a inventory of all components of a system.

R.I.P. IPMI

Version: 1.12.1 (2025-08-07)

mandatory arguments:
  -H HOST, --host HOST  define the host to request. To change the port just
                        add ':portnumber' to this parameter

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
  --sessionlock         prevents multiple sessions and locks the session file
                        when connecting
  --nosession           Don't establish a persistent session and log out after
                        check is finished

optional arguments:
  -h, --help            show this help message and exit
  -w WARNING, --warning WARNING
                        set warning value
  -c CRITICAL, --critical CRITICAL
                        set critical value
  -v, --verbose         this will add all https requests and responses to
                        output, also adds inventory source data to all
                        inventory objects
  -d, --detailed        always print detailed result
  -m MAX, --max MAX     set maximum of returned items for --sel or --mel
  -r RETRIES, --retries RETRIES
                        set number of maximum retries (default: 3)
  -t TIMEOUT, --timeout TIMEOUT
                        set number of request timeout per try/retry (default:
                        7)
  --log_exclude LOG_EXCLUDE
                        a comma separated list of log lines (regex) to exclude
                        from log status checks (--sel, --mel)
  --ignore_missing_ps   ignore the fact that no power supplies are present and
                        report the status of the power subsystem
  --ignore_unavailable_resources
                        ignore all 'UNKNOWN' errors which indicate missing
                        resources and report as OK
  --ignore_unknown_on_critical_or_warning
                        suppress all 'UNKNOWN' errors if other checks returned
                        CRITICAL or WARNING
  --enable_bmc_security_warning
                        return status WARNING if BMC security issues are
                        detected (HPE iLO only)

query status/health information (at least one is required):
  --storage             request storage health
  --proc                request processor health
  --memory              request memory health
  --power               request power supply health
  --temp                request temperature sensors status
  --fan                 request fan status
  --nic                 request network interface status
  --bmc                 request bmc info and status
  --info                request system information
  --firmware            request firmware information
  --sel                 request System Log status
  --mel                 request Management Processor Log status
  --all                 request all of the above information at once

query inventory information (no health check):
  -i, --inventory       return inventory in json format instead of regular
                        plugin output
  --inventory_id INVENTORY_ID
                        set an ID which can be used to identify this host in
                        the destination inventory
  --inventory_name INVENTORY_NAME
                        set a name which can be used to identify this host in
                        the destination inventory
  --inventory_file INVENTORY_FILE
                        set file to write the inventory output to. Otherwise
                        stdout will be used.
```

## General usage
multiple request commands can be combined. Or use `--all` to query all system information at once

### Let's start with an example
```/usr/lib64/nagios/plugins/check_redfish/check_redfish.py -H 10.0.0.23 -f /etc/icinga2/ilo_credentials --storage --power```
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
```bash
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

If your default check interval is 5 minutes then the session timeout in the BMC
should be at least 6 minutes!

#### No Session
If no session is required (i.e.: testing, inventory collection) then a `--nosession` can
be added to close session on the BMC properly.

#### Session file name and location
Per default a session file will be crated in the *system/user default temp path*.
These defaults can be changed with following options:

Use ```--sessionfiledir``` to define where the session files should be stored.
Use ```--sessionfile``` to specify the name of the session file for this particular system.

#### Session lock file
In order to prevent the race condition of one monitoring instance creating multiple sessions
it is possible to use ```--sessionlock```.

#### Example
options like this:

```--sessionfiledir /var/plugin/tmp --sessionfile my-hostname.session```

results in following session file:

```/var/plugin/tmp/my-hostname.session```

### WARNING and CRITICAL (health checks only)
you can use warning and critical with following commands:

**IMPORTANT**<br>
WARNING and CRITICAL values can only be used properly if used with **ONE** query type.
If for example **--all** or **--mel** and **--storage** are used in the same command then you will
get inconsistent results/alarms.

#### Event Logs
**--mel** and **--sel** (values are passed as "days")<br>
define after how many days' event log entries which have a != OK severity shouldn't
be alerted anymore. On most systems it is not possible to set management event log entries
as cleared. So entries with a severity of warning would alarm forever. This way they change
state while they age.

These settings do **NOT** apply to HPE iLO "Integrated Management Logs" as these support a "repaired"
option to be set.

Example: ```--mel --critical 1 --warning 3```

* Entries with a != OK severity which are not older than 24 hours are reported as CRITICAL
* Entries with a != OK severity which are not older than 72 hours are reported as WARNING
* Any entries with a != OK severity which are older than 72 hours will be reported as OK

#### Storage
**--storage** (values are passed as "percent")<br>
define the percent of media lifetime left for SSD drives to report WARNING and/or CRITICAL.

Defaults:
* WARNING: 10%
* CRITICAL: 5%

### Detailed (health checks only)
Health status by default will be reported as a summary:

```[OK]: All power supplies (2) are in good condition|'ps_1'=122 'ps_2'=109```

If multiline output by default is preferred the option ```--detailed``` needs to be added
```
[OK]: Power supply 1 (865408-B21) status is: Ok
[OK]: Power supply 2 (865408-B21) status is: Ok|'ps_1'=121 'ps_2'=109
```

### Debugging
Use option ```--verbose``` to check for connection problems.
All redfish https requests and responses will be printed.

### Max option (health checks only)
This option can be used to limit the results output for event log entries requested
by **--mel** and **--sel**

### Log filter option
With `--log_exclude` it is possible to define log messages which will be excluded from monitoring.
This filter uses regex to match log messages. Multiple filters can be defined comma separated. Use quotes to
"escape" messages which include a comma.

Example Usage:
```
--log_exclude = '"log message, with a comma", another log message, user .* logged in'
```
Example result:
```
# ./check_redfish.py '--mel' ...
[CRITICAL]: 2022-03-04T09:48:35-06:00: The iDRAC Service Module communication with iDRAC has ended.
[CRITICAL]: 2022-03-04T09:36:13-06:00: The iDRAC Service Module communication with iDRAC has ended.
[WARNING]: 2022-03-03T09:13:19-06:00: The iDRAC Service Module communication with iDRAC has ended.
[WARNING]: 2022-03-02T15:40:15-06:00: The Integrated NIC 1 Port 1 network link is down.
[WARNING]: 2022-03-02T15:40:15-06:00: The Integrated NIC 1 Port 2 network link is down.
[WARNING]: 2022-03-02T15:40:12-06:00: The iDRAC Service Module communication with iDRAC has ended.
[WARNING]: 2022-03-02T08:16:53-06:00: The iDRAC Service Module communication with iDRAC has ended.

# ./check_redfish.py '--mel' ... --log_exclude "The iDRAC Service Module communication with iDRAC has ended"
[WARNING]: 2022-03-02T15:40:15-06:00: The Integrated NIC 1 Port 1 network link is down.
[WARNING]: 2022-03-02T15:40:15-06:00: The Integrated NIC 1 Port 2 network link is down.

# ./check_redfish.py '--mel' ... --log_exclude 'The iDRAC Service Module communication with iDRAC has ended, network link is down'
[OK]: Manager Event Log contains 2437 OK entries. Most recent notable: [OK]: 2022-03-07T10:00:13-06:00: Successfully logged in using icinga, from 10.1.2.3.
```

### Timeout and Retries
Sometimes an iLO4 BMC can be very slow in answering Redfish request. To avoid getting "retries exhausted"
alarms you can increase the number of retries and/or the timeout. The timeout defines the seconds after each
try/retry times out. If you increase these values make sure to also adjust the ```check_timeout``` setting
in your [Icinga2 service definition](contrib/icinga2_hw_service_checks_example.conf). The total runtime of
this plugin (if all retries fail) can be calculated like this: (1. try + num retries) * timeout

The default number of retries is set to 3 and the default timeout is set to 7. In case all retries fail then
the plugin would be finished after 28 seconds.

```(1 + 3) * 7 = 28```

## Inventory data
This plugin is able to return a (almost) complete inventory of the queried system.
Just add the command option ```--inventory``` or ```-i``` to get the inventory
in a JSON format.

**IMPORTANT**<br>
This is the first official version and might still change later on. If you encounter problems or have
suggestions for changes/improvements then please create a GitHub issue.


### Example of power supply inventory (```--power --inventory```)
```json
{
    "inventory": {
        "chassis": [],
        "fan": [],
        "firmware": [],
        "logical_drive": [],
        "manager": [],
        "memory": [],
        "network_adapter": [],
        "network_port": [],
        "physical_drive": [],
        "power_control": [
            {
                "chassis_ids": [
                    "1"
                ],
                "health_state": null,
                "health_status": null,
                "id": "1.0.1",
                "name": "Power Control",
                "power_allocated_watts": null,
                "power_available_watts": null,
                "power_capacity_watts": 1000,
                "power_consumed_watts": 209,
                "power_requested_watts": null
            }
        ],
        "power_supply": [
            {
                "bay": 1,
                "capacity_in_watt": 500,
                "chassis_ids": [
                    1
                ],
                "efficiency_percent": null,
                "firmware": "1.03",
                "health_status": "OK",
                "id": "0",
                "input_voltage": 224,
                "last_power_output": 110,
                "model": "XXXXXX-B21",
                "name": "HpeServerPowerSupply",
                "operation_status": "Enabled",
                "part_number": "XXXXXX-001",
                "serial": "XXXXXXX",
                "type": "AC",
                "vendor": "CHCNY"
            },
            {
                "bay": 2,
                "capacity_in_watt": 500,
                "chassis_ids": [
                    1
                ],
                "firmware": "1.03",
                "health_status": "OK",
                "id": "1",
                "input_voltage": 228,
                "last_power_output": 110,
                "model": "XXXXXX-B21",
                "name": "HpeServerPowerSupply",
                "operation_status": "Enabled",
                "part_number": "XXXXXX-001",
                "serial": "XXXXXXX",
                "type": "AC",
                "vendor": "CHCNY"
            }
        ],
        "processor": [],
        "storage_controller": [],
        "storage_enclosure": [],
        "system": [],
        "temperature": []
    },
    "meta": {
        "data_retrieval_issues": {},
        "duration_of_data_collection_in_seconds": 1.002901,
        "host_that_collected_inventory": "inventory-collector.example.com",
        "inventory_id": null,
        "inventory_name": null,
        "inventory_layout_version": "1.12.0",
        "script_version": "1.12.0",
        "start_of_data_collection": "2024-02-13T19:09:07+02:00"
    }
}
```

### Verbose output
In case you need more information or want to debug the data you can add the verbose
option. This will also add the `source_data` attribute for each inventory item.

### Inventory attributes
You can find a list of attributes for each item [here](cr_module/classes/inventory.py#L183)

### Inventory file
It is also possible to use the cli option `--inventory_file` to write the inventory data to a file.
This way it can be forwarded or used in an inventory import tool. Here you also might want to use
`--inventory_id` to get a fixed reference to an existing object.

## Known limitations
* On HPE iLO4 a maximum of 30 entries will be returned for the commands
**--mel** and **--sel**
* On almost all systems the nic status is reported unreliable
* For **--storage** components which report a Status.Health as **None**
will be treated as **OK** if Status.State is set to **Enabled**

## Supported Systems
This plugin is currently tested with following systems

### Hewlett Packard Enterprise
Almost all HPE server with iLO4 (>=2.50), iLO5 (>=1.40) or iLO6 should work

IMPORTANT:
* newer iLO5 firmware reports some storage components twice as the data is present in two locations

Models:
* ProLiant BL460c Gen8
* ProLiant BL460c Gen9
* ProLiant BL460c Gen10
* ProLiant DL325 Gen10
* ProLiant DL325 Gen11
* ProLiant DL360p Gen8
* ProLiant DL360 Gen9
* ProLiant DL360 Gen10
* ProLiant DL365 Gen10 Plus
* ProLiant DL380p Gen8
* ProLiant DL380 Gen9
* ProLiant DL380 Gen10
* ProLiant DL560 Gen10
* ProLiant DL580 Gen8
* ProLiant DL580 Gen9
* ProLiant RL300 Gen11
* ProLiant XL450 Gen10

* Compute Scale-up Server 3200
* Superdome Flex

### Lenovo
* ThinkSystem SR650 (BMC Version 2.12)
* ThinkSystem SR650 V2 (BMC Version 12I-1.15)
* ThinkAgile HX7520 Appliance (Lenovo XClarity Controller v5.4)
* ThinkAgile HX3720 Appliance (Lenovo XClarity Controller v4.2)

### Dell
* PowerEdge R630   (iDRAC 8 Version 2.70.70.70)
* PowerEdge R640   (iDrac 9 Version 4.22.00.00)
* PowerEdge R6525  (iDRAC 9 Version 5.10.50.00)
* PowerEdge R740   (iDRAC 9 Version 3.32.32.32)
* PowerEdge R740xd (iDRAC 9 Version 4.00.00.00)
* PowerEdge R7515  (iDRAC 9 Version 4.10.10.10)
* PowerEdge R840   (iDRAC 9 Version 4.22.00.00)
* PowerEdge R930   (iDRAC 8 Version 2.70.70.70)
* XC6420 Appliance (Firmware: 5.00.20.00 & BIOS 2.12.2)

### Huawei
* TaiShan 2280 V2 (iBMC Version 3.63)
* X8600 Blade     (iBMC Version 3.04)
* G560 V5

### Fujitsu
IMPORTANT:
* iRMC S5 Firmware 2.60 till 2.63 has a minor bug, avoid usage!
* make sure to use `--detailed` option for memory check. HealthRollup for Memory is not working/existent!
* iRMC S5 Firmware 3.06P reports storage data twice for some components
Models:
* PRIMERGY RX2530 M5 (iRMC Version 2.50P)
* PRIMERGY RX2540 M4 (iRMC Version 2.50P)
* PRIMERGY RX2540 M5 (iRMC Version 2.50P)
* PRIMERGY RX2540 M6 (iRMC Version 3.54P)

### Cisco
* Cisco C220M4SX (CIMC Version 4.1(2a))
* Cisco C220M5SX (CIMC Version 3.1(3a))
* Cisco C240M5SX (CIMC Version 3.1(3a))

### Inspur (limited support)
* Inspur NF5280 M5 (4.26.3)
* Inspur NF5280 M6 (4.12.04)

### SuperMicro (limited support)
* SuperServer 5028D-TN4T       (BMC Version 3.88)
* SuperServer E300-9D-8CN8TP   (BMC Version 01.73.12)
* SuperServer SSG-620P-E1CR24H (BMC Version 01.01.24)

### GIGABYTE (limited support)
* H262-Z61

### Bull
* BullSequana SH120

## License
>You can check out the full license [here](LICENSE.txt)

This project is licensed under the terms of the **MIT** license.
