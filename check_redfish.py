#!/usr/bin/env python36

self_description = \
"""This is a monitoring plugin to check components and
health status of systems which support Redfish.

R.I.P. IPMI
"""

# import build-in modules
import logging
import pickle
import os
import tempfile
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import pprint
import json
import datetime

# import 3rd party modules
import redfish

__version__ = "0.0.5"
__version_date__ = "2019-08-09"
__author__ = "Ricardo Bartels <ricardo.bartels@telekom.de>"
__description__ = "Check Redfish Plugin"
__license__ = "MIT"


# define valid return status types
status_types = {
    "OK" : 0,
    "WARNING": 1,
    "CRITICAL": 2,
    "UNKNOWN": 3
}

plugin = None

class RedfishConnection():

    sessionfilepath = None
    session_was_restored = False
    connection = None
    username = None
    password = None
    __cached_data = dict()
    vendor = None
    vendor_dict_key = None
    vendor_data = None
    cli_args = None

    # defaults
    conn_max_retries = 5
    conn_timeout = 5

    def __init__(self, cli_args = None):

        if cli_args is None:
            raise Exception("No args passed to RedfishConnection()")

        if cli_args.host is None:
            raise Exception("cli args host not set")

        self.cli_args = cli_args

        self.sessionfilepath = self.get_session_file_name()
        self.restore_session_from_file()

        self.init_connection()

    def exit_on_error(self, message, level = "UNKNOWN"):

        print("[%s]: %s" % (level,message))
        exit(status_types.get(level))

    def get_credentials(self):

        """
            Order of credential reading from highest to lowest priority
            1. cli_args username and apssword
            2. credentials from auth file
            3. credentials from environment
        """

        env_username_var = "CHECK_REDFISH_USERNAME"
        env_password_var = "CHECK_REDFISH_PASSWORD"

        # 1. if credentials are set via arguments then use them and return
        if self.cli_args.username is not None and self.cli_args.password is not None:
            self.username = self.cli_args.username
            self.password = self.cli_args.password
            return

        # 2. a authentication file is defined, lets try to parse it
        if self.cli_args.authfile is not None:

            try:
                with open(self.cli_args.authfile) as authfile:
                    for line in authfile:
                        name, var = line.partition("=")[::2]
                        if name.strip() == "username":
                            self.username = var.strip()
                        if name.strip() == "password":
                            self.password = var.strip()

            except FileNotFoundError:
                self.exit_on_error("Provided authentication file not found: %s" % self.cli_args.authfile)
            except PermissionError as e:
                self.exit_on_error("Error opening authentication file: %s" % self.cli_args.authfile)
            except Exception as e:
                self.exit_on_error("Unknown exception while trying to open authentication file %s: %s" % self.cli_args.authfile, str(e))

            if self.username is None or self.password is None:
                self.exit_on_error("Error parsing authentication file '%s'. Make sure username and password are set properly." % self.cli_args.authfile)

            return

        # 3. try to read credentials from environment
        self.username = os.getenv(env_username_var)
        self.password = os.getenv(env_password_var)

        return

    def get_session_file_name(self):

        default_session_file_prefix = "check_redfish_"
        default_session_file_suffix = ".session"
        sessionfiledir = None

        if self.cli_args.sessionfiledir:
            sessionfiledir = self.cli_args.sessionfiledir
        else:
            sessionfiledir = tempfile.gettempdir()

        # check if directory is a file
        if os.path.isfile(sessionfiledir):
            self.exit_on_error("The session file destination (%s) seems to be file." % sessionfiledir)

        # check if directory exists
        if not os.path.exists(sessionfiledir):
            # try to create directory
            try:
                os.makedirs(sessionfiledir, 0o700)
            except OSError:
                self.exit_on_error("Unable to create session file directory: %s." % sessionfiledir)
            except Exception as e:
                self.exit_on_error("Unknown exception while creating session file directory %s: %s" % sessionfiledir, str(e))

        # check if directory is writable
        if not os.access(sessionfiledir, os.X_OK | os.W_OK):
            self.exit_on_error("Error writing to session file directory: %s" % sessionfiledir)

        # get full path to session file
        if self.cli_args.sessionfile:
            sessionfilename = self.cli_args.sessionfile
        else:
            sessionfilename = default_session_file_prefix + self.cli_args.host

        sessionfilepath = os.path.normpath(sessionfiledir) + os.sep + sessionfilename + default_session_file_suffix

        if os.path.exists(sessionfilepath) and not os.access(sessionfilepath, os.R_OK):
            self.exit_on_error("Got no permission to read existing session file: %s" % sessionfilepath)

        if os.path.exists(sessionfilepath) and not os.access(sessionfilepath, os.W_OK):
            self.exit_on_error("Got no permission to write to existing session file: %s" % sessionfilepath)

        return sessionfilepath

    def restore_session_from_file(self):

        if self.sessionfilepath is None:
            raise Exception("sessionfilepath not set.")

        try:
            with open(self.sessionfilepath, 'rb') as pickled_session:
                self.connection = pickle.load(pickled_session)
        except (FileNotFoundError, EOFError):
            pass
        except PermissionError as e:
            self.exit_on_error("Error opening session file: %s" % str(e))
        except Exception as e:
            self.exit_on_error("Unknown exception while trying to open session file %s: %s" % (self.sessionfilepath, str(e)))

        # restore root attribute as RisObject
        # unfortunately we have to re implement the code from get_root_object function
        try:
            root_data = json.loads(self.connection.root_resp.text, "ISO-8859-1")
        except TypeError:
            root_data = json.loads(self.connection.root_resp.text)
        except AttributeError:
            root_data = None
        except ValueError as excp:
            raise

        if root_data is not None:
            self.connection.root = redfish.rest.v1.RisObject.parse(root_data)

        # set possible changed connection values
        if self.connection is not None:
            self.connection._max_retry = self.conn_max_retries
            self.connection._timeout = self.conn_timeout

        self.session_was_restored = True

        return

    def save_session_to_file(self):

        if self.sessionfilepath is None:
            raise Exception("sessionfilepath not set")

        if self.connection is None:
            raise Exception("session not initialized")

        # unset root attribute
        # root attribute is an RisObject which can't be pickled
        root_data = self.connection.root
        self.connection.root = None

        # fix for change in redfish 2.0.10
        # Socket objects can't be pickled. Remove socket object from pickle object and add it back later on
        connection_socket = self.connection._conn
        connection_socket_count = self.connection._conn_count
        self.connection._conn = None
        self.connection._conn_count = 0

        try:
            with open(self.sessionfilepath, 'wb') as pickled_session:
                pickle.dump(self.connection, pickled_session)
        except PermissionError as e:
            self.exit_on_error("Error opening session file to save session: %s" % str(e))
        except Exception as e:

            # log out from current connection
            self.connection.logout()

            # try to delete session file
            try:
                os.remove(self.sessionfilepath)
            except Exception:
                pass

            self.exit_on_error("Unknown exception while trying to save session to file %s: %s" % (self.sessionfilepath, str(e)))

        # set root attribute again
        self.connection.root = root_data

        # restore connection object
        self.connection._conn = connection_socket
        self.connection._conn_count = connection_socket_count

        return

    def init_connection(self, reset = False):

        # reset connection
        if reset is True:
            self.connection = None

        # if we have a connection object then just return
        if self.connection is not None:
            return

        self.get_credentials()

        if self.username is None or self.password is None:
            self.exit_on_error("Error: insufficient credentials provided")

        # initialize connection
        try:
            self.connection = redfish.redfish_client(base_url="https://%s" % self.cli_args.host, max_retry=self.conn_max_retries, timeout=self.conn_timeout)
        except redfish.rest.v1.ServerDownOrUnreachableError:
            self.exit_on_error("Host '%s' down or unreachable." % self.cli_args.host, "CRITICAL")
        except redfish.rest.v1.RetriesExhaustedError:
            self.exit_on_error("Unable to connect to Host '%s', max retries exhausted." % self.cli_args.host, "CRITICAL")
        except Exception as e:
            self.exit_on_error("Unable to connect to Host '%s': %s" % (self.cli_args.host, str(e)), "CRITICAL")

        if not self.connection:
            raise Exception("Unable to establish connection.")

        try:
            self.connection.login(username=self.username, password=self.password, auth="session")
        except redfish.rest.v1.RetriesExhaustedError:
            self.exit_on_error("Unable to connect to Host '%s', max retries exhausted." % self.cli_args.host, "CRITICAL")
        except redfish.rest.v1.InvalidCredentialsError:
            self.exit_on_error("Username or password invalid.", "CRITICAL")
        except Exception as e:
            self.exit_on_error("Unable to connect to Host '%s': %s" % (self.cli_args.host, str(e)), "CRITICAL")

        if self.connection is not None:
            self.save_session_to_file()

        return

    def _rf_get(self, redfish_path):

        try:
            return self.connection.get(redfish_path, None)
        except redfish.rest.v1.RetriesExhaustedError:
            self.exit_on_error("Unable to connect to Host '%s', max retries exhausted." % self.cli_args.host, "CRITICAL")

    def get(self, redfish_path):

        if self.__cached_data.get(redfish_path) is None:

            redfish_response = self._rf_get(redfish_path)

            # session invalid
            if redfish_response.status >= 400 and self.session_was_restored is True:

                # reset connection
                self.init_connection(reset = True)

                # query again
                redfish_response = self._rf_get(redfish_path)

            if args.verbose:
                pprint.pprint(redfish_response.dict)

            if redfish_response.dict.get("error"):
                error = redfish_response.dict.get("error").get("@Message.ExtendedInfo")
                self.exit_on_error("get error '%s' for API path '%s'" % (error[0].get("MessageId"), error[0].get("MessageArgs")))

            self.__cached_data[redfish_path] = redfish_response.dict

        return  self.__cached_data.get(redfish_path)

    def _rf_post(self, redfish_path, body):

        try:
            return self.connection.post(redfish_path, body=body)
        except redfish.rest.v1.RetriesExhaustedError:
            self.exit_on_error("Unable to connect to Host '%s', max retries exhausted." % self.cli_args.host, "CRITICAL")

    def get_view(self, redfish_path = None):

        if self.vendor_data is not None and \
           self.vendor_data.view_select is not None and \
           self.vendor_data.view_sopported:

            if self.vendor_data.view_response:
                return self.vendor_data.view_response

            redfish_response = self._rf_post("/redfish/v1/Views/", self.vendor_data.view_select)

            # session invalid
            if redfish_response.status >= 400 and self.session_was_restored is True:

                # reset connection
                self.init_connection(reset = True)

                # query again
                redfish_response = self._rf_post("/redfish/v1/Views/", self.vendor_data.view_select)

            if args.verbose:
                pprint.pprint(redfish_response.dict)

            if redfish_response.dict.get("error"):
                error = redfish_response.dict.get("error").get("@Message.ExtendedInfo")
                self.exit_on_error("get error '%s' for API path '%s'" % (error[0].get("MessageId"), error[0].get("MessageArgs")))

            self.vendor_data.view_response = redfish_response.dict

            return  self.vendor_data.view_response

        if redfish_path is not None:
            return self.get(redfish_path)

        return None

class PluginData():

    rf = None

    __perf_data = list()
    __output_data = dict()
    __log_output_data = list()
    __return_status = "OK"

    def __init__(self, cli_args = None):

        for state in status_types.keys():
            self.__output_data[state] = list()

        if cli_args is None:
            raise Exception("No args passed to RedfishConnection()")

        self.rf = RedfishConnection(cli_args)

    def set_status(self, state):

        if self.__return_status == state:
            return

        if state not in list(status_types.keys()):
            raise Exception("Status '%s' is invalid" % state)

        if status_types[state] > status_types[self.__return_status]:
            self.__return_status = state

    def add_output_data(self, state = None, text = None):

        if state is None:
            raise Exception("state not set")

        if text is None:
            raise Exception("text not set")

        self.set_status(state)

        self.__output_data[state].append(text)

    def add_log_output_data(self, state = None, text = None):

        if state is None:
            raise Exception("state not set")

        if text is None:
            raise Exception("text not set")

        self.set_status(state)

        self.__log_output_data.append("[%s]: %s" % (state, text))

    def add_perf_data(self, name, value, perf_uom = None, warning = None, critical = None):

        if name is None:
            raise Exception("option name for perf data not set")

        if value is None:
            raise Exception("option name for perf data not set")

        perf_string = "'%s'=%s" % (name.replace(" ", "_"), value)

        if perf_uom:
            perf_string += perf_uom

        if critical is not None and warning is None:
            warning = -1

        if warning is not None:
            perf_string += ",%s" % str(warning)

        if critical is not None:
            perf_string += ",%s" % str(critical)

        self.__perf_data.append(perf_string)

    def return_output_data(self):

        return_text = list()
        for key, value in sorted(status_types.items(), key=lambda item: item[1], reverse=True):
            for data_output in self.__output_data[key]:
                return_text.append("[%s]: %s" % (key, data_output))

        # add data from log commands
        return_text.extend(self.__log_output_data)

        return_string = "\n".join(return_text)

        # append perfdata if there is any
        if len(self.__perf_data) > 0:
            return_string += "|" + " ".join(self.__perf_data)

        return return_string

    def get_return_status(self, level = False):

        if level is True:
            return status_types[self.__return_status]

        return self.__return_status

    def do_exit(self):

        print(self.return_output_data())

        exit(self.get_return_status(True))

class VendorHPEData():

    ilo_hostname = None
    ilo_version = None
    ilo_firmware_version = None
    ilo_health = None

    resource_directory = None

    """
        Select and store view (supported from ILO 5)
    """
    view_sopported = False
    view_select = {
        "Select": [
            {
                "From": "/Systems/1/Memory/?$expand=.",
                "Properties": [ "Members AS Memory"]
            },
            {
                "From": "/Systems/1/Processors/?$expand=.",
                "Properties": [ "Members AS Processors"]
            },
            {
                "From": "/Systems/1/EthernetInterfaces/?$expand=.",
                "Properties": [ "Members AS EthernetInterfaces"]
            },
            {
                "From": "/Chassis/1/Power/?$expand=.",
                "Properties" : ["PowerSupplies", "Redundancy AS PowerRedundancy"]
            },
            {
                "From": "/Chassis/1/Thermal/",
                "Properties" : ["Temperatures", "Fans" ]
            }
        ]
    }

    view_response = None

def parse_command_line():
    """parse command line arguments
    Also add current version and version date to description
    """

    # define command line options
    parser = ArgumentParser(
        description=self_description + "\nVersion: " + __version__ + " (" + __version_date__ + ")",
        formatter_class=RawDescriptionHelpFormatter, add_help=False)

    group = parser.add_argument_group(title="mandatory arguments")
    group.add_argument("-H", "--host",
                        help="define the host to request" )

    group = parser.add_argument_group(title="authentication arguments")
    group.add_argument("-u", "--username", help="the login user name")
    group.add_argument("-p", "--password", help="the login password")
    group.add_argument("-f", "--authfile", help="authentication file with user name and password")
    group.add_argument("--sessionfile", help="define name of session file")
    group.add_argument("--sessionfiledir", help="define directory where the plugin saves session files")

    group = parser.add_argument_group(title="optional arguments")
    group.add_argument("-h", "--help", action='store_true',
                        help="show this help message and exit")
    group.add_argument("-w", "--warning", default=-1,
                        help="set warning value")
    group.add_argument("-c", "--critical", default=-1,
                        help="set critical value")
    group.add_argument("-v", "--verbose",  action='store_true',
                        help="this will add all requests and responses to output")
    group.add_argument("-d", "--detailed",  action='store_true',
                        help="always print detailed result")
    group.add_argument("-m", "--max",  type=int,
                        help="set maximum of returned items for --sel or --mel")

    # require at least one argument
    group = parser.add_argument_group(title="query status/health informations (at least one is required)")
    group.add_argument("--storage", dest="requested_query", action='append_const', const="storage",
                        help="request storage health")
    group.add_argument("--proc", dest="requested_query", action='append_const', const="proc",
                        help="request processor health")
    group.add_argument("--memory", dest="requested_query", action='append_const', const="memory",
                        help="request memory health")
    group.add_argument("--power", dest="requested_query", action='append_const', const="power",
                        help="request power supply health")
    group.add_argument("--temp", dest="requested_query", action='append_const', const="temp",
                        help="request temperature sensors status")
    group.add_argument("--fan", dest="requested_query", action='append_const', const="fan",
                        help="request fan status")
    group.add_argument("--nic", dest="requested_query", action='append_const', const="nic",
                        help="request network interface status")
    group.add_argument("--info", dest="requested_query", action='append_const', const="info",
                        help="request system informations")
    group.add_argument("--firmware", dest="requested_query", action='append_const', const="firmware",
                        help="request firmware informations")
    group.add_argument("--sel", dest="requested_query", action='append_const', const="sel",
                        help="request System Log status")
    group.add_argument("--mel", dest="requested_query", action='append_const', const="mel",
                        help="request Management Processor Log status")

    result = parser.parse_args()

    if result.help:
        parser.print_help()
        print("")
        exit(0)

    if result.requested_query is None:
        parser.error("You need to specify at least one query command.")

    # need to check this ourself otherwise it's not
    # possible to put the help command into a arguments group
    if result.host is None:
        parser.error("no remote host defined")

    return result

def MiB_to_GB(value):
    return int(value) * 1024 ** 2 / 1000 ** 3

def get_power(chassi = 1):

    global plugin

    redfish_url = "/redfish/v1/Chassis/%d/Power" % chassi

    power_supplies = plugin.rf.get_view(redfish_url).get("PowerSupplies")

    health_issue = False
    ps_num = 0
    if power_supplies:
        for ps in power_supplies:

            ps_num += 1
            # generic data
            last_power = ps.get("LastPowerOutputWatts")
            health = ps.get("Status").get("Health").upper()
            model = ps.get("Model").strip()
            last_power_output = ps.get("LastPowerOutputWatts")
            ps_bay = None
            ps_hp_status = None

            oem_data = ps.get("Oem")

            if oem_data is not None:

                if plugin.rf.vendor == "HPE":
                    ps_bay = oem_data.get(plugin.rf.vendor_dict_key).get("BayNumber")
                    ps_hp_status = oem_data.get(plugin.rf.vendor_dict_key).get("PowerSupplyStatus").get("State")

            if ps_bay is None:
                ps_bay = ps_num

            # align check output with temp and fan command
            if ps_hp_status is not None and ps_hp_status == "Unknown":
                health = "CRITICAL"

            status_text = "Power supply %s (%s) status is: %s" % (str(ps_bay), model, ps_hp_status or health)

            if health != "OK":
                if health == "WARNING":
                    plugin.add_output_data("WARNING", status_text)
                else:
                    plugin.add_output_data("CRITICAL", status_text)
                health_issue = True
            else:
                if args.detailed:
                    plugin.add_output_data("OK", status_text)

            if last_power_output is not None and ps_bay is not None:
                plugin.add_perf_data("ps_%s" % str(ps_bay), int(last_power_output))

        if args.detailed is False and health_issue == False:
            plugin.add_output_data("OK", "All power supplies (%d) are in good condition" % ps_num)

    else:
        plugin.add_output_data("UNKNOWN", "No power supply data returned for API URL '%s'" % redfish_url)

    # get PowerRedundancy status
    power_redundancies = plugin.rf.get_view(redfish_url).get("PowerRedundancy")

    if power_redundancies:
        for power_redundancy in power_redundancies:

            status = power_redundancy.get("Status")

            if status is not None:
                health = status.get("Health")
                state = status.get("State")

                if health is not None:
                    health = health.upper()

                    status_text = "Power redundancy status is: %s" % state

                    if health in [ "OK", "WARNING" ]:
                        plugin.add_output_data(health, status_text)
                    else:
                        plugin.add_output_data("CRITICAL", status_text)
    return

def get_temp(chassi = 1):

    global plugin

    redfish_url = "/redfish/v1/Chassis/%s/Thermal" % chassi

    thermal_data = plugin.rf.get_view(redfish_url)

    health_issue = False
    temp_num = 0
    if "Temperatures" in thermal_data:

        for temp in thermal_data.get("Temperatures"):

            state = temp.get("Status").get("State")

            if state == "Absent":
                continue

            if state == "Offline":
                health = state
            else:
                health = temp.get("Status").get("Health").upper()

            name = temp.get("Name").strip()
            current_temp = temp.get("ReadingCelsius")
            critical_temp = temp.get("UpperThresholdCritical")

            temp_num += 1

            if critical_temp is None or str(critical_temp) == "0":
                critical_temp = "N/A"

            status_text = "Temp sensor %s status is: %s (%s °C) (max: %s °C)" % (name, health, str(current_temp), str(critical_temp))

            if health != "OK":
                if health == "WARNING":
                    plugin.add_output_data("WARNING", status_text)
                else:
                    plugin.add_output_data("CRITICAL", status_text)
                health_issue = True
            else:
                if args.detailed:
                    plugin.add_output_data("OK", status_text)

            critical_temp = critical_temp if critical_temp != 0 else None

            plugin.add_perf_data("Temp_%s" % str(name), int(current_temp), critical=critical_temp)

        if args.detailed is False and health_issue == False:
            plugin.add_output_data("OK", "All temp sensors (%d) are in good condition" % temp_num)

    else:
        plugin.add_output_data("UNKNOWN", "No thermal data returned for API URL '%s'" % redfish_url)

    return

def get_fan(chassi = 1):

    global plugin

    redfish_url = "/redfish/v1/Chassis/%s/Thermal" % chassi

    thermal_data = plugin.rf.get_view(redfish_url)

    health_issue = False
    fan_num = 0
    if "Fans" in thermal_data:
        for fan in thermal_data.get("Fans"):

            fan_num += 1

            state = fan.get("Status").get("State")
            if state == "Absent":
                continue

            if state == "Offline":
                health = state
            else:
                health = fan.get("Status").get("Health").upper()

            name = fan.get("FanName") or fan.get("Name")

            speed = fan.get("Reading")
            speed_units = fan.get("ReadingUnits")

            if speed_units:
                speed_units = speed_units.replace("Percent", "%")
            else:
                speed_units = ""

            speed_status = ""
            if speed:
                speed_status = " (%s%s)" % (str(speed), str(speed_units))

            status_text = "Fan '%s'%s status is: %s" % (name, speed_status, health)

            if health != "OK":
                if health == "WARNING":
                    plugin.add_output_data("WARNING", status_text)
                else:
                    plugin.add_output_data("CRITICAL", status_text)
                health_issue = True
            else:
                if args.detailed:
                    plugin.add_output_data("OK", status_text)

            if speed:
                plugin.add_perf_data("Fan_%s" % str(name), int(speed), perf_uom=speed_units, warning=args.warning, critical=args.critical)

        if args.detailed is False and health_issue == False:
            plugin.add_output_data("OK", "All fans (%d) are in good condition" % fan_num)

    else:
        plugin.add_output_data("UNKNOWN", "No thermal data returned for API URL '%s'" % redfish_url)

    return plugin

def get_procs(system = 1):

    global plugin

    redfish_url = "/redfish/v1/Systems/%s/" % system

    systems_response = plugin.rf.get(redfish_url)

    if systems_response.get("ProcessorSummary"):

        health = systems_response.get("ProcessorSummary").get("Status").get("HealthRollup")

        if health == "OK" and args.detailed == False:
            plugin.add_output_data("OK", "All processors (%d) are in good condition" % systems_response.get("ProcessorSummary").get("Count"))
            return

    # if "HealthRollup" is not "OK" or we want detailed informations we have to dig deeper
    redfish_url =  "/redfish/v1/Systems/%s/Processors" % system

    processors_response = plugin.rf.get_view(redfish_url)

    if processors_response.get("Members") or processors_response.get("Processors"):

        for proc in processors_response.get("Members") or processors_response.get("Processors"):

            if proc.get("@odata.context"):
                proc_response = proc
            else:
                proc_response = plugin.rf.get(proc.get("@odata.id"))

            if proc_response.get("Id"):
                socket = proc_response.get("Socket")
                status = proc_response.get("Status")
                model =  proc_response.get("Model").strip()

                if status.get("State") and status.get("State") == "Absent":
                    continue

                health = status.get("Health").upper()

                status_text = "Processor %s (%s) status is: %s" % (socket, model, health)

                if health in [ "OK", "WARNING" ]:
                    plugin.add_output_data(health, status_text)
                else:
                    plugin.add_output_data("CRITICAL", status_text)
            else:
                plugin.add_output_data("UNKNOWN", "No processor data returned for API URL '%s'" % proc_response.get("@odata.id"))
    else:
        plugin.add_output_data("UNKNOWN", "No processor data returned for API URL '%s'" % redfish_url)

    return

def get_mem(system = 1):

    global plugin

    redfish_url = "/redfish/v1/Systems/%s/" % system

    systems_response = plugin.rf.get(redfish_url)

    if systems_response.get("MemorySummary"):

        health = None

        try:
            health = systems_response.get("MemorySummary").get("Status").get("HealthRollup")
        except AttributeError:
            args.detailed == True

        if health == "OK" and args.detailed == False:
            plugin.add_output_data("OK", "All memory modules (Total %dGB) are in good condition" % systems_response.get("MemorySummary").get("TotalSystemMemoryGiB"))
            return

    # if "HealthRollup" is not "OK" or we want detailed informations we have to dig deeper
    redfish_url = "/redfish/v1/Systems/%s/Memory/" % system

    memory_response = plugin.rf.get_view(redfish_url)

    if memory_response.get("Members") or memory_response.get("Memory"):

        for mem_module in memory_response.get("Members") or memory_response.get("Memory"):

            if mem_module.get("@odata.context"):
                mem_module_response = mem_module
            else:
                mem_module_response = plugin.rf.get(mem_module.get("@odata.id"))

            if mem_module_response.get("Id"):

                # ILO 4
                if mem_module_response.get("DIMMStatus"):

                    health = mem_module_response.get("DIMMStatus")
                    size = mem_module_response.get("SizeMB") / 1024
                    name = mem_module_response.get("SocketLocator")

                elif mem_module_response.get("Status"):

                    status = mem_module_response.get("Status")

                    if status.get("State") and status.get("State") == "Absent":
                        continue

                    if plugin.rf.vendor == "HPE" and mem_module_response.get("Oem").get(plugin.rf.vendor_dict_key).get("DIMMStatus"):
                        health = mem_module_response.get("Oem").get(plugin.rf.vendor_dict_key).get("DIMMStatus")
                    else:
                        health = status.get("Health")
                    size = mem_module_response.get("CapacityMiB") / 1024
                    name = mem_module_response.get("DeviceLocator")

                else:
                    plugin.add_output_data("UNKNOWN", "Error retrieving memory module status: %s" % mem_module_response)
                    continue

                status_text = "Memory module %s (%dGB) status is: %s" % (name, size, health)

                if health not in [ "GoodInUse", "OK" ]:
                    if health == "WARNING":
                        plugin.add_output_data("WARNING", status_text)
                    else:
                        plugin.add_output_data("CRITICAL", status_text)
                else:
                    plugin.add_output_data("OK", status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No memory data returned for API URL '%s'" % mem_module.get("@odata.id"))
    else:
        plugin.add_output_data("UNKNOWN", "No memory data returned for API URL '%s'" % redfish_url)

    return

def get_nics(system = 1):

    global plugin

    redfish_url = "/redfish/v1/Systems/%d/EthernetInterfaces/" % system

    nics_response = plugin.rf.get_view(redfish_url)
    data_members = nics_response.get("EthernetInterfaces") or nics_response.get("Members")

    health_issue = False
    nic_num = 0
    if data_members:

        for nic in data_members:

            if nic.get("@odata.context"):
                nic_response = nic
            else:
                nic_response = plugin.rf.get(nic.get("@odata.id"))

            if nic_response.get("Id"):

                nic_num += 1

                link_status = None
                id = nic_response.get("Id")

                if nic_response.get("Status"):

                    health = nic_response.get("Status").get("Health")
                    link_status = nic_response.get("LinkStatus")

                else:
                    health = "Undefined"

                if health is None:
                    health = "Undefined"

                if link_status:
                    status_text = "NIC %s status is '%s' and link status is '%s'" % (id, health, link_status)
                else:
                    status_text = "NIC %s status is: %s" % (id, health)

                if health not in ["OK", "Undefined"]:
                    if health == "WARNING":
                        plugin.add_output_data("WARNING", status_text)
                    else:
                        plugin.add_output_data("CRITICAL", status_text)
                    health_issue = True
                else:
                    if args.detailed:
                        plugin.add_output_data("OK", status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No network interface data returned for API URL '%s'" % nic.get("@odata.id"))

        if args.detailed is False and health_issue == False:
            plugin.add_output_data("OK", "All network interfaces (%d) are in good condition" % nic_num)

    else:
        plugin.add_output_data("UNKNOWN", "No network interface data returned for API URL '%s'" % redfish_url)

    return

def get_storage(system = 1):

    global plugin

    if plugin.rf.vendor == "HPE":
        get_storage_hpe(system)

    if not plugin.rf.vendor:
        plugin.add_output_data("UNKNOWN", "'storage' command is currently not supported for this system.")

    return

def get_storage_hpe(system = 1):

    def get_disks(link, type = "DiskDrives"):

        disks_response = plugin.rf.get("%s/%s/?$expand=." % (link,type))

        if disks_response.get("Members") is None:
            if type == "DiskDrives":
                plugin.add_output_data("OK", "no %s found for this ArrayController" % type)
            return

        for disk in disks_response.get("Members"):

            if disk.get("@odata.context"):
                disk_response = disk
            else:
                disk_response = plugin.rf.get(disk.get("@odata.id"))

            health = disk_response.get("Status").get("Health").upper()
            location = disk_response.get("Location")
            size = disk_response.get("CapacityGB")

            status_text = "Physical Drive (%s) %sGB Status: %s" % (location, size, health)

            if health in [ "OK", "WARNING" ]:
                plugin.add_output_data(health, status_text)
            else:
                plugin.add_output_data("CRITICAL", status_text)

    def get_logical_drives(link):

        ld_response = plugin.rf.get("%s/LogicalDrives/?$expand=." % link)

        if ld_response.get("Members") is None:
            plugin.add_output_data("OK", "no logical drives found for this ArrayController")
            return

        for logical_drive in ld_response.get("Members"):

            if logical_drive.get("@odata.context"):
                logical_drive_response = logical_drive
            else:
                logical_drive_response = plugin.rf.get(logical_drive.get("@odata.id"))

            health = logical_drive_response.get("Status").get("Health").upper()
            id = logical_drive_response.get("LogicalDriveNumber")
            size = int(logical_drive_response.get("CapacityMiB")) * 1024 ** 2 / 1000 ** 3
            raid = logical_drive_response.get("Raid")

            status_text = "Logical Drive (%s) %.0fGB (RAID %s) Status: %s" % (id, size, raid, health)

            if health in [ "OK", "WARNING" ]:
                plugin.add_output_data(health, status_text)
            else:
                plugin.add_output_data("CRITICAL", status_text)

    def get_enclosures(link):

        enclosures_response = plugin.rf.get("%s/StorageEnclosures/?$expand=." % link)

        if enclosures_response.get("Members") is None:
            plugin.add_output_data("OK", "no storage enclosures found for this ArrayController")
            return

        for enclosure in enclosures_response.get("Members"):

            if enclosure.get("@odata.context"):
                enclosure_response = enclosure
            else:
                enclosure_response = plugin.rf.get(enclosure.get("@odata.id"))

            health = enclosure_response.get("Status").get("Health").upper()
            location = enclosure_response.get("Location")

            status_text = "StorageEnclosure (%s) Status: %s" % (location, health)

            if health in [ "OK", "WARNING" ]:
                plugin.add_output_data(health, status_text)
            else:
                plugin.add_output_data("CRITICAL", status_text)


    global plugin

    redfish_url = "/redfish/v1/Systems/%s/SmartStorage/" % system

    storage_response = plugin.rf.get(redfish_url)

    status = storage_response.get("Status").get("Health").upper()

    if status and status == "OK" and args.detailed == False:
        plugin.add_output_data("OK", "Status of HP SmartArray is: %s" % status)
        return

    # unhealthy
    redfish_url = "/redfish/v1/Systems/%s/SmartStorage/ArrayControllers/?$expand=." % system

    array_controllers_response = plugin.rf.get(redfish_url)

    if array_controllers_response.get("Members"):

        for array_controller in array_controllers_response.get("Members"):

            if array_controller.get("@odata.context"):
                controller_response = array_controller
            else:
                controller_response = plugin.rf.get(array_controller.get("@odata.id"))

            if controller_response.get("Id"):
                model = controller_response.get("Model")
                fw_version = controller_response.get("FirmwareVersion").get("Current").get("VersionString")
                status = controller_response.get("Status")

                if status.get("State") and status.get("State") == "Absent":
                    continue

                health = status.get("Health").upper()

                status_text = "%s (FW: %s) status is: %s" % (model, fw_version, health)

                if health in [ "OK", "WARNING" ]:
                    plugin.add_output_data(health, status_text)
                else:
                    plugin.add_output_data("CRITICAL", status_text)

                get_disks(array_controller.get("@odata.id"))
                get_logical_drives(array_controller.get("@odata.id"))
                get_enclosures(array_controller.get("@odata.id"))
                get_disks(array_controller.get("@odata.id"), "UnconfiguredDrives")
            else:
                plugin.add_output_data("UNKNOWN", "No array controller data returned for API URL '%s'" % array_controller.get("@odata.id"))

    else:
        plugin.add_output_data("UNKNOWN", "No array controller data returned for API URL '%s'" % redfish_url)

    return

def get_event_log(type, system_manager_id = 1):

    global plugin

    if type not in ["manager", "system"]:
        plugin.add_output_data("UNKNOWN", "Unknown event log type: %s", type)
        return

    if plugin.rf.vendor == "HPE":
        get_event_log_hpe(type, system_manager_id)
    else:
        plugin.add_output_data("UNKNOWN", "Command to check %s event log not implemented for this vendor" % type)

    return

def get_event_log_hpe(type, system_manager_id):

    global plugin

    limit_of_returned_itmes = args.max
    forced_limit = False
    data_now = datetime.datetime.now()

    if plugin.rf.vendor_data.ilo_version.lower() != "ilo 5":
        ilo4_limit = 30
        if args.max:
            limit_of_returned_itmes = min(args.max, ilo4_limit)
            if args.max > ilo4_limit:
                forced_limit = True
        else:
            forced_limit = True
            limit_of_returned_itmes = ilo4_limit

    if type == "system":
        redfish_url = "/redfish/v1/Systems/%s/LogServices/IML/Entries/?$expand=." % system_manager_id
    else:
        redfish_url = "/redfish/v1/Managers/%s/LogServices/IEL/Entries?$expand=." % system_manager_id

        if args.warning:
            date_warning = data_now - datetime.timedelta(days=int(args.warning))
        if args.critical:
            date_critical = data_now - datetime.timedelta(days=int(args.critical))

    event_data = plugin.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin.add_output_data("OK", "No log entries found.")
        return

    # reverse list from newest to oldest entry
    event_entries = event_data.get("Members")
    event_entries.reverse()

    num_entry = 0
    for event_entry_itme in event_entries:

        if event_entry_itme.get("@odata.context"):
            event_entry = event_entry_itme
        else:
            event_entry = plugin.rf.get(event_entry_itme.get("@odata.id"))

        message = event_entry.get("Message")

        num_entry += 1

        severity = event_entry.get("Severity").upper()
        date = event_entry.get("Created")
        repaired = event_entry.get("Oem").get(plugin.rf.vendor_dict_key).get("Repaired")

        if repaired == None:
            repaired = False

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00Z"

        status = "OK"

        if type == "system":
            if severity == "WARNING" and repaired is False:
                status = "WARNING"
            elif severity != "OK" and repaired is False:
                status = "CRITICAL"
        else:
            entry_data = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")

            if args.critical:
                if entry_data > date_critical and severity != "OK":
                    status = "CRITICAL"
            if args.warning:
                if entry_data > date_warning and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_itmes is not None and num_entry >= limit_of_returned_itmes:
            if forced_limit:
                plugin.add_log_output_data("OK", "This is an %s, limited results to %d entries" %
                    (plugin.rf.vendor_data.ilo_version, limit_of_returned_itmes))
            return

    return

def get_system_info(system = 1):

    global plugin

    if plugin.rf.vendor == "HPE":
        get_system_info_hpe(system)

    if not plugin.rf.vendor:
        plugin.add_output_data("UNKNOWN", "'info' command is currently not supported for this system.")

    return

def get_system_info_hpe(system = 1):

    global plugin

    redfish_url = "/redfish/v1/Systems/%s/" % system

    system_response = plugin.rf.get(redfish_url)

    model = system_response.get("Model").strip()
    serial = system_response.get("SerialNumber").strip()
    system_health_state = system_response.get("Status").get("Health").upper()
    power_state = system_response.get("PowerState")
    bios_version = system_response.get("BiosVersion")
    host_name = system_response.get("HostName").strip()
    cpu_num = system_response.get("ProcessorSummary").get("Count")
    mem_size = system_response.get("MemorySummary").get("TotalSystemMemoryGiB")

    status = "OK"
    if system_health_state == "WARNING":
        status = "WARNING"
    elif system_health_state != "OK":
        status = "CRITICAL"

    if len(host_name) == 0:
        host_name = "NOT SET"

    plugin.add_output_data(status, f"Type: {model} (CPU: {cpu_num}, MEM: {mem_size}GB) - BIOS: {bios_version} - Serial: {serial} - Power: {power_state} - Name: {host_name}")
    plugin.add_output_data("OK", "%s - FW: %s" % (plugin.rf.vendor_data.ilo_version, plugin.rf.vendor_data.ilo_firmware_version))

def get_firmware_info(system = 1):

    global plugin

    if plugin.rf.vendor == "HPE":
        if plugin.rf.vendor_data.ilo_version.lower() == "ilo 5":
            get_firmware_info_hpe_ilo5()
        else:
            get_firmware_info_hpe_ilo4(system)

    if not plugin.rf.vendor:
        plugin.add_output_data("UNKNOWN", "'firmware' command is currently not supported for this system.")

    return

def get_firmware_info_hpe_ilo5():

    global plugin

    redfish_url = "/redfish/v1/UpdateService/FirmwareInventory/?$expand=."

    firmware_response = plugin.rf.get(redfish_url)

    for firmware_entry in firmware_response.get("Members"):

        component_name = firmware_entry.get("Name")
        component_version = firmware_entry.get("Version")
        component_context = firmware_entry.get("Oem").get(plugin.rf.vendor_dict_key).get("DeviceContext")

        plugin.add_output_data("OK", f"{component_name} ({component_context}): {component_version}")

    return

def get_firmware_info_hpe_ilo4(system = 1):

    global plugin


    redfish_url = "/redfish/v1/Systems/%s/FirmwareInventory/" % system

    firmware_response = plugin.rf.get(redfish_url)

    for key, firmware_entry in firmware_response.get("Current").items():

        for firmware_entry_object in firmware_entry:

            component_name = firmware_entry_object.get("Name")
            component_version = firmware_entry_object.get("VersionString")
            component_location = firmware_entry_object.get("Location")

            plugin.add_output_data("OK", f"{component_name} ({component_location}): {component_version}")

    return

def get_basic_system_info():

    global plugin


    basic_infos = plugin.rf.connection.root

    if basic_infos.get("Oem"):

        vendor_string = list(basic_infos.get("Oem"))[0]

        plugin.rf.vendor_dict_key = vendor_string

        if vendor_string in ["Hpe", "Hp"]:
            plugin.rf.vendor = "HPE"

            plugin.rf.vendor_data = VendorHPEData()

            manager_data = basic_infos.get("Oem").get(vendor_string).get("Manager")

            plugin.rf.vendor_data.ilo_hostname = manager_data[0].get("HostName")
            plugin.rf.vendor_data.ilo_version = manager_data[0].get("ManagerType")
            plugin.rf.vendor_data.ilo_firmware_version = manager_data[0].get("ManagerFirmwareVersion")

            if plugin.rf.vendor_data.ilo_version.lower() == "ilo 5":
                plugin.rf.vendor_data.view_sopported = True


            #resource_directory_response = get_cached_data(handle, "/redfish/v1/ResourceDirectory/")

            # try to shortcut a bit
            """
            resource_list = list()
            for resource_instance in resource_directory_response.get("Instances"):
                resource_list.append(resource_instance.get("@odata.id"))

            pprint.pprint(resource_list)

            r = re.compile(".*\/Systems\/\d\/Processors\/\d\/$")
            pprint.pprint(list(filter(r.match, resource_list)))

            r = re.compile(".*\/DiskDrives\/\d\/$")
            pprint.pprint(list(filter(r.match, resource_list)))

            r = re.compile(".*\/LogicalDrives\/\d\/$")
            pprint.pprint(list(filter(r.match, resource_list)))

            r = re.compile(".*\/StorageEnclosures\/\d\/$")
            pprint.pprint(list(filter(r.match, resource_list)))

            r = re.compile(".*\/EthernetInterfaces\/\d\/$")
            pprint.pprint(list(filter(r.match, resource_list)))
            #response.vendor_data.resource_directory =
            """

    return

if __name__ == "__main__":
    # start here
    args = parse_command_line()

    if args.verbose:
        # initialize logger
        logging.basicConfig(level="DEBUG", format='%(asctime)s - %(levelname)s: %(message)s')

    # initialize plugin object
    plugin = PluginData(args)

    # get basic informations
    get_basic_system_info()

    if plugin.rf.vendor is None:

        if plugin.rf.vendor_dict_key:
            plugin.add_output_data("UNKNOWN", "Support for vendor '%s' is currently not implemented." % plugin.rf.vendor_dict_key)
        else:
            plugin.add_output_data("UNKNOWN", "Unable to determine systems vendor.")

        plugin.do_exit()

    if "power"      in args.requested_query: get_power()
    if "temp"       in args.requested_query: get_temp()
    if "fan"        in args.requested_query: get_fan()
    if "proc"       in args.requested_query: get_procs()
    if "memory"     in args.requested_query: get_mem()
    if "nic"        in args.requested_query: get_nics()
    if "storage"    in args.requested_query: get_storage()
    if "info"       in args.requested_query: get_system_info()
    if "firmware"   in args.requested_query: get_firmware_info()
    if "mel"        in args.requested_query: get_event_log("manager")
    if "sel"        in args.requested_query: get_event_log("system")

    plugin.do_exit()

# EOF
