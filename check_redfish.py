#!/usr/bin/env python3.6

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

__version__ = "0.0.10"
__version_date__ = "2020-01-21"
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

# defaults
default_conn_max_retries = 3
default_conn_timeout = 7

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
            1. cli_args username and password
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
            self.connection._max_retry = self.cli_args.retries
            self.connection._timeout = self.cli_args.timeout

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
            self.connection = redfish.redfish_client(base_url="https://%s" % self.cli_args.host, max_retry=self.cli_args.retries, timeout=self.cli_args.timeout)
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
            self.connection.system_properties = None
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
                self.exit_on_error("got error '%s' for API path '%s'" % (error[0].get("MessageId"), error[0].get("MessageArgs")))

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
           self.vendor_data.view_supported:

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

            return self.vendor_data.view_response

        if redfish_path is not None:
            return self.get(redfish_path)

        return None

class PluginData():

    rf = None

    __perf_data = list()
    __output_data = dict()
    __log_output_data = dict()
    __return_status = "OK"
    __current_command = "global"

    def __init__(self, cli_args = None):

        if cli_args is None:
            raise Exception("No args passed to RedfishConnection()")

        self.rf = RedfishConnection(cli_args)

    def set_current_command(self, current_command = None):

        if current_command is None:
            raise Exception("current_command not set")

        self.__current_command = current_command

    def set_status(self, state):

        if self.__return_status == state:
            return

        if state not in list(status_types.keys()):
            raise Exception(f"Status '{state}' is invalid")

        if status_types[state] > status_types[self.__return_status]:
            self.__return_status = state

    def add_output_data(self, state = None, text = None, summary = False):

        if state is None:
            raise Exception("state not set")

        if text is None:
            raise Exception("text not set")

        self.set_status(state)

        if self.__output_data.get(self.__current_command) is None:
            self.__output_data[self.__current_command] = dict()
            self.__output_data[self.__current_command]["issues_found"] = False

        if summary is True:
            self.__output_data[self.__current_command]["summary"] = text
            self.__output_data[self.__current_command]["summary_state"] = state
        else:
            if self.__output_data[self.__current_command].get(state) is None:
                self.__output_data[self.__current_command][state] = list()

            if state != "OK":
                self.__output_data[self.__current_command]["issues_found"] = True

            self.__output_data[self.__current_command][state].append(text)

    def add_log_output_data(self, state = None, text = None):

        if state is None:
            raise Exception("state not set")

        if text is None:
            raise Exception("text not set")

        self.set_status(state)

        if self.__log_output_data.get(self.__current_command) is None:
            self.__log_output_data[self.__current_command] = list()

        self.__log_output_data[self.__current_command].append(
            { "status": state,
              "text": "[%s]: %s" % (state, text)
            }
        )

    def add_perf_data(self, name, value, perf_uom = None, warning = None, critical = None):

        if name is None:
            raise Exception("option name for perf data not set")

        if value is None:
            raise Exception("option name for perf data not set")

        perf_string = "'%s'=%s" % (name.replace(" ", "_"), value)

        if perf_uom:
            perf_string += perf_uom

        if critical is not None and warning is None:
            warning = ""

        if warning is not None:
            perf_string += ";%s" % str(warning)

        if critical is not None:
            perf_string += ";%s" % str(critical)

        self.__perf_data.append(perf_string)

    def return_output_data(self):

        return_text = list()

        for command, _ in self.__output_data.items():

            if self.__output_data[command].get("issues_found") == False and args.detailed == False:
                return_text.append("[%s]: %s" % (self.__output_data[command].get("summary_state"), self.__output_data[command].get("summary")))
            else:
                for status_type_name, _ in sorted(status_types.items(), key=lambda item: item[1], reverse=True):

                    if self.__output_data[command].get(status_type_name) is None:
                        continue

                    for data_output in self.__output_data[command].get(status_type_name):
                        if status_type_name != "OK" or args.detailed == True:
                            return_text.append("[%s]: %s" % (status_type_name, data_output))

        # add data from log commands
        for command, log_entries in self.__log_output_data.items():

            command_status = "OK"
            most_recent = dict()
            log_entry_counter = dict()

            for log_entry in log_entries:

                if args.detailed == True:
                    return_text.append(log_entry.get("text"))
                else:

                    if status_types[log_entry.get("status")] > status_types[command_status]:
                        command_status = log_entry.get("status")

                    if log_entry_counter.get(log_entry.get("status")):
                        log_entry_counter[log_entry.get("status")] += 1
                    else:
                        log_entry_counter[log_entry.get("status")] = 1

                    if most_recent.get(log_entry.get("status")) is None:
                        most_recent[log_entry.get("status")] = log_entry.get("text")

            if args.detailed == False:

                message_summary = " and ".join([ "%d %s" % (value, key) for key,value in log_entry_counter.items() ])

                return_text.append(f"[{command_status}]: Found {message_summary} {command} entries. Most recent notable: %s" % most_recent.get(command_status))

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

    expand_string = "?$expand=."

    resource_directory = None

    """
        Select and store view (supported from ILO 5)

        ATTENTION: This will only work as long as we are querying servers
        with "1" System, "1" Chassi and "1" Manager

        OK for now but will be changed once we have to query blade centers
    """
    view_supported = False
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
                "Properties": ["PowerSupplies", "Redundancy AS PowerRedundancy"]
            },
            {
                "From": "/Chassis/1/Thermal/",
                "Properties": ["Temperatures", "Fans" ]
            },
            {
                "From": "/Managers/?$expand=.",
                "Properties": [ "Members as ILO" ]
            },
            {
                "From": "/Managers/1/EthernetInterfaces/?$expand=.",
                "Properties": [ "Members as ILOInterfaces" ]
            }
        ]
    }

    view_response = None

class VendorLenovoData():

    view_supported = False
    view_select = None

    expand_string = "?$expand=*"

class VendorDellData():

    view_supported = False
    view_select = None

    expand_string = "?$expand=*($levels=1)"

class VendorHuaweiData():

    view_supported = False
    view_select = None

    # currently $expand is not supported
    expand_string = ""

class VendorFujitsuData():

    view_supported = False
    view_select = None

    expand_string = "?$expand=Members"

class VendorGeneric():

    view_supported = False
    view_select = None

    expand_string = ""

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
                        help="define the host to request. To change the port just add ':portnumber' to this parameter." )

    group = parser.add_argument_group(title="authentication arguments")
    group.add_argument("-u", "--username", help="the login user name")
    group.add_argument("-p", "--password", help="the login password")
    group.add_argument("-f", "--authfile", help="authentication file with user name and password")
    group.add_argument("--sessionfile", help="define name of session file")
    group.add_argument("--sessionfiledir", help="define directory where the plugin saves session files")

    group = parser.add_argument_group(title="optional arguments")
    group.add_argument("-h", "--help", action='store_true',
                        help="show this help message and exit")
    group.add_argument("-w", "--warning", default="",
                        help="set warning value")
    group.add_argument("-c", "--critical", default="",
                        help="set critical value")
    group.add_argument("-v", "--verbose",  action='store_true',
                        help="this will add all requests and responses to output")
    group.add_argument("-d", "--detailed",  action='store_true',
                        help="always print detailed result")
    group.add_argument("-m", "--max",  type=int,
                        help="set maximum of returned items for --sel or --mel")
    group.add_argument("-r", "--retries",  type=int, default=default_conn_max_retries,
                        help="set number of maximum retries (default: %d)" % default_conn_max_retries)
    group.add_argument("-t", "--timeout",  type=int, default=default_conn_timeout,
                        help="set number of request timeout per try/retry (default: %d)" % default_conn_timeout)

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
    group.add_argument("--bmc", dest="requested_query", action='append_const', const="bmc",
                        help="request bmc infos and status")
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

def get_chassi_data(data_type = None):

    global plugin

    if data_type is None or data_type not in [ "power", "temp", "fan" ]:
        raise Exception("Unknown data_type not set for get_chassi_data(): %s", type)

    if plugin.rf.connection.system_properties is None:
        discover_system_properties()

    chassis = plugin.rf.connection.system_properties.get("chassis")

    if chassis is None or len(chassis) == 0:
        plugin.add_output_data("UNKNOWN", "No 'chassis' property found in root path '/redfish/v1'")
        return

    for chassi in chassis:
        if data_type == "power":
            get_single_chassi_power(chassi)
        if data_type == "temp":
            get_single_chassi_temp(chassi)
        if data_type == "fan":
            get_single_chassi_fan(chassi)

    return

def get_single_chassi_power(redfish_url):

    global plugin

    plugin.set_current_command("Power")

    redfish_url = f"{redfish_url}/Power"

    power_supplies = plugin.rf.get_view(redfish_url).get("PowerSupplies")

    default_text = ""
    ps_num = 0
    ps_absent = 0
    if power_supplies:
        for ps in power_supplies:

            ps_num += 1

            status = ps.get("Status").get("Health").upper() # HP, Lenovo
            ps_op_status = ps.get("Status").get("State") # HP, Lenovo
            model = ps.get("Model") # HP
            part_number = ps.get("PartNumber") # Lenovo
            last_power_output = ps.get("LastPowerOutputWatts") # HP, Lenovo
            ps_bay = None
            ps_hp_status = None

            oem_data = ps.get("Oem")

            if oem_data is not None:

                if plugin.rf.vendor == "HPE":
                    ps_bay = oem_data.get(plugin.rf.vendor_dict_key).get("BayNumber")
                    if oem_data.get(plugin.rf.vendor_dict_key).get("PowerSupplyStatus") is not None:
                        ps_hp_status = oem_data.get(plugin.rf.vendor_dict_key).get("PowerSupplyStatus").get("State")

                elif plugin.rf.vendor == "Lenovo":
                    ps_bay = oem_data.get(plugin.rf.vendor_dict_key).get("Location").get("Info")

                elif plugin.rf.vendor == "Huawei":
                    last_power_output = oem_data.get(plugin.rf.vendor_dict_key).get("PowerInputWatts")

            if ps_bay is None:
                ps_bay = ps_num

            if model is None:
                model = part_number

            if model is None:
                model = "Unknown model"

            # align check output with temp and fan command
            if ps_hp_status is not None and ps_hp_status == "Unknown":
                status = "CRITICAL"

            if ps_op_status is not None and ps_op_status == "Absent":
                status_text = "Power supply %s status is: %s" % (str(ps_bay), ps_op_status)
                status = "OK"
                ps_absent += 1
            else:
                status_text = "Power supply %s (%s) status is: %s" % (str(ps_bay), model.strip(), ps_hp_status or status)

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            if last_power_output is not None and ps_bay is not None:
                plugin.add_perf_data(f"ps_{ps_bay}", int(last_power_output))

        default_text = "All power supplies (%d) are in good condition" % ( ps_num - ps_absent )

    else:
        plugin.add_output_data("UNKNOWN", f"No power supply data returned for API URL '{redfish_url}'")

    # get PowerRedundancy status
    if plugin.rf.vendor == "HPE":
        redundancy_key = "PowerRedundancy"
    else:
        redundancy_key = "Redundancy"

    power_redundancies = plugin.rf.get_view(redfish_url).get(redundancy_key)

    if power_redundancies:
        status_text = ""
        for power_redundancy in power_redundancies:

            pr_status = power_redundancy.get("Status")

            if pr_status is not None:
                status = pr_status.get("Health")
                state = pr_status.get("State")

                if status is not None:
                    status = status.upper()

                    status_text = f"power redundancy status is: {state}"

                    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text[0].upper() + status_text[1:])

        if len(status_text) != 0:
            default_text += f" and {status_text}"

    plugin.add_output_data("OK", default_text, summary = True)

    return

def get_single_chassi_temp(redfish_url):

    global plugin

    plugin.set_current_command("Temp")

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin.rf.get_view(redfish_url)

    default_text = ""
    temp_num = 0
    if "Temperatures" in thermal_data:

        for temp in thermal_data.get("Temperatures"):

            state = temp.get("Status").get("State")

            if state in [ "Absent", "Disabled", "UnavailableOffline" ]:
                continue

            if temp.get("Status").get("Health") is None:
                if state == "Enabled":
                    status = "OK"
                else:
                    status = state
            else:
                status = temp.get("Status").get("Health").upper()

            name = temp.get("Name").strip()
            current_temp = temp.get("ReadingCelsius")
            critical_temp = temp.get("UpperThresholdCritical")
            warning_temp = temp.get("UpperThresholdNonCritical")

            temp_num += 1

            if current_temp is None:
                current_temp = 0

            if warning_temp is None or str(warning_temp) == "0":
                warning_temp = "N/A"

            if warning_temp != "N/A" and current_temp >= warning_temp:
                status = "WARNING"

            if critical_temp is None or str(critical_temp) == "0":
                critical_temp = "N/A"

            if critical_temp != "N/A" and current_temp >= critical_temp:
                status = "CRITICAL"

            status_text = f"Temp sensor {name} status is: {status} ({current_temp} °C) (max: {critical_temp} °C)"

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            warning_temp = warning_temp if warning_temp != "N/A" else None
            critical_temp = critical_temp if critical_temp != "N/A" else None

            plugin.add_perf_data(f"Temp_{name}", int(current_temp), warning=warning_temp, critical=critical_temp)

        default_text = f"All temp sensors ({temp_num}) are in good condition"
    else:
        plugin.add_output_data("UNKNOWN", f"No thermal data returned for API URL '{redfish_url}'")

    plugin.add_output_data("OK", default_text, summary = True)

    return

def get_single_chassi_fan(redfish_url):

    global plugin

    plugin.set_current_command("Fan")

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin.rf.get_view(redfish_url)

    default_text = ""
    fan_num = 0
    if "Fans" in thermal_data:
        for fan in thermal_data.get("Fans"):

            fan_num += 1

            state = fan.get("Status").get("State")
            if state == "Absent":
                continue

            if fan.get("Status").get("Health") is None:
                if state == "Enabled":
                    status = "OK"
                else:
                    status = state
            else:
                status = fan.get("Status").get("Health").upper()

            name = fan.get("FanName") or fan.get("Name")

            if fan.get("Oem") is not None:

                if plugin.rf.vendor == "Lenovo":
                    name = fan.get("Oem").get(plugin.rf.vendor_dict_key).get("Location").get("Info")

            speed_status = ""

            # DELL, Fujitsu, Huawei
            if fan.get("ReadingRPM") is not None or fan.get("ReadingUnits") == "RPM":
                speed = fan.get("ReadingRPM") or fan.get("Reading")
                speed_units = ""

                speed_status = f" ({speed} RPM)"

            # HP, Lenovo
            else:
                speed = fan.get("Reading")
                speed_units = fan.get("ReadingUnits")

                if speed_units:
                    speed_units = speed_units.replace("Percent", "%")
                else:
                    speed_units = ""

                speed_status = f" ({speed}{speed_units})"

            status_text = f"Fan '{name}'{speed_status} status is: {status}"

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            if speed:
                plugin.add_perf_data(f"Fan_{name}", int(speed), perf_uom=speed_units, warning=args.warning, critical=args.critical)

        default_text = f"All fans ({fan_num}) are in good condition"
    else:
        plugin.add_output_data("UNKNOWN", f"No thermal data returned for API URL '{redfish_url}'")

    # get FanRedundancy status
    if plugin.rf.vendor == "HPE":
        redundancy_key = "FanRedundancy"
    else:
        redundancy_key = "Redundancy"

    fan_redundancies = plugin.rf.get_view(redfish_url).get(redundancy_key)

    if fan_redundancies:
        status_text = ""
        for fan_redundancy in fan_redundancies:

            fr_status = fan_redundancy.get("Status")

            if fr_status is not None:
                status = fr_status.get("Health")
                state = fr_status.get("State")

                if status is not None:
                    status = status.upper()

                    status_text = f"fan redundancy status is: {state}"

                    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text[0].upper() + status_text[1:])

        if len(status_text) != 0:
            default_text += f" and {status_text}"

    plugin.add_output_data("OK", default_text, summary = True)

    return plugin

def get_system_data(data_type):

    global plugin

    if data_type is None or data_type not in [ "procs", "mem", "nics" ]:
        plugin.add_output_data("UNKNOWN", "Internal ERROR, data_type not set for get_system_data()")
        return

    if plugin.rf.connection.system_properties is None:
        discover_system_properties()

    systems = plugin.rf.connection.system_properties.get("systems")

    if systems is None or len(systems) == 0:
        plugin.add_output_data("UNKNOWN", "No 'systems' property found in root path '/redfish/v1'")
        return

    for system in systems:
        if data_type == "procs":
            get_single_system_procs(system)
        if data_type == "mem":
            get_single_system_mem(system)
        if data_type == "nics":
            if plugin.rf.vendor == "Fujitsu":
                get_system_nics_fujitsu(system)
            else:
                get_single_system_nics(system)

    return

def get_single_system_procs(redfish_url):

    global plugin

    plugin.set_current_command("Procs")

    systems_response = plugin.rf.get(redfish_url)

    if systems_response.get("ProcessorSummary"):

        proc_health = systems_response.get("ProcessorSummary").get("Status")

        # DELL is HealthRollUp not HealthRollup
        # Fujitsu is just Health an not HealthRollup
        health = proc_health.get("HealthRollup") or proc_health.get("HealthRollUp") or proc_health.get("Health")

        if health == "OK" and args.detailed == False:
            plugin.add_output_data("OK", "All processors (%d) are in good condition" % systems_response.get("ProcessorSummary").get("Count"), summary = True)
            return

    system_response_proc_key = "Processors"
    if systems_response.get(system_response_proc_key) is None:
        plugin.add_output_data("UNKNOWN", f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_proc_key}'")
        return

    processors_response = plugin.rf.get_view(systems_response.get(system_response_proc_key).get("@odata.id") + "%s" % plugin.rf.vendor_data.expand_string)

    if processors_response.get("Members") or processors_response.get(system_response_proc_key):

        for proc in processors_response.get("Members") or processors_response.get(system_response_proc_key):

            if proc.get("@odata.context"):
                proc_response = proc
            else:
                proc_response = plugin.rf.get(proc.get("@odata.id"))

            if proc_response.get("Id"):

                proc_status = proc_response.get("Status")

                if proc_status.get("State") and proc_status.get("State") == "Absent":
                    continue

                socket = proc_response.get("Socket")
                model =  proc_response.get("Model").strip()

                status = proc_status.get("Health").upper()

                status_text = f"Processor {socket} ({model}) status is: {status}"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No processor data returned for API URL '%s'" % proc_response.get("@odata.id"))
    else:
        plugin.add_output_data("UNKNOWN", f"No processor data returned for API URL '{redfish_url}'")

    return

def get_single_system_mem(redfish_url):

    global plugin

    plugin.set_current_command("Mem")

    systems_response = plugin.rf.get(redfish_url)

    if systems_response.get("MemorySummary"):

        health = None

        memory_health = systems_response.get("MemorySummary").get("Status")

        try:
            # DELL is HealthRollUp not HealthRollup
            # Fujitsu is just Health an not HealthRollup
            health = memory_health.get("HealthRollup") or memory_health.get("HealthRollUp") or memory_health.get("Health")
        except AttributeError:
            args.detailed = True

        if health == "OK" and args.detailed == False:

            total_mem = systems_response.get("MemorySummary").get("TotalSystemMemoryGiB")

            if plugin.rf.vendor == "Dell":
                total_mem = total_mem * 1024 ** 3 / 1000 ** 3

            plugin.add_output_data("OK", "All memory modules (Total %dGB) are in good condition" %
                total_mem, summary = True)
            return

    system_response_memory_key = "Memory"
    if systems_response.get("Oem") and systems_response.get("Oem").get(plugin.rf.vendor_dict_key) and \
        systems_response.get("Oem").get(plugin.rf.vendor_dict_key).get("Links") and \
        systems_response.get("Oem").get(plugin.rf.vendor_dict_key).get("Links").get("Memory"):
            memory_path_dict = systems_response.get("Oem").get(plugin.rf.vendor_dict_key).get("Links")
    else:
        memory_path_dict = systems_response

    if memory_path_dict.get(system_response_memory_key) is None:
        plugin.add_output_data("UNKNOWN", f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_memory_key}'")
        return

    redfish_url = memory_path_dict.get(system_response_memory_key).get("@odata.id") + "%s" % plugin.rf.vendor_data.expand_string

    memory_response = plugin.rf.get_view(redfish_url)

    found_memory_data = False

    if memory_response.get("Members") or memory_response.get(system_response_memory_key):

        for mem_module in memory_response.get("Members") or memory_response.get(system_response_memory_key):

            if mem_module.get("@odata.context"):
                mem_module_response = mem_module
            else:
                mem_module_response = plugin.rf.get(mem_module.get("@odata.id"))

            if mem_module_response.get("Id"):

                # get size
                size = mem_module_response.get("SizeMB") or mem_module_response.get("CapacityMiB")

                if size is None:
                    size = 0
                else:
                    #size = MiB_to_GB(size)
                    # DELL
                    if plugin.rf.vendor == "Dell":
                        size = round(size * 1024 ** 2 / 1000 ** 2) / 1024
                    else:
                        size = size / 1024

                # get name
                name = mem_module_response.get("SocketLocator") or mem_module_response.get("DeviceLocator")

                if name is None:
                    name = "UnknownNameLocation"

                # get status
                if plugin.rf.vendor == "HPE" and mem_module_response.get("Oem") and mem_module_response.get("Oem").get(plugin.rf.vendor_dict_key).get("DIMMStatus"):
                    status = mem_module_response.get("Oem").get(plugin.rf.vendor_dict_key).get("DIMMStatus")

                elif mem_module_response.get("DIMMStatus"):

                    status = mem_module_response.get("DIMMStatus")

                elif mem_module_response.get("Status"):

                    module_status = mem_module_response.get("Status")

                    if module_status.get("State") and module_status.get("State") == "Absent":
                        status = module_status.get("State")
                    else:
                        status = module_status.get("Health")

                else:
                    plugin.add_output_data("UNKNOWN", f"Error retrieving memory module status: {mem_module_response}")
                    continue

                if status in [ "Absent", "NotPresent"]:
                    continue

                found_memory_data = True

                status_text = f"Memory module {name} ({size}GB) status is: {status}"

                if status == "GoodInUse":
                    status = "OK"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No memory data returned for API URL '%s'" % mem_module.get("@odata.id"))

    if found_memory_data == False:
        plugin.add_output_data("UNKNOWN", f"No memory data returned for API URL '{redfish_url}'")

    return

def get_system_nics_fujitsu(redfish_url):

    global plugin

    plugin.set_current_command("NICs")

    redfish_url = f"{redfish_url}/NetworkInterfaces"  + "%s" % plugin.rf.vendor_data.expand_string

    nics_response = plugin.rf.get(redfish_url)

    num_nic_ports = 0

    if nics_response.get("Members") and len(nics_response.get("Members")) > 0:

        for nic in nics_response.get("Members"):

            nic_id = nic.get("Id")

            # network functions
            network_functions = plugin.rf.get("%s%s" % (nic.get("NetworkDeviceFunctions").get("@odata.id"), plugin.rf.vendor_data.expand_string))
            # network ports
            network_ports = plugin.rf.get("%s%s" % (nic.get("NetworkPorts").get("@odata.id"), plugin.rf.vendor_data.expand_string))

            for network_function in network_functions.get("Members"):

                # get port
                network_port_link = network_function.get("Links").get("PhysicalPortAssignment").get("@odata.id")

                network_port_data = None
                for network_port in network_ports.get("Members"):
                    if network_port.get("@odata.id") == network_port_link:
                        network_port_data = network_port
                        break

                num_nic_ports += 1

                nic_name = network_function.get("Name")
                nic_dev_func_type = network_port_data.get("ActiveLinkTechnology")
                nic_port_current_speed = network_port_data.get("CurrentLinkSpeedMbps")
                nic_port_name = network_port_data.get("Name")
                nic_port_link_status = network_port_data.get("LinkStatus")

                nic_port_address = network_function.get("Ethernet")
                if nic_port_address is not None:
                    nic_port_address = nic_port_address.get("MACAddress")

                # get health status
                nic_health_status = network_port_data.get("Status")
                if nic_health_status is not None:

                    # ignore interface if state is not Enabled
                    if nic_health_status.get("State") != "Enabled":
                        continue

                    nic_health_status = nic_health_status.get("Health")

                    if nic_health_status is not None:
                        nic_health_status = nic_health_status.upper()

                nic_capable_speed = None
                try:
                    nic_capable_speed = network_port_data.get("SupportedLinkCapabilities")[0].get("CapableLinkSpeedMbps")[0]
                except Exception:
                    pass

                status_text = f"NIC {nic_id} ({nic_name}) {nic_port_name} (Type: {nic_dev_func_type}, Speed: {nic_port_current_speed}/{nic_capable_speed}, MAC: {nic_port_address}) status: {nic_port_link_status}"
                plugin.add_output_data("CRITICAL" if nic_health_status not in ["OK", "WARNING"] else nic_health_status, status_text)

    if num_nic_ports == 0:
        plugin.add_output_data("UNKNOWN", f"No network interface data returned for API URL '{redfish_url}'")

    plugin.add_output_data("OK", f"All network interfaces ({num_nic_ports}) are in good condition", summary = True)

    return

def get_single_system_nics(redfish_url):

    global plugin

    plugin.set_current_command("NICs")

    redfish_url = f"{redfish_url}/EthernetInterfaces/" + "%s" % plugin.rf.vendor_data.expand_string

    nics_response = plugin.rf.get_view(redfish_url)
    data_members = nics_response.get("EthernetInterfaces") or nics_response.get("Members")

    default_text = ""
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

                    status = nic_response.get("Status").get("Health")
                    link_status = nic_response.get("LinkStatus")

                else:
                    status = "Undefined"

                if status is None:
                    status = "Undefined"

                status_text = f"NIC {id} status is: {status}"

                if link_status:
                    status_text += f" and link status is '{link_status}'"

                if status == "Undefined":
                    status = "OK"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No network interface data returned for API URL '%s'" % nic.get("@odata.id"))

        default_text = f"All network interfaces ({nic_num}) are in good condition"
    else:
        plugin.add_output_data("UNKNOWN", f"No network interface data returned for API URL '{redfish_url}'")

    plugin.add_output_data("OK", default_text, summary = True)

    return

def get_storage():

    global plugin

    plugin.set_current_command("Storage")

    if plugin.rf.connection.system_properties is None:
        discover_system_properties()

    systems = plugin.rf.connection.system_properties.get("systems")

    if systems is None or len(systems) == 0:
        plugin.add_output_data("UNKNOWN", "No 'systems' property found in root path '/redfish/v1'")
        return

    for system in systems:

        if plugin.rf.vendor == "HPE":
            get_storage_hpe(system)

        elif plugin.rf.vendor == "Lenovo":
            get_storage_lenovo(system)

        else:
            get_storage_generic(system)

    return

def get_storage_hpe(system):

    def get_disks(link, type = "DiskDrives"):

        disks_response = plugin.rf.get("%s/%s/?$expand=." % (link,type))

        if disks_response.get("Members") is None:
            if type == "DiskDrives":
                plugin.add_output_data("OK", f"no {type} found for this Controller")
            return

        for disk in disks_response.get("Members"):

            if disk.get("@odata.context"):
                disk_response = disk
            else:
                disk_response = plugin.rf.get(disk.get("@odata.id"))

            status = disk_response.get("Status").get("Health").upper()
            location = disk_response.get("Location")
            size = disk_response.get("CapacityGB")

            status_text = f"Physical Drive ({location}) {size}GB Status: {status}"

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    def get_logical_drives(link):

        ld_response = plugin.rf.get("%s/LogicalDrives/?$expand=." % link)

        if ld_response.get("Members") is None:
            plugin.add_output_data("OK", "no logical drives found for this Controller")
            return

        for logical_drive in ld_response.get("Members"):

            if logical_drive.get("@odata.context"):
                logical_drive_response = logical_drive
            else:
                logical_drive_response = plugin.rf.get(logical_drive.get("@odata.id"))

            status = logical_drive_response.get("Status").get("Health").upper()
            id = logical_drive_response.get("LogicalDriveNumber")
            size = int(logical_drive_response.get("CapacityMiB")) * 1024 ** 2 / 1000 ** 3
            raid = logical_drive_response.get("Raid")

            status_text = "Logical Drive (%s) %.0fGB (RAID %s) Status: %s" % (id, size, raid, status)

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    def get_enclosures(link):

        enclosures_response = plugin.rf.get("%s/StorageEnclosures/?$expand=." % link)

        if enclosures_response.get("Members") is None:
            plugin.add_output_data("OK", "no storage enclosures found for this Controller")
            return

        for enclosure in enclosures_response.get("Members"):

            if enclosure.get("@odata.context"):
                enclosure_response = enclosure
            else:
                enclosure_response = plugin.rf.get(enclosure.get("@odata.id"))

            status = enclosure_response.get("Status").get("Health").upper()
            location = enclosure_response.get("Location")

            status_text = f"StorageEnclosure ({location}) Status: {status}"

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    global plugin

    plugin.set_current_command("Storage")

    redfish_url = f"{system}/SmartStorage/"

    storage_response = plugin.rf.get(redfish_url)

    status = storage_response.get("Status").get("Health").upper()

    if status and status == "OK" and args.detailed == False:
        plugin.add_output_data("OK", f"Status of HP SmartArray is: {status}", summary = True)
        return

    # unhealthy
    redfish_url = f"{system}/SmartStorage/ArrayControllers/?$expand=."

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
                controller_status = controller_response.get("Status")

                if controller_status.get("State") and controller_status.get("State") == "Absent":
                    continue

                status = controller_status.get("Health").upper()

                status_text = f"{model} (FW: {fw_version}) status is: {status}"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

                get_disks(array_controller.get("@odata.id"))
                get_logical_drives(array_controller.get("@odata.id"))
                get_enclosures(array_controller.get("@odata.id"))
                get_disks(array_controller.get("@odata.id"), "UnconfiguredDrives")
            else:
                plugin.add_output_data("UNKNOWN", "No array controller data returned for API URL '%s'" % array_controller.get("@odata.id"))

    else:
        plugin.add_output_data("UNKNOWN", f"No array controller data returned for API URL '{redfish_url}'")

    return

def get_storage_lenovo(system):

    def get_disks(link):

        disks_response = plugin.rf.get("%s/?$expand=*" % link)

        if disks_response.get("value") is None:
            plugin.add_output_data("OK", f"no disk found for this Controller")
            return

        for disk_response in disks_response.get("value"):

            name = disk_response.get("Name").strip()
            status = disk_response.get("Status").get("Health").upper()
            location = disk_response.get("Location") or disk_response.get("PhysicalLocation")
            location = location[0].get("Info")
            size = disk_response.get("CapacityBytes")

            if size is not None and size > 0:
                size = size / ( 1000 ** 3)

            status_text = f"Physical Drive {name} ({location}) %0.2fGiB Status: {status}" % size

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    def get_volumes(link):

        volumes_response = plugin.rf.get("%s/?$expand=*" % link)

        if len(volumes_response.get("Members")) == 0:
            plugin.add_output_data("OK", f"no volumes found for this Controller")
            return

        for volume_response in volumes_response.get("Members"):

            name = volume_response.get("Name").strip()
            status = volume_response.get("Status").get("Health").upper()
            size = int(volume_response.get("CapacityBytes")) / ( 1000 ** 3)
            raid = volume_response.get("Oem").get(plugin.rf.vendor_dict_key).get("RaidLevel")

            status_text = "Logical Drive %s %.0fGiB (%s) Status: %s" % (name, size, raid, status)

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    global plugin

    plugin.set_current_command("Storage")

    redfish_url = f"{system}/Storage/?$expand=Members"

    storage_response = plugin.rf.get(redfish_url)

    if storage_response is not None:

        storage_status = list()
        storage_controller_names = list()

        for storage_member in storage_response.get("Members"):

            if storage_member.get("Id"):

                name = storage_member.get("Name")

                storage_status.append(storage_member.get("Status").get("HealthRollup").upper())

                for storage_controller in storage_member.get("StorageControllers"):
                    model = storage_controller.get("Model")
                    fw_version = storage_controller.get("FirmwareVersion")
                    location = storage_controller.get("Oem").get(plugin.rf.vendor_dict_key).get("Location").get("Info")
                    controller_status = storage_controller.get("Status")

                    if controller_status.get("State") and controller_status.get("State") == "Absent":
                        continue

                    status = controller_status.get("Health").upper()

                    storage_controller_names.append(f"{name} {model}")

                    status_text = f"{name} {model} ({location}) (FW: {fw_version}) status is: {status}"

                    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)


                get_disks(storage_member.get("Drives@odata.navigationLink"))
                get_volumes(storage_member.get("Volumes").get("@odata.id"))

            else:
                plugin.add_output_data("UNKNOWN", "No array controller data returned for API URL '%s'" % storage_member.get("@odata.id"))

        if "CRITICAL" in storage_status:
            status = "CRITICAL"
        elif "WARNING" in storage_status:
            status = "WARNING"
        else:
            status = "OK"

        if status != "OK":
            plugin.add_output_data("CRITICAL", "One or more storage controller report a issue")
        else:
            plugin.add_output_data("OK", "Status of %s is: OK" % " and ".join(storage_controller_names), summary = True)
    else:
        plugin.add_output_data("UNKNOWN", f"No storage controller data returned for API URL '{redfish_url}'")

    return

def get_storage_generic(system):

    def get_drive(drive_link):

        drive_response = plugin.rf.get(drive_link)

        if drive_response.get("Name") is None:
            plugin.add_output_data("UNKNOWN", f"Unable to retrieve disk infos: {drive_link}")
            return

        name = drive_response.get("Name").strip()
        model = drive_response.get("Model")
        type = drive_response.get("MediaType")
        protocol = drive_response.get("Protocol")
        status = drive_response.get("Status").get("Health").upper()
        size = drive_response.get("CapacityBytes")

        drives_status_list.append(status)

        if size is not None and size > 0:
            size = "%0.2fGB" % (size / ( 1000 ** 3))
        else:
            size = "0GB"

        status_text = f"Physical Drive {name} ({model} / {type} / {protocol}) {size} status: {status}"

        plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    def get_volumes(volumes_link):

        volumes_response = plugin.rf.get(volumes_link)

        if len(volumes_response.get("Members")) == 0:
            plugin.add_output_data("OK", f"No volumes found for this controller")
            return

        for volume_member in volumes_response.get("Members"):

            volume_data = plugin.rf.get(volume_member.get("@odata.id"))

            if volume_data.get("Name") is None:
                continue

            name = volume_data.get("Name")
            status = volume_data.get("Status").get("Health")
            if status is not None:
                status = status.upper()

            volume_status_list.append(status)

            if volume_data.get("CapacityBytes") is not None:
                size = int(volume_data.get("CapacityBytes")) / ( 1000 ** 3)
            else:
                size = 0

            raid_level = volume_data.get("VolumeType")
            volume_name = volume_data.get("Description")

            if plugin.rf.vendor == "Huawei":
                raid_level = volume_data.get("Oem").get(plugin.rf.vendor_dict_key).get("VolumeRaidLevel")
                volume_name = volume_data.get("Oem").get(plugin.rf.vendor_dict_key).get("VolumeName")

            if plugin.rf.vendor == "Fujitsu":
                raid_level = volume_data.get("Oem").get(plugin.rf.vendor_dict_key).get("RaidLevel")
                volume_name = volume_data.get("Oem").get(plugin.rf.vendor_dict_key).get("Name")

            status_text = "Logical Drive %s (%s) %.0fGiB (%s) Status: %s" % (name, volume_name, size, raid_level, status)

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    def condensed_status_from_list(status_list):

        status = None

        status_list = list(set(status_list))

        # remove default state
        if "OK" in status_list:
            status_list.remove("OK")

        if len(status_list) == 0:
            status = "OK"
        elif len(status_list) == 1 and status_list[0] == "WARNING":
            status = "WARNING"
        else:
            status = "CRITICAL"

        return status

    global plugin

    plugin.set_current_command("Storage")

    if plugin.rf.vendor == "Huawei":
        redfish_url = f"{system}/Storages" + "%s" % plugin.rf.vendor_data.expand_string
    else:
        redfish_url = f"{system}/Storage" + "%s" % plugin.rf.vendor_data.expand_string

    storage_response = plugin.rf.get(redfish_url)

    system_drives_list = list()
    drives_status_list = list()
    storage_controller_names_list = list()
    storage_status_list = list()
    volume_status_list = list()

    if storage_response is not None:

        for storage_member in storage_response.get("Members"):

            if storage_member.get("@odata.context"):
                controller_response = storage_member
            else:
                controller_response = plugin.rf.get(storage_member.get("@odata.id"))

            if controller_response.get("Status") and len(controller_response.get("Status")) > 0 and controller_response.get("Status").get("Health") is None:
                continue

            if controller_response.get("Id"):

                for storage_controller in controller_response.get("StorageControllers"):
                    name = storage_controller.get("Name")
                    model = storage_controller.get("Model")
                    fw_version = storage_controller.get("FirmwareVersion")
                    controller_status = storage_controller.get("Status")

                    controller_oem_data = None
                    if storage_controller.get("Oem") is not None:
                        controller_oem_data = storage_controller.get("Oem").get(plugin.rf.vendor_dict_key)

                    if controller_oem_data is not None:
                        model = controller_oem_data.get("Type") if controller_oem_data.get("Type") else model

                    # ignore absent and Health None controllers
                    if controller_status.get("State") and controller_status.get("State") == "Absent":
                        continue

                    if controller_status.get("Health") is None:
                        continue

                    status = controller_status.get("Health").upper()

                    storage_status_list.append(status)

                    storage_controller_names_list.append(f"{name} {model}")

                    status_text = f"{name} {model} (FW: {fw_version}) status is: {status}"

                    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

                    if controller_oem_data is not None and controller_oem_data.get("CapacitanceStatus") is not None:
                        cap_model = controller_oem_data.get("CapacitanceName")
                        cap_status = controller_oem_data.get("CapacitanceStatus").get("Health")
                        cap_fault_details = controller_oem_data.get("CapacitanceStatus").get("FaultDetails")

                        if cap_status is not None:
                            cap_status = cap_status.upper()

                        cap_status_text = f"Controller capacitor ({cap_model}) status: {status}"

                        if cap_status != "OK" and cap_fault_details is not None:
                            cap_status_text += f" : {cap_fault_details}"

                        plugin.add_output_data("CRITICAL" if cap_status not in ["OK", "WARNING"] else cap_status, cap_status_text)

                if len(controller_response.get("Drives")) == 0:
                    plugin.add_output_data("OK", f"No drives found for this controller")
                else:
                    for controller_drive in controller_response.get("Drives"):
                        system_drives_list.append(controller_drive.get("@odata.id"))
                        get_drive(controller_drive.get("@odata.id"))

                get_volumes(controller_response.get("Volumes").get("@odata.id"))

            else:
                plugin.add_output_data("UNKNOWN", "No array controller data returned for API URL '%s'" % controller_response.get("@odata.id"))

    # check for other drives in system
    system_response = plugin.rf.get(system)

    if system_response.get("Oem") is not None and system_response.get("Oem").get(plugin.rf.vendor_dict_key).get("StorageViewsSummary") is not None:

        system_drives = system_response.get("Oem").get(plugin.rf.vendor_dict_key).get("StorageViewsSummary").get("Drives")
        if system_drives is not None:
            for system_drive in system_drives:
                drive_url = system_drive.get("Link").get("@odata.id")
                if drive_url not in system_drives_list:
                    system_drives_list.append(drive_url)
                    get_drive(drive_url)

    condensed_storage_status = condensed_status_from_list(storage_status_list)
    condensed_drive_status = condensed_status_from_list(drives_status_list)
    condensed_volume_status = condensed_status_from_list(volume_status_list)

    if len(storage_controller_names_list) == 0 and len(system_drives_list) == 0:
        plugin.add_output_data("UNKNOWN", "No storage controller and disk drive data found in system", summary = not args.detailed)
    elif args.detailed == False:
        if len(storage_controller_names_list) == 0 and len(system_drives_list) != 0:

            drive_summary_status = "All system drives are in good condition (No storage controller found)"

            plugin.add_output_data(condensed_drive_status, drive_summary_status, summary = True)

        elif len(storage_controller_names_list) != 1 and len(system_drives_list) == 0:

            storage_summary_status = "All storage controllers (%s) are in good condition (No system drives found)" % (", ".join(storage_controller_names_list))

            plugin.add_output_data(condensed_storage_status, storage_summary_status, summary = True)
        else:
            condensed_summary_status = condensed_status_from_list([condensed_storage_status, condensed_drive_status, condensed_volume_status])

            if condensed_summary_status == "OK":
                summary_status = "All storage controllers (%s), volumes and disk drives are in good condition" % (", ".join(storage_controller_names_list))
            else:
                summary_status = "One or more storage components report an issue"

            plugin.add_output_data(condensed_summary_status, summary_status, summary = True)

    return

def get_event_log(type):

    global plugin

    if type not in ["Manager", "System"]:
        raise Exception("Unknown event log type: %s", type)

    plugin.set_current_command("%s Event Log" % type)

    if plugin.rf.vendor == "Lenovo":
        get_event_log_lenovo(type)

    elif plugin.rf.vendor in [ "Huawei", "Fujitsu", "HPE", "Dell" ]:

        if type == "System" and plugin.rf.vendor in [ "Huawei", "HPE" ]:
            property_name = "systems"
        else:
            property_name = "managers"

        if plugin.rf.connection.system_properties is None:
            discover_system_properties()

        system_manager_ids = plugin.rf.connection.system_properties.get(property_name)

        if system_manager_ids is None or len(system_manager_ids) == 0:
            plugin.add_output_data("UNKNOWN", f"No '{property_name}' property found in root path '/redfish/v1'", summary = not args.detailed)
            return

        for system_manager_id in system_manager_ids:

            if plugin.rf.vendor == "HPE":
                get_event_log_hpe(type, system_manager_id)

            elif plugin.rf.vendor == "Huawei":
                get_event_log_huawei(type, system_manager_id)

            elif plugin.rf.vendor in [ "Dell", "Fujitsu" ]:
                get_event_log_dell_fujitsu(type, system_manager_id)

    else:
        plugin.add_output_data("UNKNOWN", f"Command to check {type} Event Log not implemented for this vendor", summary = not args.detailed)

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

    if type == "System":
        redfish_url = f"{system_manager_id}/LogServices/IML/Entries/?$expand=."
    else:
        redfish_url = f"{system_manager_id}/LogServices/IEL/Entries?$expand=."

        if args.warning:
            date_warning = data_now - datetime.timedelta(days=int(args.warning))
        if args.critical:
            date_critical = data_now - datetime.timedelta(days=int(args.critical))

    event_data = plugin.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin.add_output_data("OK", "No log entries found.", summary = not args.detailed)
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

        if type == "System":
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

def get_event_log_lenovo(type):

    global plugin

    """
    if type == "System":
        redfish_url = f"/redfish/v1/Systems/{system_manager_id}/LogServices/ActiveLog/Entries/" # /Entries/?$expand=.
    else:
        redfish_url = f"/redfish/v1/Systems/{system_manager_id}/LogServices/StandardLog/Entries/" # ML/Entries/?$expand=.

    # event_data = plugin.rf.get(redfish_url)
    """

    plugin.add_output_data("UNKNOWN", f"Request of {type} Event Log entries currently not implemented due to timeout issues.")

def get_event_log_dell_fujitsu(type, system_manager_id):

    global plugin

    limit_of_returned_itmes = args.max
    forced_limit = False
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None

    if type == "System":
        if plugin.rf.vendor == "Dell":
            redfish_url = f"{system_manager_id}/Logs/Sel"
        else:
            redfish_url = f"{system_manager_id}/LogServices/SystemEventLog/Entries/" # /Entries/?$expand=.
    else:
        if plugin.rf.vendor == "Dell":
            redfish_url = f"{system_manager_id}/Logs/Lclog"
        else:
            redfish_url = f"/redfish/v1/Managers/iRMC/LogServices/InternalEventLog/Entries/" # ML/Entries/?$expand=.

        if args.warning:
            date_warning = data_now - datetime.timedelta(days=int(args.warning))
        if args.critical:
            date_critical = data_now - datetime.timedelta(days=int(args.critical))

    event_data = plugin.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin.add_output_data("OK", "No log entries found.", summary = not args.detailed)
        return

    event_entries = event_data.get("Members")

    assoc_id_status = dict()

    num_entry = 0
    for event_entry_item in event_entries:

        if event_entry_item.get("Severity"):
            event_entry = event_entry_item
        else:
            event_entry = plugin.rf.get(event_entry_item.get("@odata.id"))

        message = event_entry.get("Message")

        num_entry += 1

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()

        date = event_entry.get("Created")

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00-00:00"

        status = "OK"

        # keep track of message IDs
        # newer message can clear a status for older messages
        if type == "System":

            # get log entry id to associate older log entries
            if plugin.rf.vendor == "Dell":
                assoc_id = event_entry.get("MessageId")
            if plugin.rf.vendor == "Fujitsu":
                assoc_id = event_entry.get("SensorNumber")

            # found an old message that has been cleared
            if assoc_id is not None and assoc_id_status.get(assoc_id) == "cleared" and severity != "OK":
                message += " (severity '%s' cleared)" % severity
            else:
                if severity == "WARNING":
                    status = severity
                elif severity != "OK":
                    status = "CRITICAL"

            # keep track of messages that clear an older message
            # get entry code
            if plugin.rf.vendor == "Dell":
                if event_entry.get("EntryCode") is not None:
                    if event_entry.get("EntryCode")[0].get("Member") == "Deassert" and assoc_id is not None:
                        assoc_id_status[assoc_id] = "cleared"

            if plugin.rf.vendor == "Fujitsu":
                if event_entry.get("SensorNumber") is not None and severity == "OK":
                    assoc_id_status[assoc_id] = "cleared"

        else:
            # convert time zone offset from valid ISO 8601 format to python implemented datetime TZ offset
            # from:
            #   2019-11-01T15:03:32-05:00
            # to:
            #   2019-11-01T15:03:32-0500

            entry_data = datetime.datetime.strptime(date[::-1].replace(":","",1)[::-1], "%Y-%m-%dT%H:%M:%S%z")

            if date_critical is not None:
              if entry_data > date_critical.astimezone(entry_data.tzinfo) and severity != "OK":
                    status = "CRITICAL"
            if date_warning is not None:
                if entry_data > date_warning.astimezone(entry_data.tzinfo) and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_itmes is not None and num_entry >= limit_of_returned_itmes:
            return
    return

def get_event_log_huawei(type, system_manager_id):

    def collect_log_entries(entry_url):

        collected_log_entries_list = list()

        while True:

            event_data = plugin.rf.get(entry_url)

            collected_log_entries_list.extend(event_data.get("Members"))

            if limit_of_returned_itmes is not None and len(collected_log_entries_list) >= limit_of_returned_itmes:
                break

            if event_data.get("Members@odata.nextLink") is not None:
                entry_url = event_data.get("Members@odata.nextLink")
            else:
                break

        return collected_log_entries_list

    global plugin

    limit_of_returned_itmes = args.max
    num_entry = 0
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    log_entries = list()

    if type == "System":
        redfish_url = f"{system_manager_id}/LogServices/Log1/Entries/"

        log_entries = collect_log_entries(redfish_url)
    else:

        """
        This is currently only a start of implementation. Will be finished once we
        have an example of how the different LogServices Entries look like.
        """

        # leave here and tell user about missing implementation
        plugin.add_output_data("UNKNOWN", f"Command to check {type} Event Log not implemented for this vendor", summary = not args.detailed)
        return

        # set fix to max 50 (ugly, needs to be re-factored)
        if limit_of_returned_itmes is not None and limit_of_returned_itmes > 50:
            limit_of_returned_itmes = 50
        else:
            limit_of_returned_itmes = 50

        redfish_url = f"{system_manager_id}"

        manager_data = plugin.rf.get(redfish_url)

        if len(manager_data.get("LogServices")) == 0:
            plugin.add_output_data("UNKNOWN", f"No 'LogServices' found for redfish URL '{redfish_url}'", summary = not args.detailed)
            return

        log_services_data = plugin.rf.get(manager_data.get("LogServices").get("@odata.id"))

        while True:

            # this should loop over following LogServices
            # https://device_ip/redfish/v1/Managers/1/LogServices/OperateLog/Entries
            # https://device_ip/redfish/v1/Managers/1/LogServices/RunLog/Entries
            # https://device_ip/redfish/v1/Managers/1/LogServices/SecurityLog/Entries

            for manager_log_service in log_services_data.get("Members"):
                log_entries.extend(manager_log_service.get("@odata.id") + "/Entries")

            if limit_of_returned_itmes is not None and len(log_entries) >= limit_of_returned_itmes:
                break


    if args.warning:
        date_warning = data_now - datetime.timedelta(days=int(args.warning))
    if args.critical:
        date_critical = data_now - datetime.timedelta(days=int(args.critical))

    for log_entry in log_entries:

        event_entry = plugin.rf.get(log_entry.get("@odata.id"))

        num_entry += 1

        """
        It is not really clear what a "Asserted" and a "Deasserted" event looks like.
        We could assume that an "Asserted" event contains a "MessageId" and a
        "Deasserted" event doesn't. And the Only relation between these events is the
        exact same "Message" text. The "EventID" isn't really helpful either.
        And a clearing (Deasserted) of an alarm doesn't seem to work reliably either.
        It is also not possible to mark an event as "repaired" in iBMC.

        Due to all the above stated issues we implement a simple critical and warnings
        days logic as with HP Manager event logs. Otherwise uncleared events will alarm
        forever.
        """

        severity = event_entry.get("Severity").upper()
        message = event_entry.get("Message")
        date = event_entry.get("Created")
        # event_id = event_entry.get("EventId")
        # message_id = event_entry.get("MessageId")

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00-00:00"

        status = "OK"

        # convert time zone offset from valid ISO 8601 format to python implemented datetime TZ offset
        # from:
        #   2019-11-01T15:03:32-05:00
        # to:
        #   2019-11-01T15:03:32-0500

        entry_data = datetime.datetime.strptime(date[::-1].replace(":","",1)[::-1], "%Y-%m-%dT%H:%M:%S%z")

        if date_critical is not None:
          if entry_data > date_critical.astimezone(entry_data.tzinfo) and severity != "OK":
                status = "CRITICAL"
        if date_warning is not None:
            if entry_data > date_warning.astimezone(entry_data.tzinfo) and status != "CRITICAL" and severity != "OK":
                status = "WARNING"

        plugin.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_itmes is not None and num_entry >= limit_of_returned_itmes:
            return

    return

def get_system_info():

    global plugin

    plugin.set_current_command("System Info")

    if plugin.rf.connection.system_properties is None:
        discover_system_properties()

    systems = plugin.rf.connection.system_properties.get("systems")

    if systems is None or len(systems) == 0:
        plugin.add_output_data("UNKNOWN", "No 'systems' property found in root path '/redfish/v1'")
        return

    for system in systems:
        get_single_system_info(system)

    return

def get_single_system_info(redfish_url):

    global plugin

    system_response = plugin.rf.get(redfish_url)

    if system_response is None:
        plugin.add_output_data("UNKNOWN", f"No system information data returned for API URL '{redfish_url}'")
        return

    model = system_response.get("Model").strip()
    vendor_name = system_response.get("Manufacturer").strip()
    serial = system_response.get("SerialNumber").strip()
    system_health_state = system_response.get("Status").get("Health").upper()
    power_state = system_response.get("PowerState")
    bios_version = system_response.get("BiosVersion")
    host_name = system_response.get("HostName")
    cpu_num = system_response.get("ProcessorSummary").get("Count")
    mem_size = system_response.get("MemorySummary").get("TotalSystemMemoryGiB")

    # Huawei system
    if plugin.rf.vendor == "Huawei":
        model = system_response.get("Oem").get(plugin.rf.vendor_dict_key).get("ProductName")

    # Dell system
    # just WHY?
    if plugin.rf.vendor == "Dell":
        mem_size = round(mem_size * 1024 ** 3 / 1000 ** 3)

    if host_name is not None:
        host_name = host_name.strip()
    else:
        host_name = ""

    status = "OK"
    if system_health_state == "WARNING":
        status = "WARNING"
    elif system_health_state != "OK":
        status = "CRITICAL"

    if len(host_name) == 0:
        host_name = "NOT SET"

    status_text = f"Type: {vendor_name} {model} (CPU: {cpu_num}, MEM: {mem_size}GB) - BIOS: {bios_version} - Serial: {serial} - Power: {power_state} - Name: {host_name}"

    if args.detailed is False:
        plugin.add_output_data(status, status_text, summary = True)
    else:
        plugin.add_output_data(status, status_text)
        # add ILO data
        if plugin.rf.vendor == "HPE":
            plugin.add_output_data("OK", "%s - FW: %s" % (plugin.rf.vendor_data.ilo_version, plugin.rf.vendor_data.ilo_firmware_version))
        # add SDCard status
        if plugin.rf.vendor == "Fujitsu":
            sd_card = plugin.rf.get(redfish_url + "/Oem/ts_fujitsu/SDCard")

            if sd_card.get("Inserted") is True:
                sd_card_status = sd_card.get("Status")
                sd_card_capacity = sd_card.get("CapacityMB")
                sd_card_free_space = sd_card.get("FreeSpaceMB")

                status_text = f"SDCard Capacity {sd_card_capacity}MB and {sd_card_free_space}MB free space left."
                plugin.add_output_data("CRITICAL" if sd_card_status not in ["OK", "WARNING"] else sd_card_status, status_text)

    return

def get_firmware_info():

    global plugin

    plugin.set_current_command("Firmware Info")

    if (plugin.rf.vendor == "HPE" and plugin.rf.vendor_data.ilo_version.lower() == "ilo 4") or plugin.rf.vendor == "Fujitsu":

        if plugin.rf.connection.system_properties is None:
            discover_system_properties()

        system_ids = plugin.rf.connection.system_properties.get("systems")

        if system_ids is None or len(system_ids) == 0:
            plugin.add_output_data("UNKNOWN", f"No 'systems' property found in root path '/redfish/v1'")
            return

        for system_id in system_ids:

            if plugin.rf.vendor == "Fujitsu":
                get_firmware_info_fujitsu(system_id)
            else:
                get_firmware_info_hpe_ilo4(system_id)

    else:
        get_firmware_info_generic()

    return

def get_firmware_info_hpe_ilo4(system_id = 1):

    global plugin

    redfish_url = f"{system_id}/FirmwareInventory/"

    firmware_response = plugin.rf.get(redfish_url)

    for key, firmware_entry in firmware_response.get("Current").items():

        for firmware_entry_object in firmware_entry:

            component_name = firmware_entry_object.get("Name")
            component_version = firmware_entry_object.get("VersionString")
            component_location = firmware_entry_object.get("Location")

            plugin.add_output_data("OK", f"{component_name} ({component_location}): {component_version}")

    plugin.add_output_data("OK", "Found %d firmware entries. Use '--detailed' option to display them." % len(firmware_response.get("Current")), summary = True)

    return

def get_firmware_info_fujitsu(system_id):

    # there is room for improvement

    global plugin

    # list of dicts: keys: {name, version, location}
    firmware_entries = list()

    if plugin.rf.connection.system_properties is None:
            discover_system_properties()

    # get iRMC firmware
    manager_ids = plugin.rf.connection.system_properties.get("managers")

    if manager_ids is not None and len(manager_ids) > 0:

        irmc_firmware_informations = get_bmc_firmware_fujitsu(manager_ids[0])

        if irmc_firmware_informations is not None:
            for bmc_fw_bank in [ "iRMCFwImageHigh", "iRMCFwImageLow" ]:
                fw_info = irmc_firmware_informations.get(bmc_fw_bank)
                if fw_info is not None:
                    firmware_entries.append(
                        { "name": "%s iRMC" % fw_info.get("FirmwareRunningState"),
                          "version": "%s, Booter %s, SDDR: %s/%s (%s)," % (
                            fw_info.get("FirmwareVersion"),
                            fw_info.get("BooterVersion"),
                            fw_info.get("SDRRVersion"),
                            fw_info.get("SDRRId"),
                            fw_info.get("FirmwareBuildDate")
                          ),
                          "location": "System Board"
                        }
                    )

    # get power supply firmware
    chassie_ids = plugin.rf.connection.system_properties.get("chassis")

    if chassie_ids is not None and len(chassie_ids) > 0:

        for chassie_id in chassie_ids:
            power_data = plugin.rf.get(f"{chassie_id}/Power")

            if power_data.get("PowerSupplies") is not None and len(power_data.get("PowerSupplies")) > 0:

                for ps_data in power_data.get("PowerSupplies"):
                    ps_manufacturer = ps_data.get("Manufacturer")
                    ps_location = ps_data.get("Name")
                    ps_model = ps_data.get("Model")
                    ps_fw_version = ps_data.get("FirmwareVersion")

                    firmware_entries.append({
                        "name": f"Power Supply {ps_manufacturer} {ps_model}",
                        "version": f"{ps_fw_version}",
                        "location": f"{ps_location}"
                    })


    # get hard drive firmware
    redfish_url = f"{system_id}/Storage" + "%s" % plugin.rf.vendor_data.expand_string

    storage_response = plugin.rf.get(redfish_url)

    for storage_member in storage_response.get("Members"):

        controller_response = None
        if storage_member.get("@odata.context"):
            controller_response = storage_member
        else:
            controller_response = plugin.rf.get(storage_member.get("@odata.id"))

        for controller_drive in controller_response.get("Drives"):
            drive_response = plugin.rf.get(controller_drive.get("@odata.id"))

            if drive_response.get("Name") is not None:
                drive_name = drive_response.get("Name")
                drive_firmware = drive_response.get("Revision")
                drive_slot = drive_response.get("Oem").get(plugin.rf.vendor_dict_key).get("SlotNumber")
                drive_storage_controller = storage_member.get("Id")

                firmware_entries.append({
                    "name": f"Drive {drive_name}",
                    "version": f"{drive_firmware}",
                    "location": f"{drive_storage_controller}:{drive_slot}"
                })

    # get other firmware
    redfish_url = f"{system_id}/Oem/%s/FirmwareInventory/" % plugin.rf.vendor_dict_key

    firmware_response = plugin.rf.get(redfish_url)

    # get BIOS
    if firmware_response.get("SystemBIOS"):
        firmware_entries.append({
            "name": "SystemBIOS",
            "version": "%s" % firmware_response.get("SystemBIOS"),
            "location": "System Board"
        })

    # get other components
    for key, value in firmware_response.items():

        if key.startswith("@"):
            continue

        if isinstance(value, dict) and value.get("@odata.id") is not None:
            component_fw_data = plugin.rf.get(value.get("@odata.id"))

            if component_fw_data.get("Ports") is not None and len(component_fw_data.get("Ports")) > 0:

                for component_entry in component_fw_data.get("Ports"):
                    component_name = component_entry.get("AdapterName")
                    component_location = component_entry.get("ModuleName")
                    component_bios_version = component_entry.get("BiosVersion")
                    component_fw_version = component_entry.get("FirmwareVersion")
                    component_slot = component_entry.get("SlotId")
                    component_port = component_entry.get("PortId")

                    firmware_entries.append({
                        "name": f"{component_name}",
                        "version": f"{component_fw_version} (BIOS: {component_bios_version})",
                        "location": f"{component_location} {component_slot}/{component_port}"
                    })

            if component_fw_data.get("Adapters") is not None and len(component_fw_data.get("Adapters")) > 0:

                for component_entry in component_fw_data.get("Adapters"):
                    component_name = component_entry.get("ModuleName")
                    component_pci_segment = component_entry.get("PciSegment")
                    component_bios_version = component_entry.get("BiosVersion")
                    component_fw_version = component_entry.get("FirmwareVersion")

                    system_id_num = system_id.split("/")[-1]

                    firmware_entries.append({
                        "name": f"{component_name} controller",
                        "version": f"{component_fw_version} (BIOS: {component_bios_version})",
                        "location": f"{system_id_num}:{component_pci_segment}"
                    })

    if args.detailed is True:
        for fw_entry in firmware_entries:
            plugin.add_output_data("OK", "%s (%s): %s" % (fw_entry.get("name"), fw_entry.get("location"), fw_entry.get("version")))

    plugin.add_output_data("OK", "Found %d firmware entries. Use '--detailed' option to display them." % len(firmware_entries), summary = True)

    return

def get_firmware_info_generic():

    global plugin

    if plugin.rf.connection.root.get("UpdateService") is None:
        plugin.add_output_data("UNKNOWN", "URL '/redfish/v1/UpdateService' unavailable. Unable to retrieve firmware information.", summary = not args.detailed)
        return

    redfish_url = "/redfish/v1/UpdateService/FirmwareInventory/" + "%s" % plugin.rf.vendor_data.expand_string

    firmware_response = plugin.rf.get(redfish_url)

    if args.detailed is False:
        plugin.add_output_data("OK", "Found %d firmware entries. Use '--detailed' option to display them." % len(firmware_response.get("Members")), summary = True)
        return

    for firmware_member in firmware_response.get("Members"):

        if firmware_member.get("@odata.type"):
            firmware_entry = firmware_member
        else:
            firmware_entry = plugin.rf.get(firmware_member.get("@odata.id"))

        component_name = firmware_entry.get("Name")
        component_version = firmware_entry.get("Version")
        component_id = None

        if plugin.rf.vendor == "HPE":
            component_id = firmware_entry.get("Oem").get(plugin.rf.vendor_dict_key).get("DeviceContext")

        if component_id is None:
            component_id = firmware_entry.get("Id")

        plugin.add_output_data("OK", f"{component_name} ({component_id}): {component_version}")

    return

def get_bmc_info():

    global plugin
    known_manager = False

    plugin.set_current_command("BMC Info")

    managers = plugin.rf.connection.system_properties.get("managers")

    if managers is None or len(managers) == 0:
        plugin.add_output_data("UNKNOWN", "No 'managers' property found in root path '/redfish/v1'")
        return

    for manager in managers:
        if plugin.rf.vendor == "HPE":
            known_manager = True
            get_bmc_info_hpe(manager)

        if plugin.rf.vendor == "Lenovo":
            known_manager = True
            get_bmc_info_lenovo(manager)

        if plugin.rf.vendor in ["Dell", "Fujitsu"]:
            known_manager = True
            get_bmc_info_dell_fujitsu(manager)

        if plugin.rf.vendor == "Huawei":
            known_manager = True
            get_bmc_info_huawei(manager)

    if known_manager == False:
        plugin.add_output_data("UNKNOWN", "'bmc' command is currently not supported for this system.")

    return

def get_bmc_info_hpe(redfish_url):

    global plugin

    view_response = plugin.rf.get_view(f"{redfish_url}/" + plugin.rf.vendor_data.expand_string)

    if view_response.get("ILO"):
        manager_response = view_response.get("ILO")[0]
    else:
        manager_response = view_response

    # get general informations
    ilo_data = manager_response.get("Oem").get(plugin.rf.vendor_dict_key)

    # firmware
    ilo_firmware = ilo_data.get("Firmware").get("Current")
    ilo_fw_date = ilo_firmware.get("Date")
    ilo_fw_version = ilo_firmware.get("VersionString")

    plugin.add_output_data("OK", f"{ilo_fw_version} ({ilo_fw_date})")

    # license
    ilo_license_string = ilo_data.get("License").get("LicenseString")
    ilo_license_key = ilo_data.get("License").get("LicenseKey")

    plugin.add_output_data("OK", f"Licenses: {ilo_license_string} ({ilo_license_key})")

    # iLO Self Test
    for self_test in ilo_data.get("iLOSelfTestResults"):

        status = self_test.get("Status")

        if status is None or status == "Informational":
            continue

        status = status.upper()

        name = self_test.get("SelfTestName")
        notes = self_test.get("Notes").strip()

        if notes is not None and len(notes) != 0:
            status_text = f"SelfTest {name} ({notes}) status: {status}"
        else:
            status_text = f"SelfTest {name} status: {status}"

        plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    # iLO Network interfaces
    redfish_url = f"{redfish_url}/EthernetInterfaces/" + plugin.rf.vendor_data.expand_string

    if view_response.get("ILOInterfaces") is None:
        manager_nic_response = plugin.rf.get(redfish_url)

        if manager_nic_response.get("Members") is None or len(manager_nic_response.get("Members")) == 0:
            plugin.add_output_data("UNKNOWN", "No informations about the iLO network interfaces found.")
            return

    for manager_nic_member in view_response.get("ILOInterfaces") or manager_nic_response.get("Members"):

        if manager_nic_member.get("@odata.context"):
            manager_nic = manager_nic_member
        else:
            manager_nic = plugin.rf.get(manager_nic_member.get("@odata.id"))

        nic_status = manager_nic.get("Status")

        if nic_status is None or nic_status.get("State") is None:
            continue

        if nic_status.get("State") == "Disabled":
            continue

        # workaround for older ILO versions
        if nic_status.get("Health"):
            status = nic_status.get("Health").upper()
        elif nic_status.get("State") == "Enabled":
            status = "OK"
        else:
            status = "UNKNOWN"

        speed = manager_nic.get("SpeedMbps")
        duplex = "full" if manager_nic.get("FullDuplex") is True else "half"
        autoneg = "on" if manager_nic.get("AutoNeg") is True else "off"
        host_name = manager_nic.get("HostName")
        nic_id = manager_nic.get("Id")

        status_text = f"iLO NIC {nic_id} '{host_name}' (speed: {speed}, autoneg: {autoneg}, duplex: {duplex}) status: {status}"

        plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    plugin.add_output_data("OK", f"{ilo_fw_version} ({ilo_license_string} license) all self tests and nics are in 'OK' state.", summary = True)

    return

def get_bmc_info_lenovo(redfish_url):

    global plugin

    manager_response = plugin.rf.get(redfish_url)

    imm_model = manager_response.get("Model")
    imm_fw_version = manager_response.get("FirmwareVersion")

    summary = True
    if args.detailed is True:
        summary = False

    status_text = f"{imm_model} ({imm_fw_version})"

    # FixMe:
    #   * this has to be retrieved from manager infos,
    #     which chassie(s) this manager is responsible for
    redfish_url = "/redfish/v1/Chassis/1/"

    chassi_response = plugin.rf.get(redfish_url)

    located_data = chassi_response.get("Oem").get(plugin.rf.vendor_dict_key).get("LocatedIn")

    if located_data is not None:
        descriptive_name = located_data.get("DescriptiveName")
        rack = located_data.get("Rack")

        status_text += f" system name: {descriptive_name} ({rack})"

    plugin.add_output_data("OK", status_text, summary=summary)

def get_bmc_firmware_fujitsu(manager_url):

    manager_response = plugin.rf.get(manager_url)

    # get configuration
    iRMCConfiguration_link = manager_response.get("Oem").get(plugin.rf.vendor_dict_key).get("iRMCConfiguration").get("@odata.id")

    iRMCConfiguration = None
    if iRMCConfiguration_link is not None:
        iRMCConfiguration = plugin.rf.get(iRMCConfiguration_link)

    firmware_informations = None
    if iRMCConfiguration is not None:
        firmware_informations = plugin.rf.get(iRMCConfiguration.get("FWUpdate").get("@odata.id"))

    return firmware_informations

def get_bmc_info_dell_fujitsu(redfish_url):

    global plugin

    manager_response = plugin.rf.get(redfish_url)

    bmc_model = manager_response.get("Model")
    bmc_fw_version = manager_response.get("FirmwareVersion")
    bmc_type = ""

    if plugin.rf.vendor == "Dell":
        bmc_type = "iDRAC "

    status_text = f"{bmc_type}{bmc_model} ({bmc_fw_version})"

    status = manager_response.get("Status").get("Health").upper()

    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    # BMC Network interfaces
    manager_nic_response = None
    if manager_response.get("EthernetInterfaces"):
        manager_nic_response = plugin.rf.get(manager_response.get("EthernetInterfaces").get("@odata.id") + "%s" % plugin.rf.vendor_data.expand_string)

    if manager_nic_response is not None:

        if manager_nic_response.get("Members") is None or len(manager_nic_response.get("Members")) == 0:
            status_text = f"{status_text} but no informations about the iDRAC network interfaces found"
        else:

            for manager_nic_member in manager_nic_response.get("Members"):

                if manager_nic_member.get("@odata.context"):
                    manager_nic = manager_nic_member
                else:
                    manager_nic = plugin.rf.get(manager_nic_member.get("@odata.id"))

                nic_status = manager_nic.get("Status")

                if nic_status is None or nic_status.get("State") is None:
                    continue

                if nic_status.get("State") == "Disabled":
                    continue

                if nic_status.get("Health"):
                    status = nic_status.get("Health").upper()
                elif nic_status.get("State") == "Enabled":
                    status = "OK"
                else:
                    status = "UNKNOWN"

                speed = manager_nic.get("SpeedMbps")
                duplex = manager_nic.get("FullDuplex")
                autoneg = manager_nic.get("AutoNeg")
                host_name = manager_nic.get("HostName")
                nic_id = manager_nic.get("Id")
                ip_address = manager_nic.get("IPv4Addresses")[0].get("Address")

                if duplex is not None:
                    duplex = "full" if duplex is True else "half"
                if autoneg is not None:
                    autoneg = "on" if autoneg is True else "off"

                status_text = f"NIC {nic_id} '{host_name}' ({ip_address}) (speed: {speed}, autoneg: {autoneg}, duplex: {duplex}) status: {status}"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    # get running firmware informations from Fujitsu server
    if plugin.rf.vendor == "Fujitsu":

        # get configuration
        iRMCConfiguration_link = manager_response.get("Oem").get(plugin.rf.vendor_dict_key).get("iRMCConfiguration").get("@odata.id")

        iRMCConfiguration = None
        if iRMCConfiguration_link is not None:
            iRMCConfiguration = plugin.rf.get(iRMCConfiguration_link)

        license_informations = None
        if iRMCConfiguration is not None:
            license_informations = plugin.rf.get(iRMCConfiguration.get("Licenses").get("@odata.id"))

        irmc_firmware_informations = get_bmc_firmware_fujitsu(redfish_url)
        if irmc_firmware_informations is not None:
            for bmc_fw_bank in [ "iRMCFwImageHigh", "iRMCFwImageLow" ]:
                fw_info = irmc_firmware_informations.get(bmc_fw_bank)
                if fw_info is not None:
                    plugin.add_output_data("OK", "Firmware: State: %s, Booter: %s, SDDR: %s (%s), Date: %s" % (
                        fw_info.get("FirmwareRunningState"),
                        fw_info.get("BooterVersion"),
                        fw_info.get("SDRRVersion"),
                        fw_info.get("SDRRId"),
                        fw_info.get("FirmwareBuildDate")
                        )
                    )

        if license_informations is not None and license_informations.get("Keys@odata.count") > 0:
            licenses = list()
            for bmc_license in license_informations.get("Keys"):
                licenses.append("%s (%s)" % ( bmc_license.get("Name"), bmc_license.get("Type")))

            if len(licenses) > 0:
                plugin.add_output_data("OK", "Licenses: %s" % ", ".join(licenses))

    plugin.add_output_data("OK", f"{bmc_type}{bmc_model} ({bmc_fw_version}) and nics are in 'OK' state.", summary = True)

def get_bmc_info_huawei(redfish_url):

    global plugin

    summary = True
    if args.detailed is True:
        summary = False

    manager_response = plugin.rf.get(f"{redfish_url}/" + plugin.rf.vendor_data.expand_string)

    ibmc_model = manager_response.get("Model")
    ibmc_fw_version = manager_response.get("FirmwareVersion")

    # get general informations
    vendor_ibmc_data = manager_response.get("Oem").get(plugin.rf.vendor_dict_key)
    ibmc_uptime = vendor_ibmc_data.get("BMCUpTime")
    ibmc_ipv4 = vendor_ibmc_data.get("DeviceIPv4")
    ibmc_ipv6 = vendor_ibmc_data.get("DeviceIPv6")
    ibmc_hostname = vendor_ibmc_data.get("HostName")
    ibmc_domainname = vendor_ibmc_data.get("DomainName")
    ibmc_location = vendor_ibmc_data.get("DeviceLocation")

    ibmc_license_link = vendor_ibmc_data.get("LicenseService")
    ibmc_license_status = None
    ibmc_license_class = None

    if ibmc_license_link is not None and len(ibmc_license_link) > 0:
        ibmc_license_informations = plugin.rf.get(ibmc_license_link.get("@odata.id"))

        ibmc_license_status = ibmc_license_informations.get("InstalledStatus")
        ibmc_license_class = ibmc_license_informations.get("LicenseClass")

    status_text = f"{ibmc_model} ({ibmc_fw_version})"

    if ibmc_hostname is not None:
        status_text += f" {ibmc_hostname}"
        if ibmc_domainname is not None and len(ibmc_domainname) > 0:
            status_text += f".{ibmc_domainname}"

    if ibmc_ipv4 and len(ibmc_ipv4) > 0:
        status_text += f" IPv4: {ibmc_ipv4}"
    if ibmc_ipv6 and len(ibmc_ipv6) > 0:
        status_text += f" IPv6: {ibmc_ipv6}"

    if ibmc_location and len(ibmc_location) > 0:
        status_text += f" Location: {ibmc_location}"

    if ibmc_license_status and ibmc_license_class:
        status_text += f" License: {ibmc_license_class} (status: {ibmc_license_status})"

    status = manager_response.get("Status").get("Health").upper()

    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text, summary = summary)

def get_basic_system_info():

    global plugin

    basic_infos = plugin.rf.connection.root
    vendor_string = ""

    if basic_infos.get("Oem"):

        if len(basic_infos.get("Oem")) > 0:
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
                plugin.rf.vendor_data.view_supported = True

        if vendor_string in ["Lenovo"]:
            plugin.rf.vendor = "Lenovo"

            plugin.rf.vendor_data = VendorLenovoData()

        if vendor_string in ["Dell"]:
            plugin.rf.vendor = "Dell"

            plugin.rf.vendor_data = VendorDellData()

        if vendor_string in ["Huawei"]:
            plugin.rf.vendor = "Huawei"

            plugin.rf.vendor_data = VendorHuaweiData()

        if vendor_string in ["ts_fujitsu"]:
            plugin.rf.vendor = "Fujitsu"

            plugin.rf.vendor_data = VendorFujitsuData()

    if plugin.rf.vendor_data is None:
        if vendor_string is None:
            plugin.rf.vendor = "Generic"
        else:
            plugin.rf.vendor = vendor_string

        plugin.rf.vendor_data = VendorGeneric()

    return

def discover_system_properties():

    global plugin

    if vars(plugin.rf.connection).get("system_properties") is not None:
        return

    system_properties = dict()

    root_objects = [ "Chassis", "Managers", "Systems" ]

    for root_object in root_objects:
        if plugin.rf.connection.root.get(root_object) is None:
            continue

        rf_path = plugin.rf.get(plugin.rf.connection.root.get(root_object).get("@odata.id"))

        if rf_path is None:
            continue

        system_properties[root_object.lower()] = list()
        for entity in rf_path.get("Members"):

            # ToDo:
            #  * This is a DELL workaround
            #  * If RAID chassi is requested the iDRAC will restart
            if "RAID" not in entity.get("@odata.id"):
                system_properties[root_object.lower()].append(entity.get("@odata.id"))

    plugin.rf.connection.system_properties = system_properties
    plugin.rf.save_session_to_file()

    return

if __name__ == "__main__":
    # start here
    args = parse_command_line()

    if args.verbose:
        # initialize logger
        logging.basicConfig(level="DEBUG", format='%(asctime)s - %(levelname)s: %(message)s')

    # initialize plugin object
    plugin = PluginData(args)

    # try to get systems, managers and chassis IDs
    discover_system_properties()

    # get basic informations
    get_basic_system_info()

    if "power"      in args.requested_query: get_chassi_data("power")
    if "temp"       in args.requested_query: get_chassi_data("temp")
    if "fan"        in args.requested_query: get_chassi_data("fan")
    if "proc"       in args.requested_query: get_system_data("procs")
    if "memory"     in args.requested_query: get_system_data("mem")
    if "nic"        in args.requested_query: get_system_data("nics")
    if "storage"    in args.requested_query: get_storage()
    if "bmc"        in args.requested_query: get_bmc_info()
    if "info"       in args.requested_query: get_system_info()
    if "firmware"   in args.requested_query: get_firmware_info()
    if "mel"        in args.requested_query: get_event_log("Manager")
    if "sel"        in args.requested_query: get_event_log("System")

    plugin.do_exit()

# EOF
