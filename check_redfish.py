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

__version__ = "0.0.11"
__version_date__ = "2020-02-11"
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

# inventory definition
inventory_version_string = "0.1"
drive_attributes = [ "id", "name", "serial", "type", "speed", "status", "bay"]
processor_attributes = [ "id", "name", "serial"]
ps_attributes = [ "id", "name", "last_power_output", "part_number", "model", "health_status", "operation_status",
                  "bay", "model", "vendor", "serial", "firmware", "type", "capacity_in_watt", "input_voltage" ]

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

        if self.username is not None or self.password is not None:
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
            if redfish_response.status == 401:
                self.get_credentials()
                if self.username is None or self.password is None:
                    self.exit_on_error(f"Username and Password needed to connect to this BMC")

            if redfish_response.status != 404 and redfish_response.status >= 400 and self.session_was_restored is True:

                # reset connection
                self.init_connection(reset = True)

                # query again
                redfish_response = self._rf_get(redfish_path)

            # test if response is valid json and can be decoded
            try:
                redfish_response_json_data = redfish_response.dict
            except Exception:
                redfish_response_json_data = dict({ "Members": list()})

            if args.verbose:
                pprint.pprint(redfish_response_json_data)

            if redfish_response_json_data.get("error"):
                error = redfish_response_json_data.get("error").get("@Message.ExtendedInfo")
                self.exit_on_error("got error '%s' for API path '%s'" % (error[0].get("MessageId"), error[0].get("MessageArgs")))

            self.__cached_data[redfish_path] = redfish_response_json_data

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
            if redfish_response.status != 404 and redfish_response.status >= 400 and self.session_was_restored is True:

                # reset connection
                self.init_connection(reset = True)

                # query again
                redfish_response = self._rf_post("/redfish/v1/Views/", self.vendor_data.view_select)

            # test if response is valid json and can be decoded
            redfish_response_json_data = None
            try:
                redfish_response_json_data = redfish_response.dict
            except Exception:
                pass

            if redfish_response_json_data is not None:
                if args.verbose:
                    pprint.pprint(redfish_response_json_data)

                if redfish_response_json_data.get("error"):
                    error = redfish_response_json_data.get("error").get("@Message.ExtendedInfo")
                    self.exit_on_error("get error '%s' for API path '%s'" % (error[0].get("MessageId"), error[0].get("MessageArgs")))

                self.vendor_data.view_response = redfish_response_json_data

                return self.vendor_data.view_response

        if redfish_path is not None:
            return self.get(redfish_path)

        return None

class PluginData():

    rf = None
    inventory = None

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

        if args.inventory is True and self.inventory is not None:
            print(self.inventory.to_json())
        else:
            print(self.return_output_data())

        exit(self.get_return_status(True))

class InventoryItem(object):
    """

    """
    valid_attributes = None
    init_done = False

    def __init__(self, **kwargs):
        for attribute in self.valid_attributes:
            #super().__setattr__(attribute, None)
            setattr(self, attribute, None)

        self.init_done = True

        for k,v in kwargs.items():
            setattr(self, k, v)

    def to_dict(self):
        output = self.__dict__
        del output["init_done"]

        return output

    def __setattr__(self, key, value):
        if self.init_done is True and key not in self.valid_attributes:
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, key))

        if isinstance(value, str):
            value = value.strip()

            def is_int(v):
                return v=='0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()

            def is_float(v):
                try:     i = float(v)
                except:  return False
                return True

            if is_int(value):
                value = int(value)

            elif is_float(value):
                value = float(value)

            if value.upper in status_types.keys():
                value = value.upper()

        super().__setattr__(key, value)

class Drive(InventoryItem):
    valid_attributes = drive_attributes

class Processor(InventoryItem):
    valid_attributes = processor_attributes

class PowerSupply(InventoryItem):
    valid_attributes = ps_attributes

class Inventory(object):
    """

    """
    base_structure = dict()

    inventory_start = None

    valid_classes = {
        "drives": Drive,
        "processors": Processor,
        "power_supplies": PowerSupply
    }

    def __init__(self):
        for attribute_name, _ in self.valid_classes.items():
            self.base_structure[attribute_name] = list()

        # set metadata
        self.inventory_start = datetime.datetime.utcnow()

    def add(self, object):

        added_successfully = False

        for attribute_name, class_definition in self.valid_classes.items():
            if isinstance(object, class_definition):
                self.base_structure[attribute_name].append(object.to_dict())
                added_successfully = True

        if added_successfully is False:
            raise AttributeError("'%s' object not allowed to add to a '%s' class item." %
                                 (object.__class__.__name__, InventoryItem.__name__))

    def to_json(self):
        inventory_content = self.base_structure

        # add metadata
        inventory_content["meta"] = {
            "start_of_data_collection": self.inventory_start.replace(tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat(),
            "duration_of_data_colection_in_seconds": (datetime.datetime.utcnow() - self.inventory_start).total_seconds(),
            "format_version": inventory_version_string
        }

        output = { "inventory": inventory_content }

        return json.dumps(output, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

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

class VendorCiscoData():

    view_supported = False
    view_select = None

    expand_string = ""

class VendorGeneric():

    view_supported = False
    view_select = None

    expand_string = ""

def grab(structure=None, path=None, separator="."):
    """
        get data from a complex object/json structure with a
        "." separated path information. If a part of a path
        is not not present then this function returns "None".

        example structure:
            data_stracture = {
              "rows": [{
                "elements": [{
                  "distance": {
                    "text": "94.6 mi",
                    "value": 152193
                  },
                  "status": "OK"
                }]
              }]
            }

        example path:
            "rows.0.elements.0.distance.value"

        example return value:
            15193


        Parameters
        ----------
        structure: dict, list
            object structure to extract data from
        path: str
            nested path to extract
        separator: str
            path separator to use. Helpful if a path element
            contains the default (.) separator.

        Returns
        -------
        str, dict, list
            the desired path element if found, otherwise None

    """

    max_recursion_level = 100

    current_level = 0
    levels = len(path.split(separator))

    if structure is None or path is None:
        return None

    def traverse(r_structure, r_path):
        nonlocal current_level
        current_level += 1

        if current_level > max_recursion_level:
            logging.debug(f"Max recursion level ({max_recursion_level}) reached. Returning None.")
            return None

        for attribute in r_path.split(separator):
            if isinstance(r_structure, dict):
                r_structure = {k.lower(): v for k, v in r_structure.items()}
            try:
                if isinstance(r_structure, list):
                    data = r_structure[int(attribute)]
                else:
                    data = r_structure.get(attribute.lower())
            except Exception:
                return None

            if current_level == levels:
                return data
            else:
                return traverse(data, separator.join(r_path.split(separator)[1:]))

    return traverse(structure, path)

def get_status_data(status_data=None):
    """
        Some vendors provide incomplete status information
        This function is meant to parse a status structure
        and return a sanitized representation.

        Parameters
        ----------
        status_data: str, dict
            the status structure to parse

        Returns
        -------
        dict
            a unified representation of status data
            as defined in "return_data" var
    """

    return_data = {
        "Health": None,
        "HealthRollup": None,
        "State": None
    }

    """
        If it's just a string then try to check if it's one of the valid
        status types and add it as "Health" otherwise fill State
    """
    if isinstance(status_data, str):
        if status_data.upper() in status_types.keys():
            return_data["Health"] = status_data.upper()
        else:
            return_data["State"] = status_data

    # If status data is a dict then try to match the keys case insensitive.
    elif isinstance(status_data, dict):
        for status_key, status_value in status_data.items():
            for key in return_data.keys():
                if status_key.lower() == key.lower():
                    if status_value is not None and \
                       key.lower().startswith("health") and \
                       status_value.upper() in status_types.keys():
                        status_value = status_value.upper()
                    return_data[key] = status_value

    return return_data

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
    group.add_argument("-i", "--inventory",  action='store_true',
                        help="return inventory in json format instead of regular plugin output")

    # require at least one argument
    group = parser.add_argument_group(title="query status/health information (at least one is required)")
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
    group.add_argument("--all", dest="requested_query", action='append_const', const="all",
                        help="request all of the above information at once.")

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

    chassis = grab(plugin.rf.connection.system_properties, "chassis")

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

    power_data = plugin.rf.get_view(redfish_url)

    power_supplies = power_data.get("PowerSupplies")

    default_text = ""
    ps_num = 0
    ps_absent = 0
    if power_supplies:
        for ps in power_supplies:

            ps_num += 1

            status_data = get_status_data(grab(ps,"Status"))

            health = status_data.get("Health")
            operatinal_status = status_data.get("State")
            part_number = ps.get("PartNumber")
            model = ps.get("Model") or part_number
            last_power_output = ps.get("LastPowerOutputWatts")
            bay = None

            oem_data = ps.get("Oem")

            if oem_data is not None:

                if plugin.rf.vendor == "HPE":
                    bay = grab(oem_data, f"{plugin.rf.vendor_dict_key}.BayNumber")
                    ps_hp_status = grab(oem_data, f"{plugin.rf.vendor_dict_key}.PowerSupplyStatus.State")
                    if ps_hp_status is not None and ps_hp_status == "Unknown":
                        health = "CRITICAL"

                elif plugin.rf.vendor == "Lenovo":
                    bay = grab(oem_data, f"{plugin.rf.vendor_dict_key}.Location.Info")

                elif plugin.rf.vendor == "Huawei":
                    last_power_output = grab(oem_data, f"{plugin.rf.vendor_dict_key}.PowerInputWatts")

            if bay is None:
                bay = ps_num

            plugin.inventory.add(PowerSupply(
                model = model,
                bay = bay,
                health_status = health,
                operation_status = operatinal_status,
                last_power_output = last_power_output,
                serial = ps.get("SerialNumber"),
                type = ps.get("PowerSupplyType"),
                capacity_in_watt = ps.get("PowerCapacityWatts"),
                firmware = ps.get("FirmwareVersion"),
                vendor = ps.get("Manufacturer"),
                input_voltage = ps.get("LineInputVoltage"),
                part_number = ps.get("SparePartNumber") or ps.get("PartNumber"),
                id = ps.get("MemberId"),
                name = ps.get("Name")
            ))

            printed_status = health
            printed_model = ""

            if health is None:
                printed_status = operatinal_status
                if operatinal_status == "Absent":
                    health = "OK"
                    ps_absent += 1
                if operatinal_status == "Enabled":
                    health = "OK"

            if model is not None:
                printed_model = "(%s) " % model.strip()

            status_text = "Power supply {bay} {model}status is: {status}".format(
                bay=str(bay), model=printed_model, status=printed_status)

            plugin.add_output_data("CRITICAL" if health not in ["OK", "WARNING"] else health, status_text)

            if last_power_output is not None:
                plugin.add_perf_data(f"ps_{bay}", int(last_power_output))

        default_text = "All power supplies (%d) are in good condition" % ( ps_num - ps_absent )

    else:
        plugin.add_output_data("UNKNOWN", f"No power supply data returned for API URL '{redfish_url}'")

    # get PowerRedundancy status
    power_redundancies = power_data.get("PowerRedundancy")
    if power_redundancies is None:
        power_redundancies = power_data.get("Redundancy")

    if power_redundancies:
        pr_status_summary_text = ""
        pr_num = 0
        for power_redundancy in power_redundancies:

            pr_status = power_redundancy.get("Status")

            if pr_status is not None:
                status = pr_status.get("Health")
                state = pr_status.get("State")

                if status is not None:
                    pr_num += 1
                    status = status.upper()

                    status_text = f"Power redundancy {pr_num} status is: {state}"

                    pr_status_summary_text += f" {status_text}"

                    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

        if len(pr_status_summary_text) != 0:
            default_text += f" and{pr_status_summary_text}"

    # get Voltages status
    voltages = power_data.get("Voltages")

    if voltages is not None:
        voltages_num = 0
        for voltage in voltages:

            voltage_status = voltage.get("Status")

            if voltage_status is not None:
                status = voltage_status.get("Health")
                state = voltage_status.get("State")
                reading = voltage.get("ReadingVolts")
                name = voltage.get("Name")

                if status is not None:
                    voltages_num += 1
                    status = status.upper()

                    status_text = f"Voltage {name} (status: {status}/{state}): {reading}V"

                    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

                    if reading is not None and name is not None:
                        try:
                            plugin.add_perf_data(f"voltage_{name}", float(reading))
                        except Exception:
                            pass

        if voltages_num > 0:
            default_text += f" and {voltages_num} Voltages are OK"

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

            status_data = get_status_data(grab(temp,"Status"))

            status = status_data.get("Health")
            state = status_data.get("State")

            if state in [ "Absent", "Disabled", "UnavailableOffline" ]:
                continue

            if status is None:
                status = "OK" if state == "Enabled" else state

            name = temp.get("Name").strip()
            current_temp = temp.get("ReadingCelsius")
            critical_temp = temp.get("UpperThresholdCritical")
            warning_temp = temp.get("UpperThresholdNonCritical")

            temp_num += 1

            if current_temp is None:
                current_temp = 0

            if warning_temp is None or str(warning_temp) == "0":
                warning_temp = "N/A"

            if warning_temp != "N/A" and float(current_temp) >= float(warning_temp):
                status = "WARNING"

            if critical_temp is None or str(critical_temp) == "0":
                critical_temp = "N/A"

            if critical_temp != "N/A" and float(current_temp) >= float(critical_temp):
                status = "CRITICAL"

            status_text = f"Temp sensor {name} status is: {status} ({current_temp} °C) (max: {critical_temp} °C)"

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            warning_temp = float(warning_temp) if warning_temp != "N/A" else None
            critical_temp = float(critical_temp) if critical_temp != "N/A" else None

            plugin.add_perf_data(f"temp_{name}", float(current_temp), warning=warning_temp, critical=critical_temp)

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

            status_data = get_status_data(grab(fan,"Status"))

            status = status_data.get("Health")
            state = status_data.get("State")

            if state == "Absent":
                continue

            if status is None:
                status = "OK" if state == "Enabled" else state

            fan_num += 1

            name = fan.get("FanName") or fan.get("Name")

            if fan.get("Oem") is not None:

                if plugin.rf.vendor == "Lenovo":
                    name = grab(fan, f"Oem.{plugin.rf.vendor_dict_key}.Location.Info")

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
    fan_redundancies = plugin.rf.get_view(redfish_url).get("FanRedundancy")
    if fan_redundancies is None:
        fan_redundancies = plugin.rf.get_view(redfish_url).get("Redundancy")

    if fan_redundancies:
        status_text = ""
        for fan_redundancy in fan_redundancies:

            fr_status = get_status_data(fan_redundancy.get("Status"))

            status = fr_status.get("Health")

            if status is not None:
                status_text = "fan redundancy status is: %s" % fr_status.get("State")

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

        proc_status = get_status_data(grab(systems_response, "ProcessorSummary.Status"))

        # DELL is HealthRollUp not HealthRollup
        # Fujitsu is just Health an not HealthRollup
        health = proc_status.get("HealthRollup") or proc_status.get("Health")

        proc_count = grab(systems_response, "ProcessorSummary.Count")
        proc_count_text = ""
        if proc_count is not None:
            proc_count_text = f"({proc_count}) "

        if health == "OK" and args.detailed == False:
            plugin.add_output_data("OK", f"All processors {proc_count_text}are in good condition", summary = True)
            return

    system_response_proc_key = "Processors"
    if systems_response.get(system_response_proc_key) is None:
        plugin.add_output_data("UNKNOWN", f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_proc_key}'")
        return

    processors_link = grab(systems_response, f"{system_response_proc_key}/@odata.id", separator="/")

    processors_response = plugin.rf.get_view(f"{processors_link}{plugin.rf.vendor_data.expand_string}")

    if processors_response.get("Members") is not None or processors_response.get(system_response_proc_key) is not None:

        num_procs = 0
        for proc in processors_response.get("Members") or processors_response.get(system_response_proc_key):

            if proc.get("@odata.context"):
                proc_response = proc
            else:
                proc_response = plugin.rf.get(proc.get("@odata.id"))

            if proc_response.get("Id"):

                proc_status = get_status_data(proc_response.get("Status"))

                if proc_status.get("State") == "Absent":
                    continue

                num_procs += 1

                socket = proc_response.get("Socket")
                model =  proc_response.get("Model").strip()

                status = proc_status.get("Health")

                status_text = f"Processor {socket} ({model}) status is: {status}"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No processor data returned for API URL '%s'" % proc_response.get("@odata.id"))

        if args.detailed == False:
            plugin.add_output_data("OK", "All processors (%d) are in good condition" % num_procs, summary = True)
    else:
        plugin.add_output_data("UNKNOWN", f"No processor data returned for API URL '{redfish_url}'")

    return

def get_single_system_mem(redfish_url):

    global plugin

    plugin.set_current_command("Mem")

    systems_response = plugin.rf.get(redfish_url)

    if systems_response.get("MemorySummary"):

        health = None
        need_details = False

        memory_status = get_status_data(grab(systems_response, "MemorySummary.Status"))

        # DELL is HealthRollUp not HealthRollup
        # Fujitsu is just Health an not HealthRollup
        health = memory_status.get("HealthRollup") or memory_status.get("Health")

        if health == "OK" and args.detailed == False:

            total_mem = grab(systems_response, "MemorySummary.TotalSystemMemoryGiB") or 0

            if plugin.rf.vendor == "Dell":
                total_mem = total_mem * 1024 ** 3 / 1000 ** 3

            plugin.add_output_data("OK", "All memory modules (Total %dGB) are in good condition" %
                total_mem, summary = True)
            return

    system_response_memory_key = "Memory"
    if grab(systems_response, f"Oem.{plugin.rf.vendor_dict_key}.Links.{system_response_memory_key}"):
            memory_path_dict = grab(systems_response, f"Oem.{plugin.rf.vendor_dict_key}.Links")
    else:
        memory_path_dict = systems_response

    if memory_path_dict.get(system_response_memory_key) is None:
        plugin.add_output_data("UNKNOWN", f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_memory_key}'")
        return

    redfish_url = memory_path_dict.get(system_response_memory_key).get("@odata.id") + "%s" % plugin.rf.vendor_data.expand_string

    memory_response = plugin.rf.get_view(redfish_url)

    num_dimms = 0
    size_sum = 0

    if memory_response.get("Members") or memory_response.get(system_response_memory_key):

        for mem_module in memory_response.get("Members") or memory_response.get(system_response_memory_key):

            if mem_module.get("@odata.context"):
                mem_module_response = mem_module
            else:
                mem_module_response = plugin.rf.get(mem_module.get("@odata.id"))

            if mem_module_response.get("Id"):

                # get size
                size = mem_module_response.get("SizeMB") or mem_module_response.get("CapacityMiB") or 0

                size = int(size)
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
                module_status = get_status_data(mem_module_response.get("Status"))
                status = module_status.get("Health")
                state = module_status.get("State")

                if plugin.rf.vendor == "HPE" and grab(mem_module_response, f"Oem.{plugin.rf.vendor_dict_key}.DIMMStatus"):
                    status = grab(mem_module_response, f"Oem.{plugin.rf.vendor_dict_key}.DIMMStatus")

                elif mem_module_response.get("DIMMStatus"):

                    status = mem_module_response.get("DIMMStatus")

                if status in [ "Absent", "NotPresent"] or state in [ "Absent", "NotPresent"]:
                    continue

                if status is None and state is not None:
                    status = state

                num_dimms += 1
                size_sum += size
                status_text = f"Memory module {name} ({size}GB) status is: {status}"

                if status in [ "GoodInUse", "Operable"]:
                    status = "OK"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No memory data returned for API URL '%s'" % mem_module.get("@odata.id"))

    if num_dimms == 0:
        plugin.add_output_data("UNKNOWN", f"No memory data returned for API URL '{redfish_url}'")
    else:
        plugin.add_output_data("OK", f"All {num_dimms} memory modules (Total {size_sum}GB) are in good condition", summary = True)

    return

def get_system_nics_fujitsu(redfish_url):

    global plugin

    plugin.set_current_command("NICs")

    redfish_url = f"{redfish_url}/NetworkInterfaces{plugin.rf.vendor_data.expand_string}"

    nics_response = plugin.rf.get(redfish_url)

    num_nic_ports = 0

    if nics_response.get("Members") and len(nics_response.get("Members")) > 0:

        for nic in nics_response.get("Members"):

            if nic.get("Id") is not None:
                nic_member = nic
            else:
                nic_member = plugin.rf.get(nic.get("@odata.id"))

            nic_id = nic_member.get("Id")

            # network functions
            if nic_member.get("NetworkDeviceFunctions") is not None:
                network_functions_link = grab(nic_member, "NetworkDeviceFunctions/@odata.id", separator="/")
            else:
                network_functions_link = grab(nic_member, "Links/NetworkAdapter/@odata.id", separator="/")

            network_functions = plugin.rf.get(f"{network_functions_link}{plugin.rf.vendor_data.expand_string}")

            # network ports
            network_ports = plugin.rf.get("%s%s" % (grab(nic_member, "NetworkPorts/@odata.id", separator="/"), plugin.rf.vendor_data.expand_string))

            for network_function in network_functions.get("Members"):

                if network_function.get("Id") is not None:
                    network_function_member = network_function
                else:
                    network_function_member = plugin.rf.get(network_function.get("@odata.id"))

                # get port
                network_port_link = network_function_member.get("PhysicalPortAssignment")
                if network_port_link is None:
                    network_port_link = grab(network_function_member, "Links.PhysicalPortAssignment")

                network_port_data = None
                for network_port in network_ports.get("Members"):
                    if network_port.get("@odata.id") == network_port_link.get("@odata.id"):

                        if network_port.get("Id"):
                            network_port_data = network_port
                        else:
                            network_port_data = plugin.rf.get(network_port.get("@odata.id"))
                        break

                num_nic_ports += 1

                nic_name = network_function_member.get("Name")
                nic_dev_func_type = network_port_data.get("ActiveLinkTechnology")
                nic_port_current_speed = network_port_data.get("CurrentLinkSpeedMbps")
                nic_port_link_status = network_port_data.get("LinkStatus")
                if network_port_data.get("PhysicalPortNumber"):
                    nic_port_name = "Port " + network_port_data.get("PhysicalPortNumber")
                else:
                    nic_port_name = network_port_data.get("Name")

                nic_port_address = network_function_member.get("Ethernet")
                if nic_port_address is not None:
                    nic_port_address = nic_port_address.get("PermanentMACAddress")

                # get health status
                nic_health_status = get_status_data(network_port_data.get("Status"))

                # ignore interface if state is not Enabled
                if nic_health_status.get("State") != "Enabled":
                    continue

                if nic_port_current_speed is None:
                    nic_port_current_speed = grab(network_port_data, "SupportedLinkCapabilities.0.LinkSpeedMbps")

                nic_capable_speed = grab(network_port_data, "SupportedLinkCapabilities.0.CapableLinkSpeedMbps.0")

                status_text = f"NIC {nic_id} ({nic_name}) {nic_port_name} (Type: {nic_dev_func_type}, Speed: {nic_port_current_speed}/{nic_capable_speed}, MAC: {nic_port_address}) status: {nic_port_link_status}"
                plugin.add_output_data("CRITICAL" if nic_health_status.get("Health") not in ["OK", "WARNING"] else nic_health_status.get("Health"), status_text)

    if num_nic_ports == 0:
        plugin.add_output_data("UNKNOWN", f"No network interface data returned for API URL '{redfish_url}'")

    plugin.add_output_data("OK", f"All network interfaces ({num_nic_ports}) are in good condition", summary = True)

    return

def get_single_system_nics(redfish_url):

    global plugin

    plugin.set_current_command("NICs")

    redfish_url = f"{redfish_url}/EthernetInterfaces/{plugin.rf.vendor_data.expand_string}"

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

                nic_status = get_status_data(nic_response.get("Status"))
                status = nic_status.get("Health") or "Undefined"
                link_status = nic_response.get("LinkStatus")

                status_text = f"NIC {id} status is: {status}"

                if status == "Undefined":
                    status = "OK"

                if link_status is not None and link_status != "NoLink":
                    status_text += f" and link status is '{link_status}'"

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

            status = get_status_data(disk_response.get("Status")).get("Health")
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

            status = get_status_data(logical_drive_response.get("Status")).get("Health")
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

            status = get_status_data(enclosure_response.get("Status")).get("Health")
            location = enclosure_response.get("Location")

            status_text = f"StorageEnclosure ({location}) Status: {status}"

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    global plugin

    plugin.set_current_command("Storage")

    redfish_url = f"{system}/SmartStorage/"

    storage_response = plugin.rf.get(redfish_url)

    storage_status = get_status_data(storage_response.get("Status"))
    status = storage_status.get("Health")

    if status == "OK" and args.detailed == False:
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
                fw_version = grab(controller_response, "FirmwareVersion.Current.VersionString")
                controller_status = get_status_data(controller_response.get("Status"))

                if controller_status.get("State") == "Absent":
                    continue

                status = controller_status.get("Health")

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

def get_storage_generic(system):

    def get_drive(drive_link):

        drive_response = plugin.rf.get(drive_link)

        if drive_response.get("Name") is None:
            plugin.add_output_data("UNKNOWN", f"Unable to retrieve disk infos: {drive_link}")
            return

        name = drive_response.get("Name")
        model = drive_response.get("Model")
        type = drive_response.get("MediaType")
        protocol = drive_response.get("Protocol")
        size = drive_response.get("CapacityBytes")

        if name is not None:
            name = name.strip()

        location = grab(drive_response, "Location.0.Info") or grab(drive_response, "PhysicalLocation.0.Info")
        if location is None or name == location:
            location = ""
        else:
            location = f"{location} "

        status = get_status_data(drive_response.get("Status")).get("Health")

        if status is not None:
            drives_status_list.append(status)

        if size is not None and size > 0:
            size = "%0.2fGiB" % (size / ( 1000 ** 3))
        else:
            size = "0GiB"

        status_text = f"Physical Drive {name} {location}({model} / {type} / {protocol}) {size} status: {status}"

        plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)

    def get_volumes(volumes_link):

        volumes_response = plugin.rf.get(volumes_link)

        if len(volumes_response.get("Members")) == 0:
            return

        for volume_member in volumes_response.get("Members"):

            volume_data = plugin.rf.get(volume_member.get("@odata.id"))

            if volume_data.get("Name") is None:
                continue

            name = volume_data.get("Name")
            status = get_status_data(volume_data.get("Status")).get("Health")

            if status is not None:
                volume_status_list.append(status)

            size = volume_data.get("CapacityBytes") or 0
            size = int(size) / ( 1000 ** 3)

            raid_level = volume_data.get("VolumeType")
            volume_name = volume_data.get("Description")

            oem_data = grab(volume_data, f"Oem.{plugin.rf.vendor_dict_key}")
            if oem_data is not None:
                if plugin.rf.vendor == "Huawei":
                    raid_level = oem_data.get("VolumeRaidLevel")
                    volume_name = oem_data.get("VolumeName")

                if plugin.rf.vendor in ["Fujitsu", "Lenovo"]:
                    raid_level = oem_data.get("RaidLevel")
                    volume_name = oem_data.get("Name")

            status_text = "Logical Drive %s (%s) %.0fGiB (%s) Status: %s" % (name, volume_name, size, raid_level, status)

            plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)

    def get_enclosures(enclosure_link):

        # skip chassis listed as enclosures
        if enclosure_link in plugin.rf.connection.system_properties.get("chassis"):
            return

        enclosures_response = plugin.rf.get(enclosure_link)

        if enclosures_response.get("Name") is None:
            plugin.add_output_data("UNKNOWN", f"Unable to retrieve enclosure infos: {enclosure_link}")
            return

        name = enclosures_response.get("Name")
        chassis_type = enclosures_response.get("ChassisType")
        power_state = enclosures_response.get("PowerState")
        status = get_status_data(enclosures_response.get("Status")).get("Health")

        if status is not None:
            enclosure_status_list.append(status)

        status_text = f"{chassis_type} {name} (Power: {power_state}) Status: {status}"

        plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)

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

    system_response = plugin.rf.get(system)

    storage_response = None

    storage_link = grab(system_response, "Storage/@odata.id", separator="/")
    if storage_link is not None:
        storage_response = plugin.rf.get(f"{storage_link}{plugin.rf.vendor_data.expand_string}")

    system_drives_list = list()
    drives_status_list = list()
    storage_controller_names_list = list()
    storage_controller_id_list = list()
    storage_status_list = list()
    volume_status_list = list()
    enclosure_status_list = list()

    if storage_response is not None:

        for storage_member in storage_response.get("Members"):

            if storage_member.get("@odata.context"):
                controller_response = storage_member
            else:
                controller_response = plugin.rf.get(storage_member.get("@odata.id"))

            if controller_response.get("StorageControllers"):

                # if StorageControllers is just a dict then wrap it in a list (like most vendors do it)
                if isinstance(controller_response.get("StorageControllers"), dict):
                    controller_response["StorageControllers"] = [ controller_response.get("StorageControllers") ]

                for storage_controller in controller_response.get("StorageControllers"):
                    name = storage_controller.get("Name")
                    model = storage_controller.get("Model")
                    fw_version = storage_controller.get("FirmwareVersion")
                    location = grab(storage_controller, f"Oem.{plugin.rf.vendor_dict_key}.Location.Info")
                    controller_status = get_status_data(storage_controller.get("Status"))

                    controller_oem_data = grab(storage_controller, f"Oem.{plugin.rf.vendor_dict_key}")

                    model = grab(controller_oem_data, "Type") or model

                    # ignore absent controllers
                    if controller_status.get("State") == "Absent":
                        continue

                    status = controller_status.get("Health")

                    if status is not None:
                        storage_status_list.append(status)

                    storage_controller_names_list.append(f"{name} {model}")
                    storage_controller_id_list.append(controller_response.get("@odata.id"))

                    if location is None:
                        location = ""
                    else:
                        location = f"{location} "

                    status_text = f"{name} {model} {location}(FW: {fw_version}) status is: {status}"

                    plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)

                    if grab(controller_oem_data, "CapacitanceStatus") is not None:
                        cap_model = controller_oem_data.get("CapacitanceName")
                        cap_status = get_status_data(controller_oem_data.get("CapacitanceStatus")).get("Health")
                        cap_fault_details = controller_oem_data.get("CapacitanceStatus").get("FaultDetails")

                        cap_status_text = f"Controller capacitor ({cap_model}) status: {cap_status}"

                        if cap_status != "OK" and cap_fault_details is not None:
                            cap_status_text += f" : {cap_fault_details}"

                        plugin.add_output_data("CRITICAL" if cap_status not in ["OK", "WARNING"] else cap_status, cap_status_text)

                for controller_drive in controller_response.get("Drives"):
                    system_drives_list.append(controller_drive.get("@odata.id"))
                    get_drive(controller_drive.get("@odata.id"))

                # get volumes
                get_volumes(controller_response.get("Volumes").get("@odata.id"))

                # get enclosures
                enclosure_list = grab(controller_response, "Links.Enclosures")

                if isinstance(enclosure_list, list):

                    for enclosure_link in enclosure_list:
                        if isinstance(enclosure_link, str):
                            get_enclosures(enclosure_link)
                        else:
                            get_enclosures(enclosure_link.get("@odata.id"))
            else:
                plugin.add_output_data("UNKNOWN", "No array controller data returned for API URL '%s'" % controller_response.get("@odata.id"))

    # check SimpleStorage
    simple_storage_link = grab(system_response, "SimpleStorage/@odata.id", separator="/")
    if simple_storage_link is not None:

        simple_storage_response = plugin.rf.get(f"{simple_storage_link}{plugin.rf.vendor_data.expand_string}")

        if simple_storage_response.get("Members") is not None and len(simple_storage_response.get("Members")) > 0:

            for simple_storage_member in simple_storage_response.get("Members"):

                if simple_storage_member.get("@odata.context"):
                    simple_storage_controller_response = simple_storage_member
                else:
                    simple_storage_controller_response = plugin.rf.get(simple_storage_member.get("@odata.id"))

                # this controller has already been checked
                if simple_storage_controller_response.get("@odata.id") in storage_controller_id_list:
                    continue

                status = get_status_data(simple_storage_controller_response.get("Status"))

                if status.get("State") != "Enabled":
                    continue

                if simple_storage_controller_response.get("Devices") is not None and len(simple_storage_controller_response.get("Devices")) > 0:

                    name = simple_storage_controller_response.get("Name")
                    status = status.get("Health")

                    if status is not None:
                        storage_status_list.append(status)

                    storage_controller_names_list.append(f"{name}")

                    status_text = f"{name} status: {status}"
                    plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)

                    for simple_storage_device in simple_storage_controller_response.get("Devices"):
                        name = simple_storage_device.get("Name")
                        manufacturer = simple_storage_device.get("Manufacturer")
                        model = simple_storage_device.get("Model")
                        capacity = simple_storage_device.get("CapacityBytes")
                        status = get_status_data(simple_storage_device.get("Status"))

                        status_text = f"{manufacturer} {name} {model}"

                        if capacity is not None:
                            try:
                                status_text += " (size: %0.2f GiB)" % (int(capacity) / 1000 ** 3)
                            except Exception:
                                pass

                        # skip device if state is not "Enabled"
                        if status.get("State") != "Enabled":
                            continue

                        status = status.get("Health")

                        if status is not None:
                            drives_status_list.append(status)

                        status_text += f" status: {status}"

                        plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)

                else:
                    continue

    # check additional drives
    system_drives = grab(system_response, f"Oem.{plugin.rf.vendor_dict_key}.StorageViewsSummary.Drives")

    if system_drives is not None:
        for system_drive in system_drives:
            drive_url = grab(system_drive, "Link/@odata.id", separator="/")
            if drive_url not in system_drives_list:
                system_drives_list.append(drive_url)
                get_drive(drive_url)

    condensed_storage_status = condensed_status_from_list(storage_status_list)
    condensed_drive_status = condensed_status_from_list(drives_status_list)
    condensed_volume_status = condensed_status_from_list(volume_status_list)
    condensed_enclosure_status = condensed_status_from_list(enclosure_status_list)

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
            condensed_summary_status = condensed_status_from_list([condensed_storage_status, condensed_drive_status, condensed_volume_status, condensed_enclosure_status])

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

    if type == "System" and plugin.rf.vendor in ["Huawei", "HPE", "Cisco"]:
        property_name = "systems"
    else:
        property_name = "managers"

    if plugin.rf.vendor == "Lenovo":
        property_name = "systems"

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

        else:
            get_event_log_generic(type, system_manager_id)

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
        plugin.add_output_data("OK", f"No {type} log entries found.", summary = not args.detailed)
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

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()
        date = event_entry.get("Created")
        repaired = grab(event_entry, f"Oem.{plugin.rf.vendor_dict_key}.Repaired")

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

def get_event_log_generic(type, system_manager_id):

    global plugin

    limit_of_returned_itmes = args.max
    forced_limit = False
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    redfish_url = None

    # define locations for known vendors
    if type == "System":
        if plugin.rf.vendor == "Dell":
            redfish_url = f"{system_manager_id}/Logs/Sel"
        elif plugin.rf.vendor == "Fujitsu":
            redfish_url = f"{system_manager_id}/LogServices/SystemEventLog/Entries/"
        elif plugin.rf.vendor == "Cisco":
            redfish_url = f"{system_manager_id}/LogServices/SEL/Entries/"
        elif plugin.rf.vendor == "Lenovo":
            redfish_url = f"{system_manager_id}/LogServices/ActiveLog/Entries/"
    else:
        if plugin.rf.vendor == "Dell":
            redfish_url = f"{system_manager_id}/Logs/Lclog"
        elif plugin.rf.vendor == "Fujitsu":
            redfish_url = f"{system_manager_id}/LogServices/InternalEventLog/Entries/"
        elif plugin.rf.vendor == "Cisco":
            redfish_url = f"{system_manager_id}/LogServices/CIMC/Entries/"
        elif plugin.rf.vendor == "Lenovo":
            redfish_url = f"{system_manager_id}/LogServices/StandardLog/Entries/"

    # try to discover log service
    if redfish_url is None:
        system_manager_data = plugin.rf.get(system_manager_id)

        log_services = None
        log_services_link = grab(system_manager_data, "LogServices/@odata.id", separator="/")
        if log_services_link is not None:
            log_services = plugin.rf.get(log_services_link)

        if grab(log_services, "Members") is not None and len(log_services.get("Members")) > 0:

            for log_service in log_services.get("Members"):

                log_service_data = plugin.rf.get(log_service.get("@odata.id"))

                # check if "Name" contains "System" or "Manager"
                if log_service_data.get("Name") is not None and type.lower() in log_service_data.get("Name").lower():

                    if log_service_data.get("Entries") is not None:
                        redfish_url = log_service_data.get("Entries").get("@odata.id")
                        break

    if redfish_url is None:
        plugin.add_output_data("UNKNOWN", f"No log services discoverd in {system_manager_id}/LogServices that match {type}")
        return

    if args.warning:
        date_warning = data_now - datetime.timedelta(days=int(args.warning))
    if args.critical:
        date_critical = data_now - datetime.timedelta(days=int(args.critical))

    event_data = plugin.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin.add_output_data("OK", f"No {type} log entries found.", summary = not args.detailed)
        return

    event_entries = event_data.get("Members")

    assoc_id_status = dict()

    # reverse list from newest to oldest entry
    if plugin.rf.vendor == "Lenovo":
        event_entries.reverse()

    num_entry = 0
    for event_entry_item in event_entries:

        if event_entry_item.get("Id"):
            event_entry = event_entry_item
        else:
            event_entry = plugin.rf.get(event_entry_item.get("@odata.id"))

        message = event_entry.get("Message")

        if message is not None:
            message = message.strip().strip("\n").strip()

        num_entry += 1

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()

        # CISCO WHY?
        if severity in  ["NORMAL", "INFORMATIONAL"]:
            severity = "OK"

        date = event_entry.get("Created")

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00-00:00"

        status = "OK"

        # keep track of message IDs
        # newer message can clear a status for older messages
        if type == "System":

            # get log entry id to associate older log entries
            assoc_id = event_entry.get("SensorNumber")

            # found an old message that has been cleared
            if assoc_id is not None and assoc_id_status.get(assoc_id) == "cleared" and severity != "OK":
                message += " (severity '%s' cleared)" % severity
            elif severity is not None:
                if severity == "WARNING":
                    status = severity
                elif severity != "OK":
                    status = "CRITICAL"

            # keep track of messages that clear an older message
            if event_entry.get("SensorNumber") is not None and severity == "OK":
                assoc_id_status[assoc_id] = "cleared"

        if (date_critical is not None or date_warning is not None) and severity is not None:
            # convert time zone offset from valid ISO 8601 format to python implemented datetime TZ offset
            # from:
            #   2019-11-01T15:03:32-05:00
            # to:
            #   2019-11-01T15:03:32-0500

            entry_date = None
            try:
                entry_date = datetime.datetime.strptime(date[::-1].replace(":","",1)[::-1], "%Y-%m-%dT%H:%M:%S%z")
            except Exception:
                pass

            if entry_date is not None and date_critical is not None:
              if entry_date > date_critical.astimezone(entry_date.tzinfo) and severity != "OK":
                    status = "CRITICAL"
            if entry_date is not None and date_warning is not None:
                if entry_date > date_warning.astimezone(entry_date.tzinfo) and status != "CRITICAL" and severity != "OK":
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

            if event_data.get("Members@odata.nextLink") is not None and len(collected_log_entries_list) != event_data.get("Members@odata.count"):
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

    model = system_response.get("Model")
    vendor_name = system_response.get("Manufacturer")
    serial = system_response.get("SerialNumber")
    system_health_state = get_status_data(system_response.get("Status")).get("Health")
    power_state = system_response.get("PowerState")
    bios_version = system_response.get("BiosVersion")
    host_name = system_response.get("HostName")
    cpu_num = grab(system_response, "ProcessorSummary.Count")
    mem_size = grab(system_response, "MemorySummary.TotalSystemMemoryGiB")

    if vendor_name is not None:
        vendor_name = vendor_name.strip()

    if serial is not None:
        serial = serial.strip()

    if model is not None:
        model = model.strip()

    # Huawei system
    if plugin.rf.vendor == "Huawei":
        model = grab(system_response, f"Oem.{plugin.rf.vendor_dict_key}.ProductName")

    # Dell system
    # just WHY?
    if plugin.rf.vendor == "Dell":
        mem_size = round(mem_size * 1024 ** 3 / 1000 ** 3)

    status = "OK"
    if system_health_state == "WARNING":
        status = "WARNING"
    elif system_health_state != "OK":
        status = "CRITICAL"

    if host_name is not None:
        host_name = host_name.strip()
    else:
        host_name = ""

    # make sure that stripped empty hostname results in something
    host_name = "NOT SET" if host_name == "" else host_name

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
                drive_slot = grab(drive_response, f"Oem.{plugin.rf.vendor_dict_key}.SlotNumber")
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

    if plugin.rf.vendor == "Cisco":
        redfish_url = "/redfish/v1/UpdateService/" + "%s" % plugin.rf.vendor_data.expand_string
    else:
        redfish_url = "/redfish/v1/UpdateService/FirmwareInventory/" + "%s" % plugin.rf.vendor_data.expand_string

    firmware_response = plugin.rf.get(redfish_url)

    if plugin.rf.vendor == "Cisco" and firmware_response.get("FirmwareInventory") is not None:
        firmware_response["Members"] = firmware_response.get("FirmwareInventory")

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
        if component_version is not None:
            component_version = component_version.strip().replace("\n","")

        component_id = None

        if plugin.rf.vendor == "HPE":
            component_id = grab(firmware_entry, f"Oem.{plugin.rf.vendor_dict_key}.DeviceContext")

        if component_id is None:
            component_id = firmware_entry.get("Id")

        plugin.add_output_data("OK", f"{component_name} ({component_id}): {component_version}")

    return

def get_bmc_info():

    global plugin

    plugin.set_current_command("BMC Info")

    managers = plugin.rf.connection.system_properties.get("managers")

    if managers is None or len(managers) == 0:
        plugin.add_output_data("UNKNOWN", "No 'managers' property found in root path '/redfish/v1'")
        return

    for manager in managers:
        if plugin.rf.vendor == "HPE":
            get_bmc_info_hpe(manager)

        elif plugin.rf.vendor == "Lenovo":
            get_bmc_info_lenovo(manager)

        elif plugin.rf.vendor == "Huawei":
            get_bmc_info_huawei(manager)

        else:
            get_bmc_info_generic(manager)

    return

def get_bmc_info_hpe(redfish_url):

    global plugin

    view_response = plugin.rf.get_view(f"{redfish_url}/" + plugin.rf.vendor_data.expand_string)

    if view_response.get("ILO"):
        manager_response = view_response.get("ILO")[0]
    else:
        manager_response = view_response

    # get general informations
    ilo_data = grab(manager_response, f"Oem.{plugin.rf.vendor_dict_key}")

    # firmware
    ilo_firmware = grab(ilo_data, "Firmware.Current")
    ilo_fw_date = ilo_firmware.get("Date")
    ilo_fw_version = ilo_firmware.get("VersionString")

    plugin.add_output_data("OK", f"{ilo_fw_version} ({ilo_fw_date})")

    # license
    ilo_license_string = grab(ilo_data, "License.LicenseString")
    ilo_license_key = grab(ilo_data, "License.LicenseKey")

    plugin.add_output_data("OK", f"Licenses: {ilo_license_string} ({ilo_license_key})")

    # iLO Self Test
    for self_test in ilo_data.get("iLOSelfTestResults"):

        status = self_test.get("Status")

        if status is None or status == "Informational":
            continue

        status = status.upper()

        name = self_test.get("SelfTestName")
        notes = self_test.get("Notes")

        if notes is not None and len(notes) != 0:
            notes = notes.strip()
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

        nic_status = get_status_data(manager_nic.get("Status"))

        if nic_status.get("State") in ["Disabled", None]:
            continue

        # workaround for older ILO versions
        if nic_status.get("Health")is not None:
            status = nic_status.get("Health")
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

    status_text = f"{imm_model} ({imm_fw_version})"

    redfish_url = grab(manager_response, "Links/ManagerForChassis/0/@odata.id", separator="/")

    chassi_response = None
    if redfish_url is not None:
        chassi_response = plugin.rf.get(redfish_url)

    located_data = grab(chassi_response, f"Oem.{plugin.rf.vendor_dict_key}.LocatedIn")

    if located_data is not None:
        descriptive_name = located_data.get("DescriptiveName")
        rack = located_data.get("Rack")

        status_text += f" system name: {descriptive_name} ({rack})"

    plugin.add_output_data("OK", status_text, summary = not args.detailed)

def get_bmc_firmware_fujitsu(manager_url):

    manager_response = plugin.rf.get(manager_url)

    # get configuration
    iRMCConfiguration_link = grab(manager_response, f"Oem/{plugin.rf.vendor_dict_key}/iRMCConfiguration/@odata.id", separator="/")

    iRMCConfiguration = None
    if iRMCConfiguration_link is not None:
        iRMCConfiguration = plugin.rf.get(iRMCConfiguration_link)

    firmware_information = None
    firmware_information_link = grab(iRMCConfiguration, f"FWUpdate/@odata.id", separator="/")
    if firmware_information_link is not None:
        firmware_information = plugin.rf.get(firmware_information_link)

    return firmware_information

def get_bmc_info_generic(redfish_url):

    global plugin

    manager_response = plugin.rf.get(redfish_url)

    bmc_model = manager_response.get("Model")
    bmc_fw_version = manager_response.get("FirmwareVersion")

    bmc_type = "iDRAC " if plugin.rf.vendor == "Dell" else ""

    status_text = f"{bmc_type}{bmc_model} (Firmware: {bmc_fw_version})"

    manager_status = get_status_data(manager_response.get("Status"))
    status = manager_status.get("Health")

    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    # BMC Network interfaces
    manager_nic_response = None
    manager_nics_link = grab(manager_response, "EthernetInterfaces/@odata.id", separator="/")
    if manager_nics_link is not None:
        manager_nic_response = plugin.rf.get(f"{manager_nics_link}{plugin.rf.vendor_data.expand_string}")

    if manager_nic_response is not None:

        if manager_nic_response.get("Members") is None or len(manager_nic_response.get("Members")) == 0:
            status_text = f"{status_text} but no informations about the BMC network interfaces found"
        else:

            for manager_nic_member in manager_nic_response.get("Members"):

                if manager_nic_member.get("@odata.context"):
                    manager_nic = manager_nic_member
                else:
                    manager_nic = plugin.rf.get(manager_nic_member.get("@odata.id"))

                nic_status = manager_nic.get("Status")

                if nic_status is None:
                    nic_status = { "Health": "OK", "State": "Enabled" }

                if nic_status.get("State") in ["Disabled", None]:
                    continue

                if nic_status.get("Health"):
                    status = nic_status.get("Health")
                elif nic_status.get("State") == "Enabled":
                    status = "OK"
                else:
                    status = "UNKNOWN"

                speed = manager_nic.get("SpeedMbps")
                duplex = manager_nic.get("FullDuplex")
                autoneg = manager_nic.get("AutoNeg")
                host_name = manager_nic.get("HostName") or "no hostname set"
                nic_id = manager_nic.get("Id")
                ip_addresses = list()

                # get IPv4 address
                ipv4_address = grab(manager_nic, "IPv4Addresses.Address") or grab(manager_nic, "IPv4Addresses.0.Address")
                if ipv4_address is not None:
                    ip_addresses.append(ipv4_address)

                # get IPv6 address
                ipv6_address  = grab(manager_nic, "IPv6Addresses.Address") or grab(manager_nic, "IPv6Addresses.0.Address")
                if ipv6_address is not None and ipv6_address != "::":
                    ip_addresses.append(ipv6_address)

                ip_addresses_string = None
                if len(ip_addresses) > 0:
                    ip_addresses_string = "/".join(ip_addresses)

                if duplex is not None:
                    duplex = "full" if duplex is True else "half"
                if autoneg is not None:
                    autoneg = "on" if autoneg is True else "off"

                status_text = f"NIC {nic_id} '{host_name}' (IPs: {ip_addresses_string}) (speed: {speed}, autoneg: {autoneg}, duplex: {duplex}) status: {status}"

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

    # get running firmware informations from Fujitsu server
    if plugin.rf.vendor == "Fujitsu":

        # get configuration
        iRMCConfiguration_link = grab(manager_response, f"Oem/{plugin.rf.vendor_dict_key}/iRMCConfiguration/@odata.id", separator="/")

        iRMCConfiguration = None
        if iRMCConfiguration_link is not None:
            iRMCConfiguration = plugin.rf.get(iRMCConfiguration_link)

        license_informations = None
        license_informations_link = grab(iRMCConfiguration, f"Licenses/@odata.id", separator="/")
        if license_informations_link is not None:
            license_informations = plugin.rf.get(license_informations_link)

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

    manager_response = plugin.rf.get(f"{redfish_url}/{plugin.rf.vendor_data.expand_string}")

    ibmc_model = manager_response.get("Model")
    ibmc_fw_version = manager_response.get("FirmwareVersion")

    # get general informations
    vendor_ibmc_data = grab(manager_response, f"Oem.{plugin.rf.vendor_dict_key}")

    if vendor_ibmc_data is None:
        plugin.add_output_data("UNKNOWN", "No iBMC data found.")
        return

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

    status = get_status_data(manager_response.get("Status")).get("Health")

    plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text, summary = not args.detailed)

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

            manager_data = grab(basic_infos, f"Oem.{vendor_string}.Manager.0")

            if manager_data is not None:
                plugin.rf.vendor_data.ilo_hostname = manager_data.get("HostName")
                plugin.rf.vendor_data.ilo_version = manager_data.get("ManagerType")
                plugin.rf.vendor_data.ilo_firmware_version = manager_data.get("ManagerFirmwareVersion")

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

    if "CIMC" in str(plugin.rf.connection.system_properties.get("managers")):
        plugin.rf.vendor = "Cisco"

        plugin.rf.vendor_data = VendorCiscoData()

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

    # initialize inventory
    plugin.inventory = Inventory()

    # try to get systems, managers and chassis IDs
    discover_system_properties()

    # get basic informations
    get_basic_system_info()

    if any(x in args.requested_query for x in ['power', 'all']):    get_chassi_data("power")
    if any(x in args.requested_query for x in ['temp', 'all']):     get_chassi_data("temp")
    if any(x in args.requested_query for x in ['fan', 'all']):      get_chassi_data("fan")
    if any(x in args.requested_query for x in ['proc', 'all']):     get_system_data("procs")
    if any(x in args.requested_query for x in ['memory', 'all']):   get_system_data("mem")
    if any(x in args.requested_query for x in ['nic', 'all']):      get_system_data("nics")
    if any(x in args.requested_query for x in ['storage', 'all']):  get_storage()
    if any(x in args.requested_query for x in ['bmc', 'all']):      get_bmc_info()
    if any(x in args.requested_query for x in ['info', 'all']):     get_system_info()
    if any(x in args.requested_query for x in ['firmware', 'all']): get_firmware_info()
    if any(x in args.requested_query for x in ['mel', 'all']):      get_event_log("Manager")
    if any(x in args.requested_query for x in ['sel', 'all']):      get_event_log("System")

    plugin.do_exit()

# EOF
