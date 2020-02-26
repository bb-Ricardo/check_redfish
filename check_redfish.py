#!/usr/bin/env python3.6

self_description = \
"""This is a monitoring/inventory plugin to check components and
health status of systems which support Redfish.
It will also create a inventory of all components of a system.

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
import sys

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
inventory_layout_version_string = "0.1"
physical_drive_attributes = [ "id", "name", "serial", "type", "speed_in_rpm", "health_status", "operation_status", "bay",
                              "size_in_byte", "firmware", "model", "power_on_hours", "interface_type", "interface_speed",
                              "encrypted", "manufacturer", "temperature", "location", "storage_port", "system_ids",
                              "storage_controller_ids", "storage_enclosure_ids", "logical_drive_ids", "failure_predicted",
                              "predicted_media_life_left_percent", "part_number"]
logical_drive_attributes = ["id", "name", "type", "health_status", "operation_status", "size_in_byte", "raid_type",
                            "encrypted", "storage_controller_ids", "physical_drive_ids", "system_ids"]
storage_controller_attributes = ["id", "name", "serial", "model", "location", "firmware", "health_status", "operation_status",
                                 "backup_power_present", "cache_size_in_mb", "system_ids", "manufacturer",
                                 "storage_enclosure_ids", "logical_drive_ids", "physical_drive_ids"]
storage_enclosure_attributes = ["id", "name", "serial", "model", "location", "firmware", "health_status", "operation_status",
                                "num_bays", "storage_controller_ids", "physical_drive_ids", "storage_port", "system_ids",
                                "manufacturer"]
processor_attributes = [ "id", "name", "serial", "model", "socket", "health_status", "operation_status", "cores",
                         "threads", "current_speed", "max_speed", "manufacturer", "instruction_set", "architecture",
                         "system_ids", "L1_cache_kib", "L2_cache_kib", "L3_cache_kib"]
memory_attributes = [ "id", "name", "serial", "socket", "slot", "channel", "health_status", "operation_status",
                      "speed", "part_number", "manufacturer", "type", "size_in_mb", "base_type", "system_ids"]
ps_attributes = [ "id", "name", "last_power_output", "part_number", "model", "health_status", "operation_status",
                  "bay", "model", "vendor", "serial", "firmware", "type", "capacity_in_watt", "input_voltage", "chassi_ids" ]
temp_fan_common_attributes = [ "id", "name", "physical_context", "health_status", "operation_status", "reading",
                   "min_reading", "max_reading", "lower_threshold_non_critical", "lower_threshold_critical",
                   "lower_threshold_fatal", "upper_threshold_non_critical", "upper_threshold_critical",
                   "upper_threshold_fatal", "reading_unit", "location", "chassi_ids"]
nic_attributes = [ "id", "name", "current_speed", "capable_speed", "health_status", "operation_status", "link_status",
                   "full_duplex", "autoneg", "ipv4_addresses", "ipv6_addresses", "mac_address", "link_type", "port_name",
                   "system_ids", "hostname", "manager_ids", "chassi_ids"]
system_attributes = [ "id", "name", "serial", "model", "manufacturer", "chassi_ids", "bios_version", "host_name", "power_state",
                      "cpu_num", "mem_size", "health_status", "operation_status", "part_number", "type", "indicator_led",
                      "manager_ids"]
firmware_attributes = [ "id", "name", "version", "location", "updateable", "health_status", "operation_status" ]
manager_attributes = [ "id", "name", "firmware", "model", "type", "system_ids", "chassi_ids", "licenses", "health_status",
                       "operation_status" ]
chassi_attributes = [ "id", "name", "model", "type", "manufacturer", "system_ids", "health_status", "operation_status",
                      "indicator_led", "serial", "sku", "manager_ids" ]

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
                pprint.pprint(redfish_response_json_data, stream=sys.stderr)

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

        # return inventory and exit with 0
        if args.inventory is True and self.inventory is not None:
            print(self.inventory.to_json())
            exit(0)

        print(self.return_output_data())

        exit(self.get_return_status(True))

class InventoryItem(object):
    """

    """
    valid_attributes = None
    inventory_item_name = None

    def __init__(self, **kwargs):

        if args.verbose:
            self.valid_attributes.append("source_data")

        for attribute in self.valid_attributes:
            value = None
            # references with ids are always lists
            if attribute.endswith("_ids") or attribute in ["licenses", "ipv4_addresses", "ipv6_addresses"]:
                value = list()

            super().__setattr__(attribute, value)

        for k,v in kwargs.items():
            setattr(self, k, v)

    def update(self, data_key, data_value, append=False):

        #
        current_data_value = getattr(self, data_key)

        if isinstance(current_data_value, list) and append is True:
            if isinstance(data_value, (str, int, float)):
                if data_value not in current_data_value:
                    current_data_value.append(data_value)
            else:
                current_data_value.extend(data_value)
            data_value = current_data_value

        setattr(self, data_key, data_value)

    def add_relation(self, system_properties, relations_data):

        # set inventory attributes for system properties
        relations = {
            "chassis": "chassi_ids",
            "systems": "system_ids",
            "managers": "manager_ids"
        }

        # recursive function to extract all values from nested data structure
        def get_links_recursive(data_structure):

            resource_list = list()

            if isinstance(data_structure, str):
                resource_list.append(data_structure.rstrip("/"))
            elif isinstance(data_structure, list):
                for item in data_structure:
                    resource_list.extend(get_links_recursive(item))
            elif isinstance(data_structure, dict):
                for key, value in data_structure.items():
                    if key == "@odata.id":
                        resource_list.append(value.rstrip("/"))
                    else:
                        resource_list.extend(get_links_recursive(value))

            return resource_list

        if not isinstance(system_properties, dict):
            return

        if relations_data is None:
            return

        # get all values from data structure
        relation_links = get_links_recursive(relations_data)

        # iterate over managers, systems and chassis to check if
        # this inventory item has a relation to it
        for property, property_links in system_properties.items():

            for property_link in property_links:
                if property_link.rstrip("/") in relation_links:
                    relations_property_attribute = relations.get(property)

                    # add relation if item has attribute
                    if relations_property_attribute is not None and hasattr(self, relations_property_attribute):

                        id = property_link.rstrip("/").split("/")[-1]
                        # check if object id is an int
                        try:
                            id = int(id)
                        except:
                            pass

                        # update attribute
                        self.update(relations_property_attribute, id, True)

    def __setattr__(self, key, value):

        # add source data without any formatting
        if key == "source_data":
            super().__setattr__(key, value)
            return

        if key not in self.valid_attributes:
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, key))

        current_value = getattr(self, key)

        if value is None and current_value is None:
            return

        if isinstance(value, str):
            value = value.strip()

            if len(value) == 0:
                value = None

            def is_int(v):
                return v=='0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()

            def is_float(v):
                try:     i = float(v)
                except:  return False
                return True

            # skip formating of certain attributes
            if value is not None and key not in [ "id", "name", "firmware", "serial", "version" ]:
                if is_int(value):
                    value = int(float(value))

                elif is_float(value):
                    value = float(value)

                elif value.upper() in status_types.keys():
                    value = value.upper()

        if isinstance(current_value, list):
            if value is None:
                value = list()
            elif isinstance(value, (str, int, float)):
                value = [ value ]
            elif not isinstance(value, list):
                value = [ f"{value}" ]
        else:
            if isinstance(value, (list, dict, set, tuple)):
                value = f"{value}"

        super().__setattr__(key, value)

class PhysicalDrive(InventoryItem):
    inventory_item_name = "physical_drives"
    valid_attributes = physical_drive_attributes

class LogicalDrive(InventoryItem):
    inventory_item_name = "logical_drives"
    valid_attributes = logical_drive_attributes

class StorageController(InventoryItem):
    inventory_item_name = "storage_controllers"
    valid_attributes = storage_controller_attributes

class StorageEnclosure(InventoryItem):
    inventory_item_name = "storage_enclosures"
    valid_attributes = storage_enclosure_attributes

class Processor(InventoryItem):
    inventory_item_name = "processors"
    valid_attributes = processor_attributes

class Memory(InventoryItem):
    inventory_item_name = "memories"
    valid_attributes = memory_attributes

class PowerSupply(InventoryItem):
    inventory_item_name = "power_supplies"
    valid_attributes = ps_attributes

class Temperature(InventoryItem):
    inventory_item_name = "temperatures"
    valid_attributes = temp_fan_common_attributes

class Fan(InventoryItem):
    inventory_item_name = "fans"
    valid_attributes = temp_fan_common_attributes

class NIC(InventoryItem):
    inventory_item_name = "nics"
    valid_attributes = nic_attributes

class System(InventoryItem):
    inventory_item_name = "systems"
    valid_attributes = system_attributes

class Firmware(InventoryItem):
    inventory_item_name = "firmware"
    valid_attributes = firmware_attributes

class Manager(InventoryItem):
    inventory_item_name = "managers"
    valid_attributes = manager_attributes

class Chassi(InventoryItem):
    inventory_item_name = "chassis"
    valid_attributes = chassi_attributes

class Inventory(object):
    """

    """
    base_structure = dict()
    inventory_start = None
    data_retrieval_issues = list()


    def __init__(self):
        for inventory_sub_class in InventoryItem.__subclasses__():
            if inventory_sub_class.inventory_item_name is None:
                raise AttributeError("The 'inventory_item_name' attribute for class '%s' is undefined." %
                                 inventory_sub_class.__name__)

            self.base_structure[inventory_sub_class.inventory_item_name] = list()

        # set metadata
        self.inventory_start = datetime.datetime.utcnow()

    def add(self, object):

        if not isinstance(object, InventoryItem):
            raise AttributeError("'%s' object not allowed to add to a '%s' class item." %
                                 (object.__class__.__name__, InventoryItem.__name__))

        # check if ID is already used and add issue
        for inv_item in self.base_structure[object.inventory_item_name]:
            if inv_item.id == object.id:
                #raise AttributeError(f"Object id '{object.id}' already used")
                print("Object id '{object.id}' already used", file=sys.stderr)

        self.base_structure[object.inventory_item_name].append(object)

    def update(self, class_name, component_id, data_key, data_value, append=False):

        if not class_name in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        # find inventory item to update
        for inventory_item in self.base_structure[class_name.inventory_item_name]:
            if inventory_item.id == component_id:

                inventory_item.update(data_key, data_value, append)

    def append(self, class_name, component_id, data_key, data_value):

        self.update(class_name, component_id, data_key, data_value, True)

    def add_issue(self, class_name, issue = None):

        if issue is None:
            return

        if not class_name in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        self.data_retrieval_issues.append(f"{class_name.inventory_item_name}: {issue}")

    def get(self, class_name):

        if not class_name in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        if self.base_structure[class_name.inventory_item_name] is None:
            return list()

        return self.base_structure[class_name.inventory_item_name]

    def to_json(self):
        inventory_content = self.base_structure

        # add metadata
        inventory_content["meta"] = {
            "WARNING": "THIS is a alpha version of this implementation and possible changes might occur without notice",
            "start_of_data_collection": self.inventory_start.replace(tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat(),
            "duration_of_data_colection_in_seconds": (datetime.datetime.utcnow() - self.inventory_start).total_seconds(),
            "inventory_layout_version": inventory_layout_version_string,
            "data_retrieval_issues": self.data_retrieval_issues,
            "host_that_collected_inventory": os.uname()[1],
            "script_version": __version__
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
                        help="this will add all https requests and responses to output, "
                        "also adds inventory source data to all inventory objects")
    group.add_argument("-d", "--detailed",  action='store_true',
                        help="always print detailed result")
    group.add_argument("-m", "--max",  type=int,
                        help="set maximum of returned items for --sel or --mel")
    group.add_argument("-r", "--retries",  type=int, default=default_conn_max_retries,
                        help="set number of maximum retries (default: %d)" % default_conn_max_retries)
    group.add_argument("-t", "--timeout",  type=int, default=default_conn_timeout,
                        help="set number of request timeout per try/retry (default: %d)" % default_conn_timeout)

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

    # inventory
    group = parser.add_argument_group(title="query inventory information (no health check)")
    group.add_argument("-i", "--inventory",  action='store_true',
                        help="return inventory in json format instead of regular plugin output")

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

    chassi_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/Power"

    power_data = plugin.rf.get_view(redfish_url)

    power_supplies = power_data.get("PowerSupplies")

    fujitsu_power_sensors = None
    if plugin.rf.vendor == "Fujitsu":
        fujitsu_power_sensors = grab(power_data, f"Oem.{plugin.rf.vendor_dict_key}.ChassisPowerSensors")

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
            capacity_in_watt = ps.get("PowerCapacityWatts")
            bay = None

            oem_data = grab(ps, f"Oem.{plugin.rf.vendor_dict_key}")

            if oem_data is not None:

                if plugin.rf.vendor == "HPE":
                    bay = grab(oem_data, "BayNumber")
                    ps_hp_status = grab(oem_data, "PowerSupplyStatus.State")
                    if ps_hp_status is not None and ps_hp_status == "Unknown":
                        health = "CRITICAL"

                elif plugin.rf.vendor == "Lenovo":
                    bay = grab(oem_data, "Location.Info")

                elif plugin.rf.vendor == "Huawei":
                    last_power_output = grab(oem_data, f"PowerOutputWatts")

            if bay is None:
                bay = ps_num

            if capacity_in_watt is None:
                capacity_in_watt = grab(ps, "InputRanges.0.OutputWattage")

            # special Fujitsu case
            if fujitsu_power_sensors is not None and last_power_output is None:
                for fujitsu_power_sensor in fujitsu_power_sensors:
                    if fujitsu_power_sensor.get("Designation") == ps.get("Name"):
                        last_power_output = fujitsu_power_sensor.get("CurrentPowerConsumptionW")

            ps_inventory = PowerSupply(
                id = grab(ps, "MemberId") or ps_num,
                name = ps.get("Name"),
                model = model,
                bay = bay,
                health_status = health,
                operation_status = operatinal_status,
                last_power_output = last_power_output,
                serial = ps.get("SerialNumber"),
                type = ps.get("PowerSupplyType"),
                capacity_in_watt = capacity_in_watt,
                firmware = ps.get("FirmwareVersion"),
                vendor = ps.get("Manufacturer"),
                input_voltage = ps.get("LineInputVoltage"),
                part_number = ps.get("SparePartNumber") or ps.get("PartNumber"),
                chassi_ids = chassi_id
            )

            if args.verbose:
                ps_inventory.source_data = ps

            plugin.inventory.add(ps_inventory)

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

    chassi_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin.rf.get_view(redfish_url)

    default_text = ""
    temp_num = 0
    if "Temperatures" in thermal_data:

        for temp in thermal_data.get("Temperatures"):

            status_data = get_status_data(grab(temp,"Status"))

            status = status_data.get("Health")
            state = status_data.get("State")

            name = temp.get("Name")
            id = grab(temp, "MemberId")

            if id is None:
                id = name

            temp_inventory = Temperature(
                name = name,
                id = id,
                health_status = status,
                operation_status = state,
                physical_context = temp.get("PhysicalContext"),
                min_reading = temp.get("MinReadingRangeTemp"),
                max_reading = temp.get("MaxReadingRangeTemp"),
                lower_threshold_non_critical = None if temp.get("LowerThresholdNonCritical") == "N/A" else temp.get("LowerThresholdNonCritical"),
                lower_threshold_critical = None if temp.get("LowerThresholdCritical") == "N/A" else temp.get("LowerThresholdCritical"),
                lower_threshold_fatal = None if temp.get("LowerThresholdFatal") == "N/A" else temp.get("LowerThresholdFatal"),
                upper_threshold_non_critical = None if temp.get("UpperThresholdNonCritical") == "N/A" else temp.get("UpperThresholdNonCritical"),
                upper_threshold_critical = None if temp.get("UpperThresholdCritical") == "N/A" else temp.get("UpperThresholdCritical"),
                upper_threshold_fatal = None if temp.get("UpperThresholdFatal") == "N/A" else temp.get("UpperThresholdFatal"),
                chassi_ids = chassi_id
            )

            if args.verbose:
                temp_inventory.source_data = temp

            temp_inventory.reading_unit = "Celsius"
            if temp.get("ReadingCelsius") is not None:
                temp_inventory.reading = temp.get("ReadingCelsius")
            elif temp.get("ReadingFahrenheit") is not None:
                temp_inventory.reading = temp.get("ReadingFahrenheit")
                temp_inventory.reading_unit = "Fahrenheit"
            else:
                temp_inventory.reading = 0

            # add relations
            temp_inventory.add_relation(plugin.rf.connection.system_properties, temp.get("Links"))
            temp_inventory.add_relation(plugin.rf.connection.system_properties, temp.get("RelatedItem"))

            plugin.inventory.add(temp_inventory)

            if state in [ "Absent", "Disabled", "UnavailableOffline" ]:
                continue

            if status is None:
                status = "OK" if state == "Enabled" else state

            current_temp = temp_inventory.reading
            critical_temp = temp_inventory.upper_threshold_critical
            warning_temp = temp_inventory.upper_threshold_non_critical

            temp_num += 1

            if str(warning_temp) in [ "0", "N/A"]:
                warning_temp = None

            if warning_temp is not None and float(current_temp) >= float(warning_temp):
                status = "WARNING"

            if str(critical_temp) in [ "0", "N/A"]:
                critical_temp = None

            if critical_temp is not None and float(current_temp) >= float(critical_temp):
                status = "CRITICAL"

            critical_temp_text = "N/A" if critical_temp is None else "%.1f" % critical_temp

            status_text = f"Temp sensor {temp_inventory.name} status is: {status} (%.1f °C) (max: {critical_temp_text} °C)" % current_temp

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            plugin.add_perf_data(f"temp_{temp_inventory.name}", float(current_temp), warning=warning_temp, critical=critical_temp)

        default_text = f"All temp sensors ({temp_num}) are in good condition"
    else:
        plugin.add_output_data("UNKNOWN", f"No thermal data returned for API URL '{redfish_url}'")

    plugin.add_output_data("OK", default_text, summary = True)

    return

def get_single_chassi_fan(redfish_url):

    global plugin

    plugin.set_current_command("Fan")

    chassi_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin.rf.get_view(redfish_url)

    default_text = ""
    fan_num = 0
    if "Fans" in thermal_data:
        for fan in thermal_data.get("Fans"):

            status_data = get_status_data(grab(fan,"Status"))

            id = grab(fan, "MemberId")
            name = fan.get("FanName") or fan.get("Name")

            if id is None:
                id = name

            physical_context = fan.get("PhysicalContext")

            oem_data = grab(fan, f"Oem.{plugin.rf.vendor_dict_key}")
            if physical_context is None:
                physical_context = grab(oem_data, "Location") or grab(oem_data, "Position")

            fan_inventory = Fan(
                id = id,
                name = name,
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                physical_context = physical_context,
                min_reading = fan.get("MinReadingRange"),
                max_reading = fan.get("MaxReadingRange"),
                lower_threshold_non_critical = fan.get("LowerThresholdNonCritical"),
                lower_threshold_critical = fan.get("LowerThresholdCritical"),
                lower_threshold_fatal = fan.get("LowerThresholdFatal"),
                upper_threshold_non_critical = fan.get("UpperThresholdNonCritical"),
                upper_threshold_critical = fan.get("UpperThresholdCritical"),
                upper_threshold_fatal = fan.get("UpperThresholdFatal"),
                location = grab(fan, f"Oem.{plugin.rf.vendor_dict_key}.Location.Info"),
                chassi_ids = chassi_id
            )

            if args.verbose:
                fan_inventory.source_data = fan

            text_speed = ""
            text_units = ""
            fan_status = fan_inventory.health_status

            # add relations
            fan_inventory.add_relation(plugin.rf.connection.system_properties, fan.get("Links"))
            fan_inventory.add_relation(plugin.rf.connection.system_properties, fan.get("RelatedItem"))

            perf_units = ""

            # DELL, Fujitsu, Huawei
            if fan.get("ReadingRPM") is not None or fan.get("ReadingUnits") == "RPM":
                fan_inventory.reading = fan.get("ReadingRPM") or fan.get("Reading")
                fan_inventory.reading_unit = "RPM"

                text_units = " RPM"

            # HP, Lenovo
            else:
                fan_inventory.reading = fan.get("Reading")
                fan_inventory.reading_unit = fan.get("ReadingUnits")

                if fan_inventory.reading_unit == "Percent":

                    text_units = "%"
                    perf_units = "%"

            text_speed = f" ({fan_inventory.reading}{text_units})"

            plugin.inventory.add(fan_inventory)

            if fan_inventory.operation_status == "Absent":
                continue

            if fan_inventory.health_status is None:
                fan_status = "OK" if fan_inventory.operation_status == "Enabled" else fan_inventory.operation_status

            fan_num += 1

            status_text = f"Fan '{fan_inventory.name}'{text_speed} status is: {fan_status}"

            plugin.add_output_data("CRITICAL" if fan_status not in ["OK", "WARNING"] else fan_status, status_text)

            if fan_inventory.reading is not None:
                plugin.add_perf_data(f"Fan_{fan_inventory.name}", int(fan_inventory.reading), perf_uom=perf_units, warning=args.warning, critical=args.critical)

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

        if health == "OK" and args.detailed == False and args.inventory == False:
            plugin.add_output_data("OK", f"All processors {proc_count_text}are in good condition", summary = True)
            return

    system_response_proc_key = "Processors"
    if systems_response.get(system_response_proc_key) is None:
        issue_text = f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_proc_key}'"
        plugin.inventory.add_issue(Processor, issue_text)
        plugin.add_output_data("UNKNOWN", issue_text)
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

                status_data = get_status_data(proc_response.get("Status"))

                model = proc_response.get("Model")

                vendor_data = grab(proc_response, f"Oem.{plugin.rf.vendor_dict_key}")

                # get current/regular speed
                current_speed = grab(vendor_data, "CurrentClockSpeedMHz") or \
                                grab(vendor_data, "RatedSpeedMHz") or \
                                grab(vendor_data, "FrequencyMHz")

                # try to extract speed from model if current_speed is None
                # Intel XEON CPUs
                if current_speed is None and model is not None and "GHz" in model:
                    model_speed = model.split("@")[-1].strip().replace("GHz","")
                    try:
                        current_speed = int(float(model_speed) * 1000)
                    except:
                        pass

                # get cache information
                L1_cache_kib = grab(vendor_data, "L1CacheKiB")
                L2_cache_kib = grab(vendor_data, "L2CacheKiB")
                L3_cache_kib = grab(vendor_data, "L3CacheKiB")

                                    # HPE                         # Lenovo
                vendor_cache_data = grab(vendor_data, "Cache") or grab(vendor_data, "CacheInfo")

                if vendor_cache_data is not None:

                    for cpu_cache in vendor_cache_data:

                                      # HPE                               # Lenovo
                        cache_size =  cpu_cache.get("InstalledSizeKB") or cpu_cache.get("InstalledSizeKByte")
                        cache_level = cpu_cache.get("Name")            or cpu_cache.get("CacheLevel")

                        if cache_size is None or cache_level is None:
                            continue

                        if "L1" in cache_level:
                            L1_cache_kib = cache_size * 1000 / 1024
                        if "L2" in cache_level:
                            L2_cache_kib = cache_size * 1000 / 1024
                        if "L3" in cache_level:
                            L3_cache_kib = cache_size * 1000 / 1024


                proc_inventory = Processor(
                    name = proc_response.get("Name"),
                    id = proc_response.get("Id"),
                    model = model,
                    socket = proc_response.get("Socket"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    cores = proc_response.get("TotalCores"),
                    threads = proc_response.get("TotalThreads"),
                    current_speed = current_speed,
                    max_speed = proc_response.get("MaxSpeedMHz"),
                    manufacturer = proc_response.get("Manufacturer"),
                    instruction_set = proc_response.get("InstructionSet"),
                    architecture = proc_response.get("ProcessorArchitecture"),
                    serial = grab(proc_response, f"Oem.{plugin.rf.vendor_dict_key}.SerialNumber"),
                    system_ids = systems_response.get("Id"),
                    L1_cache_kib = L1_cache_kib,
                    L2_cache_kib = L2_cache_kib,
                    L3_cache_kib = L3_cache_kib
                )

                if args.verbose:
                    proc_inventory.source_data = proc_response

                plugin.inventory.add(proc_inventory)

                if proc_inventory.operation_status == "Absent":
                    continue

                num_procs += 1

                status_text = f"Processor {proc_inventory.socket} ({proc_inventory.model}) status is: {proc_inventory.health_status}"

                plugin.add_output_data("CRITICAL" if proc_inventory.health_status not in ["OK", "WARNING"] else proc_inventory.health_status, status_text)

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

        if health == "OK" and args.detailed == False and args.inventory == False:

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
        issue_text = f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_memory_key}'"
        plugin.inventory.add_issue(Memory, issue_text)
        plugin.add_output_data("UNKNOWN", issue_text)
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
                module_size = mem_module_response.get("SizeMB") or mem_module_response.get("CapacityMiB") or 0

                module_size = int(module_size)

                # DELL
                if plugin.rf.vendor == "Dell":
                    module_size = round(module_size * 1024 ** 2 / 1000 ** 2)

                # get name
                module_name = mem_module_response.get("SocketLocator") or mem_module_response.get("DeviceLocator") or mem_module_response.get("Name")

                if module_name is None:
                    module_name = "UnknownNameLocation"

                # get status
                status_data = get_status_data(mem_module_response.get("Status"))

                if plugin.rf.vendor == "HPE" and grab(mem_module_response, f"Oem.{plugin.rf.vendor_dict_key}.DIMMStatus"):
                    status_data["State"] = grab(mem_module_response, f"Oem.{plugin.rf.vendor_dict_key}.DIMMStatus")

                elif mem_module_response.get("DIMMStatus"):

                    status_data["State"] = mem_module_response.get("DIMMStatus")

                mem_inventory = Memory(
                    name = module_name,
                    id = mem_module_response.get("Id"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    size_in_mb = module_size,
                    manufacturer = mem_module_response.get("Manufacturer"),
                    serial = mem_module_response.get("SerialNumber"),
                    socket = grab(mem_module_response, "MemoryLocation.Socket"),
                    slot = grab(mem_module_response, "MemoryLocation.Slot"),
                    channel = grab(mem_module_response, "MemoryLocation.Channel"),
                    speed = mem_module_response.get("OperatingSpeedMhz"),
                    part_number = mem_module_response.get("PartNumber"),
                    type = mem_module_response.get("MemoryDeviceType") or mem_module_response.get("MemoryType"),
                    base_type = mem_module_response.get("BaseModuleType"),
                    system_ids = systems_response.get("Id")
                )

                if args.verbose:
                    mem_inventory.source_data = mem_module_response

                plugin.inventory.add(mem_inventory)

                if mem_inventory.operation_status in [ "Absent", "NotPresent"]:
                    continue

                num_dimms += 1
                size_sum += module_size

                if mem_inventory.operation_status in [ "GoodInUse", "Operable"]:
                    plugin_status = "OK"
                    status_text = mem_inventory.operation_status
                else:
                    plugin_status = mem_inventory.health_status
                    status_text = plugin_status

                status_text = f"Memory module {mem_inventory.name} (%.1fGB) status is: {status_text}" % ( mem_inventory.size_in_mb / 1024)

                plugin.add_output_data("CRITICAL" if plugin_status not in ["OK", "WARNING"] else plugin_status, status_text)

            else:
                plugin.add_output_data("UNKNOWN", "No memory data returned for API URL '%s'" % mem_module.get("@odata.id"))

    if num_dimms == 0:
        plugin.add_output_data("UNKNOWN", f"No memory data returned for API URL '{redfish_url}'")
    else:
        plugin.add_output_data("OK", f"All {num_dimms} memory modules (Total %.1fGB) are in good condition" % (size_sum / 1024), summary = True)

    return

def get_system_nics_fujitsu(redfish_url):

    global plugin

    plugin.set_current_command("NICs")

    system_id = redfish_url.rstrip("/").split("/")[-1]

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


                # get health status
                status_data = get_status_data(network_port_data.get("Status"))

                # get and sanitize MAC address
                mac_address = grab(network_function_member, "Ethernet.PermanentMACAddress")
                if mac_address is not None:
                    mac_address = mac_address.upper()

                # get Link speed
                current_speed = network_port_data.get("CurrentLinkSpeedMbps") or \
                                grab(network_port_data, "SupportedLinkCapabilities.0.LinkSpeedMbps")

                # get port number
                if network_port_data.get("PhysicalPortNumber"):
                    nic_port_name = "Port " + network_port_data.get("PhysicalPortNumber")
                else:
                    nic_port_name = network_port_data.get("Name")

                # get IP addresses
                ipv4_addresses = grab(network_function_member, f"Oem.{plugin.rf.vendor_dict_key}.IPv4Addresses")
                if ipv4_addresses is not None and len(ipv4_addresses) == 0:
                    ipv4_addresses = None

                ipv6_addresses = grab(network_function_member, f"Oem.{plugin.rf.vendor_dict_key}.IPv6Addresses")
                if ipv6_addresses is not None and len(ipv6_addresses) == 0:
                    ipv6_addresses = None

                nic_inventory = NIC(
                    id = network_function_member.get("Id"),
                    name = network_function_member.get("Name"),
                    port_name = nic_port_name,
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    mac_address = mac_address,
                    link_type = network_port_data.get("ActiveLinkTechnology"),
                    current_speed = network_port_data.get("CurrentLinkSpeedMbps"),
                    capable_speed = grab(network_port_data, "SupportedLinkCapabilities.0.CapableLinkSpeedMbps.0"),
                    link_status = network_port_data.get("LinkStatus"),
                    ipv4_addresses = ipv4_addresses,
                    ipv6_addresses = ipv6_addresses,
                    system_ids = system_id
                )

                if args.verbose:
                    nic_inventory.source_data = { "nic_functions": network_function_member, "nic_port": network_port_data }

                # add relations
                nic_inventory.add_relation(plugin.rf.connection.system_properties, network_function_member.get("Links"))
                nic_inventory.add_relation(plugin.rf.connection.system_properties, network_function_member.get("RelatedItem"))
                nic_inventory.add_relation(plugin.rf.connection.system_properties, network_port_data.get("Links"))
                nic_inventory.add_relation(plugin.rf.connection.system_properties, network_port_data.get("RelatedItem"))

                plugin.inventory.add(nic_inventory)

                # ignore interface if state is not Enabled
                if nic_inventory.operation_status != "Enabled":
                    continue

                status_text  = f"NIC {nic_inventory.id} ({nic_inventory.name}) {nic_inventory.port_name} "
                status_text += f"(Type: {nic_inventory.link_type}, Speed: {nic_inventory.current_speed}/{nic_inventory.capable_speed}, MAC: {nic_inventory.mac_address}) "
                status_text += f"status: {nic_inventory.link_status}"
                plugin.add_output_data("CRITICAL" if nic_inventory.health_status not in ["OK", "WARNING"] else nic_inventory.health_status, status_text)

    if num_nic_ports == 0:
        plugin.add_output_data("UNKNOWN", f"No network interface data returned for API URL '{redfish_url}'")

    plugin.add_output_data("OK", f"All network interfaces ({num_nic_ports}) are in good condition", summary = True)

    return

def get_single_system_nics(redfish_url):

    global plugin

    plugin.set_current_command("NICs")

    system_id = redfish_url.rstrip("/").split("/")[-1]

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

                # get health status
                status_data = get_status_data(nic_response.get("Status"))

                # get and sanitize MAC address
                mac_address = nic_response.get("PermanentMACAddress")
                if mac_address is not None:
                    mac_address = mac_address.upper()

                nic_inventory = NIC(
                    id = nic_response.get("Id"),
                    name = nic_response.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    link_status = nic_response.get("LinkStatus"),
                    mac_address = mac_address,
                    current_speed = nic_response.get("SpeedMbps"),
                    system_ids = system_id
                )

                if args.verbose:
                    nic_inventory.source_data = nic_response

                # add relations
                nic_inventory.add_relation(plugin.rf.connection.system_properties, nic_response.get("Links"))
                nic_inventory.add_relation(plugin.rf.connection.system_properties, nic_response.get("RelatedItem"))

                plugin.inventory.add(nic_inventory)

                nic_status_string = nic_inventory.health_status
                if nic_status_string is None:
                    nic_status_string = "Undefined"

                status_text = f"NIC {nic_inventory.id} status is: {nic_status_string}"

                plugin_status = nic_inventory.health_status
                if plugin_status is None:
                    plugin_status = "OK"

                if nic_inventory.link_status is not None and nic_inventory.link_status != "NoLink":
                    status_text += f" and link status is '{nic_inventory.link_status}'"

                plugin.add_output_data("CRITICAL" if plugin_status not in ["OK", "WARNING"] else plugin_status, status_text)

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

            status_data = get_status_data(disk_response.get("Status"))

            # get disk size
            disk_size = None
            if disk_response.get("CapacityLogicalBlocks") is not None and \
               disk_response.get("BlockSizeBytes") is not None:
                disk_size = int(disk_response.get("CapacityLogicalBlocks")) * int(disk_response.get("BlockSizeBytes"))
            elif disk_response.get("CapacityMiB"):
                disk_size = int(disk_response.get("CapacityMiB")) * 1024 ** 2
            elif disk_response.get("CapacityGB"):
                disk_size = disk_response.get("CapacityGB") * 1000 ** 3

            # get location
            drive_location = None
            if disk_response.get("LocationFormat") is not None and disk_response.get("Location") is not None:
                drive_location = dict(zip(disk_response.get("LocationFormat").lower().split(":"), disk_response.get("Location").split(":")))

            predicted_media_life_left_percent = None
            if disk_response.get("SSDEnduranceUtilizationPercentage") is not None:
                try:
                    predicted_media_life_left_percent = 100 - int(disk_response.get("SSDEnduranceUtilizationPercentage"))
                except:
                    pass

            pd_inventory = PhysicalDrive(
                # drive id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id,disk_response.get("Id")),
                name  = disk_response.get("Name"),
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                model = disk_response.get("Model"),
                firmware = grab(disk_response, "FirmwareVersion.Current.VersionString"),
                serial = disk_response.get("SerialNumber"),
                location = disk_response.get("Location"),
                part_number = disk_response.get("PartNumber"),
                type = disk_response.get("MediaType"),
                speed_in_rpm = disk_response.get("RotationalSpeedRpm"),
                failure_predicted = disk_response.get("FailurePredicted"),
                predicted_media_life_left_percent = predicted_media_life_left_percent,
                size_in_byte = disk_size,
                power_on_hours = disk_response.get("PowerOnHours"),
                interface_type = disk_response.get("InterfaceType"),
                interface_speed = disk_response.get("InterfaceSpeedMbps"),
                encrypted = disk_response.get("EncryptedDrive"),
                bay = None if drive_location is None else drive_location.get("bay"),
                temperature = disk_response.get("CurrentTemperatureCelsius")
            )

            if drive_location is not None:
                pd_inventory.storage_port = drive_location.get("controllerport")
            pd_inventory.storage_controller_ids = controller_inventory.id
            pd_inventory.system_ids = system_id

            if args.verbose:
                pd_inventory.source_data = disk_response

            plugin.inventory.add(pd_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "physical_drive_ids", pd_inventory.id)

            size = int(pd_inventory.size_in_byte / 1000 ** 3)

            status_text = f"Physical Drive ({pd_inventory.location}) {size}GB Status: {pd_inventory.health_status}"

            plugin.add_output_data("CRITICAL" if pd_inventory.health_status not in ["OK", "WARNING"] else pd_inventory.health_status, status_text)

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

            status_data = get_status_data(logical_drive_response.get("Status"))

            # get size
            size = logical_drive_response.get("CapacityMiB")
            if size is not None:
                size = int(size) * 1024 ** 2
                printed_size = size / 1000 ** 3
            else:
                printed_size = 0

            ld_inventory = LogicalDrive(
                # logical drive id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id, logical_drive_response.get("Id")),
                name  = logical_drive_response.get("LogicalDriveName"),
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                type = logical_drive_response.get("LogicalDriveType"),
                size_in_byte = size,
                raid_type = logical_drive_response.get("Raid"),
                encrypted = logical_drive_response.get("LogicalDriveEncryption")
            )

            if args.verbose:
                ld_inventory.source_data = logical_drive_response

            data_drives_link = grab(logical_drive_response, "Links/DataDrives/@odata.id", separator="/")

            if data_drives_link is not None:
                data_drives_response = plugin.rf.get(data_drives_link)

                for data_drive in data_drives_response.get("Members"):
                    data_drive_id = ("{}:{}".format(
                        controller_inventory.id, data_drive.get("@odata.id").rstrip("/").split("/")[-1]))

                    ld_inventory.update("physical_drive_ids", data_drive_id, True)
                    plugin.inventory.append(PhysicalDrive, data_drive_id, "logical_drive_ids", ld_inventory.id)

            ld_inventory.storage_controller_ids = controller_inventory.id
            ld_inventory.system_ids = system_id

            plugin.inventory.add(ld_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "logical_drive_ids", ld_inventory.id)

            status_text = f"Logical Drive ({ld_inventory.id}) %.1fGB (RAID {ld_inventory.raid_type}) Status: {ld_inventory.health_status}" % \
                printed_size

            plugin.add_output_data("CRITICAL" if ld_inventory.health_status not in ["OK", "WARNING"] else ld_inventory.health_status, status_text)

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

            status_data = get_status_data(enclosure_response.get("Status"))

            # get location
            enclosure_location = None
            if enclosure_response.get("LocationFormat") is not None and enclosure_response.get("Location") is not None:
                enclosure_location = dict(zip(enclosure_response.get("LocationFormat").lower().split(":"), enclosure_response.get("Location").split(":")))

            enclosure_inventory = StorageEnclosure(
                # enclosure id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id, enclosure_response.get("Id")),
                name = enclosure_response.get("Name"),
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                serial = enclosure_response.get("SerialNumber"),
                storage_port = None if enclosure_location is None else enclosure_location.get("controller"),
                model = enclosure_response.get("Model"),
                location = enclosure_response.get("Location"),
                firmware = grab(enclosure_response, "FirmwareVersion.Current.VersionString"),
                num_bays = enclosure_response.get("DriveBayCount")
            )

            if args.verbose:
                enclosure_inventory.source_data = enclosure_response

            enclosure_inventory.storage_controller_ids = controller_inventory.id
            enclosure_inventory.system_ids = system_id

            # set relation between disk drives and enclosures
            for drive in plugin.inventory.base_structure.get("physical_drives"):

                # get list of drives for each enclosure
                if drive.location is not None and enclosure_inventory.location is not None and \
                    drive.location.startswith(enclosure_inventory.location):
                    enclosure_inventory.update("physical_drive_ids", drive.id, True)
                    plugin.inventory.append(PhysicalDrive, drive.id, "storage_enclosure_ids", enclosure_inventory.id)

            plugin.inventory.add(enclosure_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "storage_enclosure_ids", enclosure_inventory.id)


            status_text = f"StorageEnclosure ({enclosure_inventory.location}) Status: {enclosure_inventory.health_status}"

            plugin.add_output_data("CRITICAL" if enclosure_inventory.health_status not in ["OK", "WARNING"] else enclosure_inventory.health_status, status_text)

    global plugin

    plugin.set_current_command("Storage")

    system_id = system.rstrip("/").split("/")[-1]

    redfish_url = f"{system}/SmartStorage/"

    storage_response = plugin.rf.get(redfish_url)

    storage_status = get_status_data(storage_response.get("Status"))
    status = storage_status.get("Health")

    if status == "OK" and args.detailed == False and args.inventory == False:
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

                status_data = get_status_data(controller_response.get("Status"))

                backup_power_present = False
                if controller_response.get("BackupPowerSourceStatus") == "Present":
                    backup_power_present = True

                controller_inventory = StorageController(
                    id = controller_response.get("Id"),
                    name  = controller_response.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    model = controller_response.get("Model"),
                    manufacturer = "HPE",
                    firmware = grab(controller_response, "FirmwareVersion.Current.VersionString"),
                    serial = controller_response.get("SerialNumber"),
                    location = controller_response.get("Location"),
                    backup_power_present = backup_power_present,
                    cache_size_in_mb = controller_response.get("CacheMemorySizeMiB"),
                    system_ids = system_id
                )

                if args.verbose:
                    controller_inventory.source_data = controller_response

                plugin.inventory.add(controller_inventory)

                if controller_inventory.operation_status == "Absent":
                    continue

                status_text = f"{controller_inventory.model} (FW: {controller_inventory.firmware}) status is: {controller_inventory.health_status}"

                plugin.add_output_data("CRITICAL" if controller_inventory.health_status not in ["OK", "WARNING"] else controller_inventory.health_status, status_text)

                get_disks(array_controller.get("@odata.id"))
                get_disks(array_controller.get("@odata.id"), "UnconfiguredDrives")
                get_logical_drives(array_controller.get("@odata.id"))
                get_enclosures(array_controller.get("@odata.id"))
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

        # get status data
        status_data = get_status_data(drive_response.get("Status"))

        # get disk size
        disk_size = None
        if drive_response.get("CapacityLogicalBlocks") is not None and \
           drive_response.get("BlockSizeBytes") is not None:
            disk_size = int(drive_response.get("CapacityLogicalBlocks")) * int(drive_response.get("BlockSizeBytes"))
        elif drive_response.get("CapacityBytes"):
            disk_size = drive_response.get("CapacityBytes")
        elif drive_response.get("CapacityMiB"):
            disk_size = int(drive_response.get("CapacityMiB")) * 1024 ** 2
        elif drive_response.get("CapacityGB"):
            disk_size = drive_response.get("CapacityGB") * 1000 ** 3

        drive_oem_data = grab(drive_response, f"Oem.{plugin.rf.vendor_dict_key}")

        temperature = None
        bay = None
        storage_port = None
        power_on_hours = drive_response.get("PowerOnHours")
        if drive_oem_data is not None:
            temperature = drive_oem_data.get("TemperatureCelsius") or drive_oem_data.get("TemperatureC")
            if power_on_hours is None:
                power_on_hours = drive_oem_data.get("HoursOfPoweredUp") or drive_oem_data.get("PowerOnHours")
            bay = drive_oem_data.get("SlotNumber")

        # Dell
        dell_disk_data = grab(drive_oem_data, "DellPhysicalDisk")
        if dell_disk_data is not None:
            if bay is None:
                bay = dell_disk_data.get("Slot")
            storage_port = dell_disk_data.get("Connector")

        interface_speed = None
        if drive_response.get("NegotiatedSpeedGbs") is not None:
            interface_speed = int(drive_response.get("NegotiatedSpeedGbs")) * 1000

        encrypted = None
        if drive_response.get("EncryptionStatus") is not None:
            if drive_response.get("EncryptionStatus").lower() == "encrypted":
                encrypted = True
            else:
                encrypted = False

        pd_inventory = PhysicalDrive(
            # drive id repeats per controller
            # prefix drive id with controller id
            id = "{}:{}".format(controller_inventory.id,drive_response.get("Id")),
            name  = drive_response.get("Name"),
            health_status = status_data.get("Health"),
            operation_status = status_data.get("State"),
            model = drive_response.get("Model"),
            manufacturer = drive_response.get("Manufacturer"),
            firmware = drive_response.get("FirmwareVersion") or drive_response.get("Revision"),
            serial = drive_response.get("SerialNumber"),
            location = grab(drive_response, "Location.0.Info") or grab(drive_response, "PhysicalLocation.0.Info"),
            type = drive_response.get("MediaType"),
            speed_in_rpm = drive_response.get("RotationalSpeedRpm") or drive_response.get("RotationSpeedRPM"),
            failure_predicted = drive_response.get("FailurePredicted"),
            predicted_media_life_left_percent = drive_response.get("PredictedMediaLifeLeftPercent"),
            part_number = drive_response.get("PartNumber"),
            size_in_byte = disk_size,
            power_on_hours = power_on_hours,
            interface_type = drive_response.get("Protocol"),
            interface_speed = interface_speed,
            encrypted = encrypted,
            storage_port = storage_port,
            bay = bay,
            temperature = temperature,
            system_ids = system_response.get("Id"),
            storage_controller_ids = controller_inventory.id
        )

        if args.verbose:
            pd_inventory.source_data = drive_response

        plugin.inventory.add(pd_inventory)

        plugin.inventory.append(StorageController, controller_inventory.id, "physical_drive_ids", pd_inventory.id)

        if pd_inventory.location is None or pd_inventory.name == pd_inventory.location:
            location_string = ""
        else:
            location_string = f"{pd_inventory.location} "

        if pd_inventory.health_status is not None:
            drives_status_list.append(pd_inventory.health_status)

        if pd_inventory.size_in_byte is not None and pd_inventory.size_in_byte > 0:
            size_string = "%0.2fGiB" % (pd_inventory.size_in_byte / ( 1000 ** 3))
        else:
            size_string = "0GiB"

        status_text = f"Physical Drive {pd_inventory.name} {location_string}({pd_inventory.model} / {pd_inventory.type} / {pd_inventory.interface_type}) {size_string} status: {pd_inventory.health_status}"

        plugin.add_output_data("OK" if pd_inventory.health_status in ["OK", None] else pd_inventory.health_status, status_text)

    def get_volumes(volumes_link):

        volumes_response = plugin.rf.get(volumes_link)

        if len(volumes_response.get("Members")) == 0:
            return

        for volume_member in volumes_response.get("Members"):

            volume_data = plugin.rf.get(volume_member.get("@odata.id"))

            if volume_data.get("Name") is None:
                continue

            # get status data
            status_data = get_status_data(volume_data.get("Status"))

            # get size
            size = volume_data.get("CapacityBytes") or 0
            if size is not None:
                printed_size = int(size) / ( 1000 ** 3)
            else:
                printed_size = 0

            name = volume_data.get("Name")

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

            ld_inventory = LogicalDrive(
                # logical drive id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id, volume_data.get("Id")),
                name = volume_name,
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                type = volume_data.get("VolumeType"),
                size_in_byte = size,
                raid_type = raid_level,
                encrypted = volume_data.get("Encrypted"),
                system_ids = system_response.get("Id"),
                storage_controller_ids = controller_inventory.id
            )

            if args.verbose:
                ld_inventory.source_data = volume_data

            data_drives_links = grab(volume_data, "Links.Drives")

            if data_drives_links is not None:

                for data_drive in data_drives_links:
                    data_drive_id = ("{}:{}".format(
                        controller_inventory.id, data_drive.get("@odata.id").rstrip("/").split("/")[-1]))

                    ld_inventory.update("physical_drive_ids", data_drive_id, True)
                    plugin.inventory.append(PhysicalDrive, data_drive_id, "logical_drive_ids", ld_inventory.id)

            if ld_inventory.health_status is not None:
                volume_status_list.append(ld_inventory.health_status)

            plugin.inventory.add(ld_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "logical_drive_ids", ld_inventory.id)

            status_text = "Logical Drive %s (%s) %.0fGiB (%s) Status: %s" % \
                (name, ld_inventory.name, printed_size, ld_inventory.raid_type, ld_inventory.health_status)

            plugin.add_output_data("OK" if ld_inventory.health_status in ["OK", None] else ld_inventory.health_status, status_text)

    def get_enclosures(enclosure_link):

        # skip chassis listed as enclosures
        if enclosure_link in plugin.rf.connection.system_properties.get("chassis"):
            return

        enclosure_response = plugin.rf.get(enclosure_link)

        if enclosure_response.get("Name") is None:
            plugin.add_output_data("UNKNOWN", f"Unable to retrieve enclosure infos: {enclosure_link}")
            return

        chassis_type = enclosure_response.get("ChassisType")
        power_state = enclosure_response.get("PowerState")

        status_data = get_status_data(enclosure_response.get("Status"))

        enclosure_inventory = StorageEnclosure(
            # enclosure id repeats per controller
            # prefix drive id with controller id
            id = "{}:{}".format(controller_inventory.id, enclosure_response.get("Id")),
            name = enclosure_response.get("Name"),
            health_status = status_data.get("Health"),
            operation_status = status_data.get("State"),
            serial = enclosure_response.get("SerialNumber"),
            model = enclosure_response.get("Model"),
            manufacturer = enclosure_response.get("Manufacturer"),
            location = enclosure_response.get("Location"),
            firmware = enclosure_response.get("FirmwareVersion"),
            num_bays = enclosure_response.get("DriveBayCount"),
            storage_controller_ids = controller_inventory.id,
            system_ids = system_response.get("Id")
        )

        if args.verbose:
            enclosure_inventory.source_data = enclosure_response

        # set relation between disk drives and enclosures
        data_drives_links = grab(enclosure_response, "Links.Drives")

        if data_drives_links is not None:

            for data_drive in data_drives_links:
                data_drive_id = ("{}:{}".format(
                    controller_inventory.id, data_drive.get("@odata.id").rstrip("/").split("/")[-1]))

                enclosure_inventory.update("physical_drive_ids", data_drive_id, True)
                plugin.inventory.append(PhysicalDrive, data_drive_id, "storage_enclosure_ids", enclosure_inventory.id)

        plugin.inventory.add(enclosure_inventory)

        plugin.inventory.append(StorageController, controller_inventory.id, "storage_enclosure_ids", enclosure_inventory.id)

        if enclosure_inventory.health_status is not None:
            enclosure_status_list.append(enclosure_inventory.health_status)

        status_text = f"{chassis_type} {enclosure_inventory.name} (Power: {power_state}) Status: {enclosure_inventory.health_status}"

        plugin.add_output_data("OK" if enclosure_inventory.health_status in ["OK", None] else enclosure_inventory.health_status, status_text)

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

                    status_data = get_status_data(storage_controller.get("Status"))

                    controller_oem_data = grab(storage_controller, f"Oem.{plugin.rf.vendor_dict_key}")

                    cache_size_in_mb = None
                    backup_power_present = False
                    model = storage_controller.get("Model")
                    if controller_oem_data is not None:
                        cache_size_in_mb = controller_oem_data.get("MemorySizeMiB")
                        if controller_oem_data.get("Type") is not None:
                            model = controller_oem_data.get("Type")
                        if controller_oem_data.get("CapacitanceStatus") is not None:
                            backup_power_present = True
                        if controller_oem_data.get("BackupUnit") is not None:
                            backup_power_present = True

                    # Cisco
                    if controller_response.get("Id") is None:
                        controller_response["Id"] = controller_response.get("@odata.id").rstrip("/").split("/")[-1]

                    if storage_controller.get("MemberId") is not None and \
                            controller_response.get("Id") != storage_controller.get("MemberId"):
                        id = "{}:{}".format(controller_response.get("Id"), storage_controller.get("MemberId"))
                    else:
                        id = controller_response.get("Id")

                    controller_inventory = StorageController(
                        id = id,
                        name  = storage_controller.get("Name"),
                        health_status = status_data.get("Health"),
                        operation_status = status_data.get("State"),
                        model = model,
                        manufacturer = storage_controller.get("Manufacturer"),
                        firmware = storage_controller.get("FirmwareVersion"),
                        serial = storage_controller.get("SerialNumber"),
                        location = grab(storage_controller, f"Oem.{plugin.rf.vendor_dict_key}.Location.Info"),
                        backup_power_present = backup_power_present,
                        cache_size_in_mb = cache_size_in_mb,
                        system_ids = system_response.get("Id")
                    )

                    if args.verbose:
                        controller_inventory.source_data = controller_response

                    if controller_inventory.name is None:
                        controller_inventory.name = "Storage controller"

                    plugin.inventory.add(controller_inventory)

                    # ignore absent controllers
                    if controller_inventory.operation_status == "Absent":
                        continue

                    if controller_inventory.health_status is not None:
                        storage_status_list.append(controller_inventory.health_status)

                    storage_controller_names_list.append(f"{controller_inventory.name} {controller_inventory.model}")
                    storage_controller_id_list.append(controller_response.get("@odata.id"))

                    if controller_inventory.location is None:
                        location_string = ""
                    else:
                        location_string = f"{controller_inventory.location} "

                    status_text = f"{controller_inventory.name} {controller_inventory.model} {location_string}(FW: {controller_inventory.firmware}) status is: {controller_inventory.health_status}"

                    plugin.add_output_data("OK" if controller_inventory.health_status in ["OK", None] else controller_inventory.health_status, status_text)

                    # Huawei
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

                status_data = get_status_data(simple_storage_controller_response.get("Status"))

                controller_inventory = StorageController(
                    id = simple_storage_controller_response.get("Id"),
                    name  = simple_storage_controller_response.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    model = simple_storage_controller_response.get("Description"),
                    system_ids = system_response.get("Id")
                )

                if args.verbose:
                    controller_inventory.source_data = simple_storage_controller_response

                plugin.inventory.add(controller_inventory)

                if status_data.get("State") != "Enabled":
                    continue

                if simple_storage_controller_response.get("Devices") is not None and len(simple_storage_controller_response.get("Devices")) > 0:

                    if controller_inventory.health_status is not None:
                        storage_status_list.append(controller_inventory.health_status)

                    storage_controller_names_list.append(f"{controller_inventory.name}")

                    status_text = f"{controller_inventory.name} status: {controller_inventory.health_status}"
                    plugin.add_output_data("OK" if controller_inventory.health_status in ["OK", None] else controller_inventory.health_status, status_text)

                    disk_id = 0
                    enclosure_id = 0
                    for simple_storage_device in simple_storage_controller_response.get("Devices"):

                        name = simple_storage_device.get("Name")
                        manufacturer = simple_storage_device.get("Manufacturer")
                        model = simple_storage_device.get("Model")
                        capacity = simple_storage_device.get("CapacityBytes")
                        status_data = get_status_data(simple_storage_device.get("Status"))

                        if capacity is not None:

                            disk_id += 1
                            pd_inventory = PhysicalDrive(
                                id = "{}:{}".format(controller_inventory.id,disk_id),
                                name = name,
                                health_status = status_data.get("Health"),
                                operation_status = status_data.get("State"),
                                model = model,
                                manufacturer = manufacturer,
                                size_in_byte = capacity,
                                system_ids = system_response.get("Id"),
                                storage_controller_ids = controller_inventory.id
                            )

                            plugin.inventory.add(pd_inventory)

                            plugin.inventory.append(StorageController, controller_inventory.id, "physical_drive_ids", pd_inventory.id)
                        else:

                            enclosure_id += 1

                            enclosure_inventory = StorageEnclosure(
                                id = "{}:{}".format(controller_inventory.id, enclosure_id),
                                name = name,
                                health_status = status_data.get("Health"),
                                operation_status = status_data.get("State"),
                                model = model,
                                manufacturer = system_response.get("Manufacturer"),
                                system_ids = system_response.get("Id"),
                                storage_controller_ids = controller_inventory.id
                            )

                            plugin.inventory.add(enclosure_inventory)

                            plugin.inventory.append(StorageController, controller_inventory.id, "storage_enclosure_ids", enclosure_inventory.id)

                        status_text = f"{manufacturer} {name} {model}"

                        if capacity is not None:
                            try:
                                status_text += " (size: %0.2f GiB)" % (int(capacity) / 1000 ** 3)
                            except Exception:
                                pass

                        # skip device if state is not "Enabled"
                        if status_data.get("State") != "Enabled":
                            continue

                        status = status_data.get("Health")

                        if status_data is not None:
                            drives_status_list.append(status)

                        status_text += f" status: {status}"

                        plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)


    # check additional drives
    system_drives = grab(system_response, f"Oem.{plugin.rf.vendor_dict_key}.StorageViewsSummary.Drives")

    if system_drives is not None:
        for system_drive in system_drives:
            drive_url = grab(system_drive, "Link/@odata.id", separator="/")
            if drive_url not in system_drives_list:
                system_drives_list.append(drive_url)
                # create placeholder for storage controller
                controller_inventory = StorageController(id = 0)
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

    if args.inventory is True:
        return

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

    # add chassi inventory here too
    if args.inventory is True:

        for chassi in plugin.rf.connection.system_properties.get("chassis"):
            get_single_chassi_info(chassi)

    return

def get_single_system_info(redfish_url):

    global plugin

    system_response = plugin.rf.get(redfish_url)

    if system_response is None:
        plugin.add_output_data("UNKNOWN", f"No system information data returned for API URL '{redfish_url}'")
        return

    # get model data
    model = system_response.get("Model")
    # Huawei system
    if plugin.rf.vendor == "Huawei":
        model = grab(system_response, f"Oem.{plugin.rf.vendor_dict_key}.ProductName")

    # get memory size
    mem_size = grab(system_response, "MemorySummary.TotalSystemMemoryGiB")

    # Dell system
    # just WHY?
    if plugin.rf.vendor == "Dell":
        mem_size = round(mem_size * 1024 ** 3 / 1000 ** 3)

    status_data = get_status_data(system_response.get("Status"))

    system_inventory = System(
        id = system_response.get("Id"),
        name = system_response.get("Name"),
        manufacturer = system_response.get("Manufacturer"),
        serial = system_response.get("SerialNumber"),
        health_status = status_data.get("Health"),
        operation_status = status_data.get("State"),
        power_state = system_response.get("PowerState"),
        bios_version = system_response.get("BiosVersion"),
        host_name = system_response.get("HostName"),
        indicator_led = system_response.get("IndicatorLED"),
        cpu_num = grab(system_response, "ProcessorSummary.Count"),
        part_number = system_response.get("PartNumber"),
        mem_size = mem_size,
        model = model,
        type = system_response.get("SystemType")
    )

    if args.verbose:
        system_inventory.source_data = system_response

    # add relations
    system_inventory.add_relation(plugin.rf.connection.system_properties, system_response.get("Links"))

    plugin.inventory.add(system_inventory)

    host_name = "NOT SET"
    if system_inventory.host_name is not None and len(system_inventory.host_name) > 0:
        host_name = system_inventory.host_name

    status_text  = f"Type: {system_inventory.manufacturer} {system_inventory.model} (CPU: {system_inventory.cpu_num}, MEM: {system_inventory.mem_size}GB)"
    status_text += f" - BIOS: {system_inventory.bios_version} - Serial: {system_inventory.serial} - Power: {system_inventory.power_state} - Name: {host_name}"

    plugin.add_output_data("CRITICAL" if system_inventory.health_status not in ["OK", "WARNING"] else system_inventory.health_status, status_text, summary = not args.detailed)

    if args.detailed is True:

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

def get_single_chassi_info(redfish_url):

    global plugin

    chassi_response = plugin.rf.get(redfish_url)

    # get status data
    status_data = get_status_data(chassi_response.get("Status"))

    chassi_inventory = Chassi(
        id = chassi_response.get("Id"),
        name = chassi_response.get("Name"),
        manufacturer = chassi_response.get("Manufacturer"),
        serial = chassi_response.get("SerialNumber"),
        health_status = status_data.get("Health"),
        operation_status = status_data.get("State"),
        sku = chassi_response.get("SKU"),
        indicator_led = chassi_response.get("IndicatorLED"),
        model = chassi_response.get("Model"),
        type = chassi_response.get("ChassisType")
    )

    if args.verbose:
        chassi_inventory.source_data = chassi_response

    # add relations
    chassi_inventory.add_relation(plugin.rf.connection.system_properties, chassi_response.get("Links"))

    plugin.inventory.add(chassi_inventory)

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

    # return gathered firmware information
    firmware_health_summary = "OK"
    for firmware_inventory in plugin.inventory.get(Firmware):

        firmware_health = "OK"

        if firmware_inventory.health_status is not None:

            if firmware_inventory.health_status == "CRITICAL":
                firmware_health = firmware_inventory.health_status
                firmware_health_summary = firmware_inventory.health_status

            if firmware_inventory.health_status == "WARNING":
                firmware_health = firmware_inventory.health_status
                if firmware_health_summary != "CRITICAL":
                    firmware_health_summary = firmware_inventory.health_status

        name = firmware_inventory.name
        id = ""
        if plugin.rf.vendor != "HPE" and firmware_inventory.id is not None and \
                firmware_inventory.name != firmware_inventory.id:

            id = f" ({firmware_inventory.id})"

        location = ""
        if firmware_inventory.location is not None:
            location = f" ({firmware_inventory.location})"

        if args.detailed is True:
            plugin.add_output_data(firmware_health, f"{name}{id}{location}: {firmware_inventory.version}")

    if args.detailed is False:
        plugin.add_output_data(firmware_health_summary, "Found %d firmware entries. Use '--detailed' option to display them." % len(plugin.inventory.get(Firmware)), summary = True)

    return

def get_firmware_info_hpe_ilo4(system_id):

    global plugin

    redfish_url = f"{system_id}/FirmwareInventory/"

    firmware_response = plugin.rf.get(redfish_url)

    fw_id = 0
    for key, firmware_entry in firmware_response.get("Current").items():

        for firmware_entry_object in firmware_entry:

            fw_id += 1

            firmware_inventory = Firmware(
                id = fw_id,
                name = firmware_entry_object.get("Name"),
                version = firmware_entry_object.get("VersionString"),
                location = firmware_entry_object.get("Location")
            )

            if args.verbose:
                firmware_inventory.source_data = firmware_entry_object

            plugin.inventory.add(firmware_inventory)

    return

def get_firmware_info_fujitsu(system_id, bmc_only=False):

    # there is room for improvement

    global plugin

    # list of dicts: keys: {name, version, location}
    firmware_entries = list()

    if plugin.rf.connection.system_properties is None:
            discover_system_properties()

    # get iRMC firmware
    manager_ids = plugin.rf.connection.system_properties.get("managers")

    if manager_ids is not None and len(manager_ids) > 0:

        manager_response = plugin.rf.get(manager_ids[0])

        # get configuration
        iRMCConfiguration_link = grab(manager_response, f"Oem/{plugin.rf.vendor_dict_key}/iRMCConfiguration/@odata.id", separator="/")

        iRMCConfiguration = None
        if iRMCConfiguration_link is not None:
            iRMCConfiguration = plugin.rf.get(iRMCConfiguration_link)

        irmc_firmware_informations = None
        firmware_information_link = grab(iRMCConfiguration, f"FWUpdate/@odata.id", separator="/")
        if firmware_information_link is not None:
            irmc_firmware_informations = plugin.rf.get(firmware_information_link)

        if irmc_firmware_informations is not None:
            for bmc_fw_bank in [ "iRMCFwImageHigh", "iRMCFwImageLow" ]:
                fw_info = irmc_firmware_informations.get(bmc_fw_bank)
                if fw_info is not None:
                    firmware_entries.append(
                        { "id": bmc_fw_bank,
                          "name": "%s iRMC" % fw_info.get("FirmwareRunningState"),
                          "version": "%s, Booter %s, SDDR: %s/%s (%s)" % (
                            fw_info.get("FirmwareVersion"),
                            fw_info.get("BooterVersion"),
                            fw_info.get("SDRRVersion"),
                            fw_info.get("SDRRId"),
                            fw_info.get("FirmwareBuildDate")
                          ),
                          "location": "System Board"
                        }
                    )

        # special case:
        #   Firmware information was requested from bmc check.
        #   So we just return the bmc firmware list
        if bmc_only is True:
         return firmware_entries

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
                        "id": f"{ps_location}",
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
                drive_storage_controller = controller_response.get("Id")

                firmware_entries.append({
                    "id": f"Drive:{drive_storage_controller}:{drive_slot}",
                    "name": f"Drive {drive_name}",
                    "version": f"{drive_firmware}",
                    "location": f"{drive_storage_controller}:{drive_slot}"
                })

    # get other firmware
    redfish_url = f"{system_id}/Oem/%s/FirmwareInventory/" % plugin.rf.vendor_dict_key

    system_id_num = system_id.rstrip("/").split("/")[-1]

    firmware_response = plugin.rf.get(redfish_url)

    # get BIOS
    if firmware_response.get("SystemBIOS"):
        firmware_entries.append({
            "id": f"System:{system_id_num}",
            "name": "SystemBIOS",
            "version": "%s" % firmware_response.get("SystemBIOS"),
            "location": "System Board"
        })

    # get other components
    for key, value in firmware_response.items():

        if key.startswith("@"):
            continue

        if isinstance(value, dict) and value.get("@odata.id") is not None:
            component_type = value.get("@odata.id").rstrip("/").split("/")[-1]
            component_fw_data = plugin.rf.get(value.get("@odata.id"))

            if component_fw_data.get("Ports") is not None and len(component_fw_data.get("Ports")) > 0:

                component_id = 0
                for component_entry in component_fw_data.get("Ports"):

                    component_id += 1

                    component_name = component_entry.get("AdapterName")
                    component_location = component_entry.get("ModuleName")
                    component_bios_version = component_entry.get("BiosVersion")
                    component_fw_version = component_entry.get("FirmwareVersion")
                    component_slot = component_entry.get("SlotId")
                    component_port = component_entry.get("PortId")

                    firmware_entries.append({
                        "id": f"{component_type}_Port_{component_id}",
                        "name": f"{component_name}",
                        "version": f"{component_fw_version} (BIOS: {component_bios_version})",
                        "location": f"{component_location} {component_slot}/{component_port}"
                    })

            if component_fw_data.get("Adapters") is not None and len(component_fw_data.get("Adapters")) > 0:

                component_id = 0
                for component_entry in component_fw_data.get("Adapters"):

                    component_id += 1

                    component_name = component_entry.get("ModuleName")
                    component_pci_segment = component_entry.get("PciSegment")
                    component_bios_version = component_entry.get("BiosVersion")
                    component_fw_version = component_entry.get("FirmwareVersion")

                    firmware_entries.append({
                        "id": f"{component_type}_Adapter_{component_id}",
                        "name": f"{component_name} controller",
                        "version": f"{component_fw_version} (BIOS: {component_bios_version})",
                        "location": f"{system_id_num}:{component_pci_segment}"
                    })

    # add firmware entry to inventory
    for fw_entry in firmware_entries:

        firmware_inventory = Firmware(**fw_entry)

        if args.verbose:
            firmware_inventory.source_data = fw_entry

        plugin.inventory.add(firmware_inventory)

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

    for firmware_member in firmware_response.get("Members"):

        if firmware_member.get("@odata.type"):
            firmware_entry = firmware_member
        else:
            firmware_entry = plugin.rf.get(firmware_member.get("@odata.id"))

        # get name and id
        component_name = firmware_entry.get("Name")
        component_id = firmware_entry.get("Id")

        if component_id == component_name and firmware_entry.get("SoftwareId") is not None:
            component_name = firmware_entry.get("SoftwareId")

        if component_id == None:
            component_id = component_name

        # get firmware version
        component_version = firmware_entry.get("Version")
        if component_version is not None:
            component_version = component_version.strip().replace("\n","")

        if grab(firmware_entry, f"Oem.{plugin.rf.vendor_dict_key}.FirmwareBuild") is not None:
            component_version = f"{component_version} %s" % grab(firmware_entry, f"Oem.{plugin.rf.vendor_dict_key}.FirmwareBuild")

        # get location
        component_location = grab(firmware_entry, f"Oem.{plugin.rf.vendor_dict_key}.PositionId")

        if plugin.rf.vendor == "HPE":
            component_location = grab(firmware_entry, f"Oem.{plugin.rf.vendor_dict_key}.DeviceContext")

        if component_location is None and firmware_entry.get("SoftwareId") is not None:
            component_location = firmware_entry.get("SoftwareId")

        # get status
        status_data = get_status_data(firmware_entry.get("Status"))

        firmware_inventory = Firmware(
            id = component_id,
            name = component_name,
            health_status = status_data.get("Health"),
            operation_status = status_data.get("State"),
            version = component_version,
            location = component_location,
            updateable = firmware_entry.get("Updateable")
        )

        if args.verbose:
            firmware_inventory.source_data = firmware_entry

        plugin.inventory.add(firmware_inventory)

    return

def get_bmc_info():

    global plugin

    plugin.set_current_command("BMC Info")

    managers = plugin.rf.connection.system_properties.get("managers")

    if managers is None or len(managers) == 0:
        plugin.add_output_data("UNKNOWN", "No 'managers' property found in root path '/redfish/v1'")
        return

    for manager in managers:

        get_bmc_info_generic(manager)

    return

def get_bmc_info_generic(redfish_url):

    global plugin

    """
    Possible Infos to add
    * NTP Status
    * NTP servers configured
    * BMC accounts
    * BIOS settings (maybe, varies a lot between vendors)
    """

    view_response = plugin.rf.get_view(f"{redfish_url}{plugin.rf.vendor_data.expand_string}")

    # HPE iLO 5 view
    if view_response.get("ILO"):
        manager_response = view_response.get("ILO")[0]
    else:
        manager_response = view_response

    # get model
    bmc_model = manager_response.get("Model")
    bmc_fw_version = manager_response.get("FirmwareVersion")

    if plugin.rf.vendor == "HPE":
        bmc_model = " ".join(bmc_fw_version.split(" ")[0:2])

    if plugin.rf.vendor == "Dell":
        if bmc_model == "13G Monolithic":
            bmc_model = "iDRAC 8"
        if bmc_model == "14G Monolithic":
            bmc_model = "iDRAC 9"

    status_text = f"{bmc_model} (Firmware: {bmc_fw_version})"

    # get status data
    status_data = get_status_data(manager_response.get("Status"))
    manager_inventory = Manager(
        id = manager_response.get("Id"),
        type = manager_response.get("ManagerType"),
        name = manager_response.get("Name"),
        health_status = status_data.get("Health"),
        operation_status = status_data.get("State"),
        model = bmc_model,
        firmware = bmc_fw_version
    )

    if args.verbose:
        manager_inventory.source_data = manager_response

    # add relations
    manager_inventory.add_relation(plugin.rf.connection.system_properties, manager_response.get("Links"))

    plugin.inventory.add(manager_inventory)

    # workaround for older ILO versions
    if manager_inventory.health_status is not None:
        bmc_status = manager_inventory.health_status
    elif manager_inventory.operation_status == "Enabled":
        bmc_status = "OK"
    else:
        bmc_status = "UNKNOWN"

    plugin.add_output_data("CRITICAL" if bmc_status not in ["OK", "WARNING"] else bmc_status, status_text)

    # BMC Network interfaces
    manager_nic_response = None

    if plugin.rf.vendor == "HPE" and view_response.get("ILOInterfaces") is not None:
        manager_nic_response = { "Members": view_response.get("ILOInterfaces") }
    else:
        manager_nics_link = grab(manager_response, "EthernetInterfaces/@odata.id", separator="/")
        if manager_nics_link is not None:
            manager_nic_response = plugin.rf.get(f"{manager_nics_link}{plugin.rf.vendor_data.expand_string}")

    if manager_nic_response is not None:

        if manager_nic_response.get("Members") is None or len(manager_nic_response.get("Members")) == 0:

            status_text = f"{status_text} but no informations about the BMC network interfaces found"
        else:

            #if args.detailed is False:
            status_text = f"{status_text} and all nics are in 'OK' state."

            for manager_nic_member in manager_nic_response.get("Members"):

                if manager_nic_member.get("@odata.context"):
                    manager_nic = manager_nic_member
                else:
                    manager_nic = plugin.rf.get(manager_nic_member.get("@odata.id"))

                status_data = get_status_data(manager_nic.get("Status"))

                def get_ip_adresses(type):

                    list_of_addresses = list()

                    ip_addresses = grab(manager_nic, type)

                    # Cisco
                    if isinstance(ip_addresses, dict):
                        if ip_addresses.get("Address") is not None:
                            list_of_addresses.append(ip_addresses.get("Address"))

                    if isinstance(ip_addresses, list):
                        for ip_address in ip_addresses:
                            if ip_address.get("Address") is not None:
                                list_of_addresses.append(ip_address.get("Address"))

                    list_of_addresses = list(set(list_of_addresses))

                    return [address for address in list_of_addresses if address not in ['::', '0.0.0.0']]

                # get and sanitize MAC address
                mac_address = manager_nic.get("PermanentMACAddress")
                if mac_address is not None:
                    mac_address = mac_address.upper()

                if plugin.rf.vendor == "Dell":
                    id = manager_nic.get("Id")
                else:
                    id = "{}:{}".format(manager_inventory.id,manager_nic.get("Id"))

                network_inventory = NIC(
                    id = id,
                    name = manager_nic.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    current_speed = manager_nic.get("SpeedMbps"),
                    autoneg = manager_nic.get("AutoNeg"),
                    full_duplex = manager_nic.get("FullDuplex"),
                    hostname = manager_nic.get("HostName"),
                    mac_address = mac_address,
                    manager_ids = manager_inventory.id,
                    system_ids = manager_inventory.system_ids,
                    chassi_ids = manager_inventory.chassi_ids,
                    ipv4_addresses = get_ip_adresses("IPv4Addresses"),
                    ipv6_addresses = get_ip_adresses("IPv6Addresses"),
                    link_type = "Ethernet",
                    link_status = manager_nic.get("LinkStatus")
                )

                if args.verbose:
                    network_inventory.source_data = manager_nic

                plugin.inventory.add(network_inventory)

                if plugin.rf.vendor == "Cisco" and manager_nic.get("InterfaceEnabled") is True:
                    network_inventory.operation_status = "Enabled"

                # Huawei is completely missing any status information
                if plugin.rf.vendor == "Huawei" and network_inventory.operation_status is None:
                    network_inventory.operation_status = "Enabled"

                nic_status = None
                if network_inventory.health_status:
                    nic_status = network_inventory.health_status
                elif network_inventory.operation_status == "Enabled":
                    nic_status = "OK"
                else:
                    nic_status = "UNKNOWN"

                if network_inventory.operation_status in ["Disabled", None]:
                    continue

                host_name = network_inventory.hostname or "no hostname set"

                ip_addresses_string = None
                ip_addresses = [*network_inventory.ipv4_addresses, *network_inventory.ipv6_addresses]
                if len(ip_addresses) > 0:
                    ip_addresses_string = "/".join(ip_addresses)

                duplex = autoneg = None
                if network_inventory.full_duplex is not None:
                    duplex = "full" if network_inventory.full_duplex is True else "half"
                if network_inventory.autoneg is not None:
                    autoneg = "on" if network_inventory.autoneg is True else "off"

                nic_status_text  = f"NIC {network_inventory.id} '{host_name}' (IPs: {ip_addresses_string}) "
                nic_status_text += f"(speed: {network_inventory.current_speed}, autoneg: {autoneg}, duplex: {duplex}) status: {nic_status}"

                plugin.add_output_data("CRITICAL" if nic_status not in ["OK", "WARNING"] else nic_status, nic_status_text)

    # get license information
    # get vendor informations
    vendor_data = grab(manager_response, f"Oem.{plugin.rf.vendor_dict_key}")

    bmc_licenses = list()
    if plugin.rf.vendor == "HPE":

        ilo_license_string = grab(vendor_data, "License.LicenseString")
        ilo_license_key = grab(vendor_data, "License.LicenseKey")

        bmc_licenses.append(f"{ilo_license_string} ({ilo_license_key})")

    elif plugin.rf.vendor == "Lenovo":

        fod_link = grab(vendor_data, "FoD/@odata.id", separator="/")

        if fod_link is not None:
            fod_data = plugin.rf.get(f"{fod_link}/Keys{plugin.rf.vendor_data.expand_string}")

            if fod_data.get("Members") is None or len(fod_data.get("Members")) > 0:

                for fod_member in fod_data.get("Members"):
                    if manager_nic_member.get("@odata.context"):
                        licenses_data = fod_member
                    else:
                        licenses_data = plugin.rf.get(fod_member.get("@odata.id"))

                    lic_status = licenses_data.get("Status") # valid
                    lic_expire_date = licenses_data.get("Expires") # NO CONSTRAINTS
                    lic_description = licenses_data.get("Description")

                    license_string = f"{lic_description}"
                    if lic_expire_date != "NO CONSTRAINTS":
                        license_string += " (expires: {lic_expire_date}"

                    license_string += f" Status: {lic_status}"
                    bmc_licenses.append(license_string)

    elif plugin.rf.vendor == "Fujitsu":

        # get configuration
        iRMCConfiguration_link = grab(vendor_data, f"iRMCConfiguration/@odata.id", separator="/")

        iRMCConfiguration = None
        if iRMCConfiguration_link is not None:
            iRMCConfiguration = plugin.rf.get(iRMCConfiguration_link)

        license_informations = None
        license_informations_link = grab(iRMCConfiguration, f"Licenses/@odata.id", separator="/")
        if license_informations_link is not None:
            license_informations = plugin.rf.get(license_informations_link)

        if license_informations is not None and license_informations.get("Keys@odata.count") > 0:
            for bmc_license in license_informations.get("Keys"):
                bmc_licenses.append("%s (%s)" % ( bmc_license.get("Name"), bmc_license.get("Type")))

    elif plugin.rf.vendor == "Huawei":

        ibmc_license_link = vendor_data.get("LicenseService")

        if ibmc_license_link is not None and len(ibmc_license_link) > 0:
            ibmc_lic = plugin.rf.get(ibmc_license_link.get("@odata.id"))

            bmc_licenses.append("%s (%s)" % ( ibmc_lic.get("InstalledStatus"), ibmc_lic.get("LicenseClass")))

    manager_inventory.licenses = bmc_licenses

    for bmc_license in bmc_licenses:
        plugin.add_output_data("OK", f"License: {bmc_license}")

    # HP ILO specific stuff
    if plugin.rf.vendor == "HPE":

        # iLO Self Test
        for self_test in vendor_data.get("iLOSelfTestResults"):

            self_test_status = self_test.get("Status")

            if self_test_status in ["Informational", None]:
                continue

            self_test_status = self_test_status.upper()

            self_test_name = self_test.get("SelfTestName")
            self_test_notes = self_test.get("Notes")

            if self_test_notes is not None and len(self_test_notes) != 0:
                self_test_notes = self_test_notes.strip()
                self_test_status_text = f"SelfTest {self_test_name} ({self_test_notes}) status: {self_test_status}"
            else:
                self_test_status_text = f"SelfTest {self_test_name} status: {self_test_status}"

            plugin.add_output_data("CRITICAL" if self_test_status not in ["OK", "WARNING"] else self_test_status, self_test_status_text)

    # Lenovo specific stuff
    if plugin.rf.vendor == "Lenovo":
        redfish_chassi_url = grab(manager_response, "Links/ManagerForChassis/0/@odata.id", separator="/")

        chassi_response = None
        if redfish_chassi_url is not None:
            chassi_response = plugin.rf.get(redfish_chassi_url)

        located_data = grab(chassi_response, f"Oem.{plugin.rf.vendor_dict_key}.LocatedIn")

        if located_data is not None:
            descriptive_name = located_data.get("DescriptiveName")
            rack = located_data.get("Rack")

            system_name_string = f"System name: {descriptive_name} ({rack})"
            if args.detailed:
                plugin.add_output_data("OK", system_name_string)
            else:
                status_text += f" {system_name_string}"

    # get running firmware informations from Fujitsu server
    if plugin.rf.vendor == "Fujitsu":

        for bmc_firmware in get_firmware_info_fujitsu(redfish_url,True):
            plugin.add_output_data("OK", "Firmware: %s: %s" % (bmc_firmware.get("name"), bmc_firmware.get("version")))

    # get Huawei Server location data
    if plugin.rf.vendor == "Huawei":

        ibmc_location = vendor_data.get("DeviceLocation")
        if ibmc_location is not None and len(ibmc_location) > 0:

            location_string = f"Location: {ibmc_location}"
            if args.detailed:
                plugin.add_output_data("OK", location_string)
            else:
                status_text += f" {location_string}"


    plugin.add_output_data("CRITICAL" if bmc_status not in ["OK", "WARNING"] else bmc_status, status_text, summary = True)

    return

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
