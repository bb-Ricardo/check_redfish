# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2024 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import os
import tempfile
import pickle
import json
import pprint
import sys
import time


from cr_module.common import grab
from cr_module.classes import plugin_status_types
from cr_module.classes.vendor import *

# import 3rd party modules
import redfish

# defaults
default_conn_max_retries = 3
default_conn_timeout = 7


# noinspection PyBroadException
class RedfishConnection:

    session_file_path = None
    session_file_lock = None
    session_was_restored = False
    connection = None
    username = None
    password = None
    __cached_data = dict()
    vendor = None
    vendor_dict_key = None
    vendor_data = None
    cli_args = None
    desired_session_file_mode = 0o600

    def __init__(self, cli_args=None):

        if cli_args is None:
            raise Exception("No args passed to RedfishConnection()")

        if cli_args.host is None:
            raise Exception("cli args host not set")

        self.cli_args = cli_args

        if self.cli_args.nosession is False:
            self.session_file_path = self.get_session_file_name()
            self.session_file_lock = self.session_file_path + ".lock"
            self.restore_session_from_file()

        self.init_connection()

    def exit_on_error(self, message, level="UNKNOWN"):
        self.remove_session_lock()
        print(f"[{level}]: {message}")
        exit(plugin_status_types.get(level))

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

        # 2. an authentication file is defined, lets try to parse it
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
                self.exit_on_error(f"Provided authentication file not found: {self.cli_args.authfile}")
            except PermissionError:
                self.exit_on_error(f"Error opening authentication file: {self.cli_args.authfile}")
            except Exception as e:
                self.exit_on_error(
                    f"Unknown exception while trying to open authentication file {self.cli_args.authfile}: {e}")

            if self.username is None or self.password is None:
                self.exit_on_error(f"Error parsing authentication file '{self.cli_args.authfile}'. "
                                   "Make sure username and password are set properly.")

            return

        # 3. try to read credentials from environment
        self.username = os.getenv(env_username_var)
        self.password = os.getenv(env_password_var)

        return

    def get_session_file_name(self):

        default_session_file_prefix = "check_redfish"
        default_session_file_suffix = ".session"

        if self.cli_args.sessionfiledir:
            session_file_dir = self.cli_args.sessionfiledir
        else:
            session_file_dir = tempfile.gettempdir()

        # check if directory is a file
        if os.path.isfile(session_file_dir):
            self.exit_on_error(f"The session file destination ({session_file_dir}) seems to be file.")

        # check if directory exists
        if not os.path.exists(session_file_dir):
            # try to create directory
            try:
                os.makedirs(session_file_dir, 0o700)
            except OSError:
                self.exit_on_error(f"Unable to create session file directory: {session_file_dir}.")
            except Exception as e:
                self.exit_on_error(f"Unknown exception while creating session file directory {session_file_dir}: {e}")

        # check if directory is writable
        if not os.access(session_file_dir, os.X_OK | os.W_OK):
            self.exit_on_error(f"Error writing to session file directory: {session_file_dir}")

        # get full path to session file
        # also try to migrate from "older" session file naming schema
        old_sessionfilename = None
        if self.cli_args.sessionfile:
            sessionfilename = self.cli_args.sessionfile
        else:
            try:
                current_user_id = os.getuid()
            except Exception:
                current_user_id = None

            if current_user_id is not None:
                sessionfilename = f"{default_session_file_prefix}_{current_user_id}_{self.cli_args.host}"
                old_sessionfilename = f"{default_session_file_prefix}_{self.cli_args.host}"
            else:
                sessionfilename = f"{default_session_file_prefix}_{self.cli_args.host}"

        sessionfilepath = os.path.normpath(session_file_dir) + os.sep + sessionfilename + default_session_file_suffix

        # try to migrate
        if old_sessionfilename is not None:
            old_sessionfilepath = os.path.normpath(session_file_dir) + os.sep + old_sessionfilename + \
                                  default_session_file_suffix

            if not os.path.exists(sessionfilepath) and os.path.exists(old_sessionfilepath):

                # move session file
                try:
                    os.rename(old_sessionfilepath, sessionfilepath)

                # fail silently and create a new file with a new session
                except Exception:
                    pass

        if os.path.exists(sessionfilepath) and not os.access(sessionfilepath, os.R_OK):
            self.exit_on_error(f"Got no permission to read existing session file: {sessionfilepath}")

        if os.path.exists(sessionfilepath) and not os.access(sessionfilepath, os.W_OK):
            self.exit_on_error(f"Got no permission to write to existing session file: {sessionfilepath}")

        return sessionfilepath

    def restore_session_from_file(self):

        if self.session_file_path is None:
            raise Exception("sessionfilepath not set.")

        try:
            # try to fix file mode before opening the file
            session_file_mode = oct(os.stat(self.session_file_path).st_mode & 0o777)
            if session_file_mode != self.desired_session_file_mode:
                os.chmod(self.session_file_path, self.desired_session_file_mode)

            # try opening the session file
            with open(self.session_file_path, 'rb') as pickled_session:
                self.connection = pickle.load(pickled_session)
        except (FileNotFoundError, EOFError):
            pass
        except PermissionError as e:
            self.exit_on_error(f"Error opening session file: {e}")
        except Exception as e:
            self.exit_on_error(
                f"Unknown exception while trying to open session file {self.session_file_path}: {e}")

        # restore root attribute as RisObject
        # unfortunately we have to re implement the code from get_root_object function
        try:
            root_data = json.loads(self.connection.root_resp.text)
        except AttributeError:
            root_data = None
        except ValueError:
            raise

        if root_data is not None:
            self.connection.root = redfish.rest.v1.RisObject.parse(root_data)

        # set possible changed connection values
        if self.connection is not None:
            self.connection._max_retry = self.cli_args.retries
            self.connection._timeout = self.cli_args.timeout

        self.session_was_restored = True

        return
    
    def remove_session_lock(self):
        if self.cli_args.sessionlock is True and \
                self.session_file_path is not None and \
                os.path.exists(self.session_file_lock):

            try:
                os.remove(self.session_file_lock)
            except Exception as e:
                self.cli_args.sessionlock = False
                self.exit_on_error(f"Unable to remove session lock '{self.session_file_lock}': {e}")

    def is_session_locked(self):
        if self.cli_args.sessionlock is False or \
                self.session_file_path is None or \
                os.path.exists(self.session_file_lock) is False:
            return False

        lock_time = None
        try:
            with open(self.session_file_lock, 'r') as lock_file:
                lock_time = float(lock_file.read().strip())
        except Exception as e:
            self.exit_on_error(f"Unable to read session lock '{self.session_file_lock}': {e}")

        # session lock should not exist much longer than the connection timeout with retries.
        if time.time() - lock_time >= self.cli_args.timeout * self.cli_args.retries + 5:
            self.remove_session_lock()
            return False

        return True

    def write_session_lock(self):
        if self.cli_args.sessionlock is True and \
                self.session_file_path is not None and \
                os.path.exists(self.session_file_path):

            try:
                with open(self.session_file_lock, 'w') as handle:
                    handle.write(str(time.time()))
            except Exception as e:
                self.exit_on_error(f"Unable to write session lock '{self.session_file_lock}': {e}")
        
    def save_session_to_file(self):

        if self.session_file_path is None:
            raise Exception("sessionfilepath not set")

        if self.connection is None:
            raise Exception("session not initialized")

        # unset root attribute as it's a RisObject which can't be pickled
        root_data = self.connection.root
        self.connection.root = None

        # fix for change in redfish 2.0.10
        # Socket objects can't be pickled. Remove socket object from pickle object and add it back later on
        # not needed anymore since redfish 3.10 but added a compatible mode

        connection_socket = None
        connection_socket_count = None
        if hasattr(self.connection, "_conn"):
            connection_socket = self.connection._conn
            connection_socket_count = self.connection._conn_count
            self.connection._conn = None
            self.connection._conn_count = 0

        # create file handle file descriptor
        umask_original = os.umask(0o777 ^ self.desired_session_file_mode)
        session_file_handle = None
        try:
            session_file_handle = os.open(self.session_file_path,
                                          os.O_WRONLY | os.O_CREAT,
                                          self.desired_session_file_mode)

        except PermissionError as e:
            self.exit_on_error(f"Error opening session file to save session: {e}")
        except Exception as e:

            # log out from current connection
            self.connection.logout()

            # try to delete session file
            try:
                os.remove(self.session_file_path)
            except Exception:
                pass

            self.exit_on_error(
                f"Unknown exception while trying to save session to file {self.session_file_path}: {e}")
        finally:
            os.umask(umask_original)

        if session_file_handle is not None:
            with os.fdopen(session_file_handle, 'wb') as pickled_session:
                pickle.dump(self.connection, pickled_session)

        # set root attribute again
        self.connection.root = root_data

        # restore connection object
        if connection_socket is not None:
            self.connection._conn = connection_socket
            self.connection._conn_count = connection_socket_count

        return

    def init_connection(self, reset=False):

        if self.is_session_locked():
            print("[UNKNOWN]: Session is connecting... Soon the status should be checked.")
            exit(3)

        # reset connection
        if reset is True:
            self.connection = None

        """
            Test for python-redfish lib version. If we unpickle old library sessions then
            the attribute '_session' is missing and the request will fail. Here we check
            if version is 3.1.0 or greater and invalidate the session if '_session' is missing.
        """
        if self.connection is not None:
            redfish_version = tuple(map(int, (redfish.__version__.split("."))))
            if len(redfish_version) >= 2 and \
                    redfish_version[0] >= 3 and \
                    redfish_version[1] >= 1:

                if hasattr(self.connection, "_session") is False:
                    self.connection = None
            else:
                if hasattr(self.connection, "_conn") is False:
                    self.connection = None

        # if we have a connection object then just return
        if self.connection is not None:
            return

        self.get_credentials()
        self.write_session_lock()

        # initialize connection
        try:
            self.connection = redfish.redfish_client(base_url=f"https://{self.cli_args.host}",
                                                     max_retry=self.cli_args.retries, timeout=self.cli_args.timeout)
        except redfish.rest.v1.ServerDownOrUnreachableError:
            self.exit_on_error(f"Host '{ self.cli_args.host}' down or unreachable.", "CRITICAL")
        except redfish.rest.v1.RetriesExhaustedError:
            self.exit_on_error(f"Unable to connect to Host '{self.cli_args.host}', max retries exhausted.",
                               "CRITICAL")
        except Exception as e:
            self.exit_on_error(f"Unable to connect to Host '{self.cli_args.host}': {e}", "CRITICAL")

        if not self.connection:
            raise Exception("Unable to establish connection.")

        if self.username is not None or self.password is not None:
            try:
                self.connection.login(username=self.username, password=self.password, auth="session")
            except redfish.rest.v1.RetriesExhaustedError:
                self.exit_on_error(f"Unable to connect to Host '{self.cli_args.host}', max retries exhausted.",
                                   "CRITICAL")
            except redfish.rest.v1.InvalidCredentialsError:
                self.exit_on_error("Username or password invalid.", "CRITICAL")
            except Exception as e:
                self.exit_on_error(f"Unable to connect to Host '{self.cli_args.host}': {e}", "CRITICAL")

        if self.connection is not None:
            self.connection.system_properties = None
            if self.cli_args.nosession is False:
                self.save_session_to_file()

        self.remove_session_lock()

        return

    def terminate_session(self):

        # don't bail out if session logout fails.
        # might leave dead sessions on the BMC
        try:
            self.connection.logout()
        except Exception:
            pass

    def _rf_get(self, redfish_path):

        try:
            return self.connection.get(redfish_path, None)
        except redfish.rest.v1.RetriesExhaustedError:
            self.exit_on_error(f"Unable to connect to Host '{self.cli_args.host}', max retries exhausted.", "CRITICAL")

    def get(self, redfish_path, max_members=None):

        if self.__cached_data.get(redfish_path) is None:

            redfish_response = self._rf_get(redfish_path)

            # session invalid
            if redfish_response.status == 401:
                self.get_credentials()
                if self.username is None or self.password is None:
                    self.exit_on_error(f"Username and Password needed to connect to this BMC")

            if (redfish_response.status is None or
                (redfish_response.status != 404 and redfish_response.status >= 400)) \
                    and self.session_was_restored is True:
                # reset connection
                self.init_connection(reset=True)

                # query again
                redfish_response = self._rf_get(redfish_path)

            # test if response is valid json and can be decoded
            redfish_response_json_data = dict({"Members": list()})
            if redfish_response.status != 404:
                try:
                    redfish_response_json_data = redfish_response.dict
                except Exception:
                    pass

            # retrieve all members from resource
            if redfish_response_json_data.get("Members") is not None:
                num_members = len(redfish_response_json_data.get("Members"))
                if num_members > 0 and redfish_response_json_data.get("Members@odata.nextLink") is not None and \
                        num_members != redfish_response_json_data.get("Members@odata.count"):

                    # disable expand for Dell
                    expand_string = self.vendor_data.expand_string if not self.vendor == "Dell" else ""
                    this_response = redfish_response_json_data

                    collected_entry_path_list = list()

                    # just to make sure to stop if for some reason we get unlimited nextLink
                    current_iteration = 0
                    while current_iteration <= 500:

                        entry_path = this_response.get("Members@odata.nextLink")

                        if entry_path is None or len(entry_path) == 0 or entry_path in collected_entry_path_list:
                            break

                        current_iteration += 1

                        if "?" in entry_path:
                            expand_string = expand_string.replace("?", "&", 1)

                        this_response = self._rf_get(f"{entry_path}{expand_string}").dict

                        collected_entry_path_list.append(entry_path)

                        if this_response.get("Members") is None or len(this_response.get("Members")) == 0:
                            break
                        else:
                            redfish_response_json_data["Members"].extend(this_response.get("Members"))

                        if max_members is not None and len(redfish_response_json_data.get("Members")) >= max_members:
                            break

            if self.cli_args.verbose:
                pprint.pprint(redfish_response_json_data, stream=sys.stderr)

            self.__cached_data[redfish_path] = redfish_response_json_data

        return self.__cached_data.get(redfish_path)

    @staticmethod
    def get_error(redfish_data, redfish_url):

        return_data = None
        if isinstance(redfish_data, dict) and redfish_data.get("error"):
            error = grab(redfish_data, "error/@Message.ExtendedInfo/0", separator="/")
            if error is not None:
                error_message = '%s/%s' % (error.get("MessageId"), error.get("Message"))
            else:
                error_message = redfish_data.get("error")

            return_data = f"got '{error_message}' for API path '{redfish_url}'"

        return return_data

    def _rf_post(self, redfish_path, body):

        try:
            return self.connection.post(redfish_path, body=body)
        except redfish.rest.v1.RetriesExhaustedError:
            self.exit_on_error(f"Unable to connect to Host '{self.cli_args.host}', max retries exhausted.", "CRITICAL")

    def get_view(self, redfish_path=None):

        if self.vendor_data is not None and \
                self.vendor_data.view_select is not None and \
                self.vendor_data.view_supported:

            if self.vendor_data.view_response:
                return self.vendor_data.view_response

            redfish_response = self._rf_post("/redfish/v1/Views/", self.vendor_data.view_select)

            # session invalid
            if redfish_response.status != 404 and redfish_response.status >= 400 and self.session_was_restored is True:
                # reset connection
                self.init_connection(reset=True)

                # query again
                redfish_response = self._rf_post("/redfish/v1/Views/", self.vendor_data.view_select)

            if redfish_response.status == 404:
                if redfish_path is not None:
                    return self.get(redfish_path)

            # test if response is valid json and can be decoded
            redfish_response_json_data = None
            try:
                redfish_response_json_data = redfish_response.dict
            except Exception:
                pass

            if redfish_response_json_data is not None:
                if self.cli_args.verbose:
                    pprint.pprint(redfish_response_json_data)

                if redfish_response_json_data.get("error"):
                    error = redfish_response_json_data.get("error").get("@Message.ExtendedInfo")
                    self.exit_on_error(
                        "get error '%s' for API path '%s'" % (error[0].get("MessageId"), error[0].get("MessageArgs")))

                self.vendor_data.view_response = redfish_response_json_data

                return self.vendor_data.view_response

        if redfish_path is not None:
            return self.get(redfish_path)

        return None

    def determine_vendor(self):

        vendor_string = ""

        if self.connection.root.get("Oem"):

            if len(self.connection.root.get("Oem")) > 0:
                vendor_string = list(self.connection.root.get("Oem"))[0]

            self.vendor_dict_key = vendor_string

        if vendor_string == "" and self.connection.root.get("Vendor") is not None:

            vendor_string = self.connection.root.get("Vendor")

            self.vendor_dict_key = vendor_string

        if vendor_string in ["Hpe", "Hp"]:

            self.vendor_data = VendorHPEData()

            manager_data = grab(self.connection.root, f"Oem.{vendor_string}.Manager.0")

            if manager_data is not None:
                self.vendor_data.ilo_version = manager_data.get("ManagerType")
                if self.vendor_data.ilo_version is None:
                    # Fix for iLO 5 version >2.3.0
                    self.vendor_data.ilo_version = \
                        grab(self.connection.root, f"Oem.{vendor_string}.Moniker.PRODGEN")

                self.vendor_data.ilo_firmware_version = manager_data.get("ManagerFirmwareVersion")
                if self.vendor_data.ilo_firmware_version is None:
                    # Fix for iLO 5 version >2.3.0
                    self.vendor_data.ilo_firmware_version = grab(manager_data, "Languages.0.Version")

                if self.vendor_data.ilo_version is None:
                    self.exit_on_error("Cannot determine HPE iLO version information.")

                if self.vendor_data.ilo_version.lower() == "ilo 5":
                    self.vendor_data.view_supported = True

        if vendor_string in ["Lenovo"]:

            self.vendor_data = VendorLenovoData()

        if vendor_string in ["Dell"]:

            self.vendor_data = VendorDellData()

        if vendor_string in ["Huawei"]:

            self.vendor_data = VendorHuaweiData()

        if vendor_string in ["ts_fujitsu"]:

            self.vendor_data = VendorFujitsuData()

        if vendor_string in ["Ami"]:

            self.vendor_data = VendorAmiData()

        if vendor_string in ["Supermicro"]:

            self.vendor_data = VendorSupermicro()

        # Cisco does not provide a OEM property in root object
        if "CIMC" in str(self.get_system_properties("managers")):

            self.vendor_data = VendorCiscoData()
            self.vendor_dict_key = self.vendor_data.name

        if self.vendor_data is None:

            self.vendor_data = VendorGeneric()

            if vendor_string is not None and len(vendor_string) > 0:
                self.vendor_data.name = vendor_string

        self.vendor = self.vendor_data.name

        return

    def discover_system_properties(self):

        if vars(self.connection).get("system_properties") is not None:
            return

        system_properties = dict()

        root_objects = ["Chassis", "Managers", "Systems"]

        for root_object in root_objects:

            system_properties[root_object.lower()] = list()

            if self.connection.root.get(root_object) is None:
                continue

            rf_path = self.get(self.connection.root.get(root_object).get("@odata.id"))

            if rf_path is None:
                continue

            for entity in rf_path.get("Members", list()):

                # mitigate an Inspur implementation bug
                if isinstance(entity, dict):
                    entity_url = entity.get("@odata.id")
                else:
                    entity_url = entity

                # ToDo:
                #  * This is a DELL workaround
                #  * If RAID chassi is requested the iDRAC will restart
                if root_object == "Chassis" and ("RAID" in entity_url or "Enclosure" in entity_url):
                    continue

                system_properties[root_object.lower()].append(entity_url)

        self.connection.system_properties = system_properties
        if self.cli_args.nosession is False:
            self.save_session_to_file()

        return

    def get_system_properties(self, requested_property=None):
        """
        get a list of links to system properties for requested_property
        i.e.:
            "systems" -> [ "/redfish/v1/Systems/1" ]

        if no property is requested the whole dict will be returned

        Parameters
        ----------
        requested_property: str
            can be either "chassis", "managers", "systems" or None

        Returns
        -------
            list, dict
                list of property links if requested_property was set or
                dict of all properties if no requested_property was set
        """

        if requested_property is not None and requested_property not in ["chassis", "managers", "systems"]:
            raise Exception(f"Invalid property '{requested_property}' requested.")

        if self.connection.system_properties is None:
            self.discover_system_properties()

        if self.connection.system_properties is not None:
            if requested_property is not None:
                return self.connection.system_properties.get(requested_property)
            else:
                return self.connection.system_properties

        return None
# EOF
