# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2023 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.
import datetime
import os

from cr_module.classes import plugin_status_types
from cr_module.classes.redfish import RedfishConnection
from cr_module.classes.inventory import Inventory
from cr_module.common import get_local_timezone


class PluginOutputDataEntry:

    state = "OK"
    command = None
    text = None
    location = None
    is_summary = False
    log_entry = False
    log_entry_date = None

    def __init__(self, state="OK", command=None, text=None, location=None, is_summary=False, is_log_entry=False,
                 log_entry_date=None):

        if state not in list(plugin_status_types.keys()):
            raise Exception(f"Status '{state}' is invalid, needs to be one of these: %s" %
                            list(plugin_status_types.keys()))

        self.state = state
        self.command = command
        self.text = text
        self.location = location
        self.is_summary = is_summary
        self.log_entry = is_log_entry
        self.log_entry_date = log_entry_date or datetime.datetime.fromtimestamp(0).replace(tzinfo=get_local_timezone())

    def output_text(self, add_location=False):

        return_text = self.text
        if add_location is True:
            return_text = f"{self.location} : {return_text}"

        return f"[{self.state}]: {return_text}"

    def __repr__(self):
        return self.__dict__


class PluginOutputData:

    __output_entries = list()

    def append(self, entry):

        if not isinstance(entry, PluginOutputDataEntry):
            raise Exception('Output entry must be a "PluginOutputDataEntry" object.')

        self.__output_entries.append(entry)

    def get_commands(self):

        return list(set([x.command for x in self.__output_entries]))

    def get_locations(self, command, summary):

        if not isinstance(summary, bool):
            summary = False

        locations = [x.location for x in self.__output_entries if x.is_summary is summary and x.command == command]

        if None in locations:
            locations.remove(None)

        return list(set(locations))

    def get_states(self, command, summary):

        if not isinstance(summary, bool):
            summary = False

        states = [x.state for x in self.__output_entries if x.is_summary is summary and x.command == command]

        if len(states) == 0:
            states.append("OK")

        return list(set(states))

    def get_command_entries(self, command):

        return [x for x in self.__output_entries if x.command == command]

    def __repr__(self):
        return [repr(x) for x in self.__output_entries]


class PluginData:

    rf = None
    inventory = None
    cli_args = None
    inventory_file = None

    __perf_data = list()
    __output_data = PluginOutputData()
    __return_status = "OK"
    __current_command = "global"
    __in_firmware_collection_mode = False

    # turns this class into a Singleton
    def __new__(cls, cli_args=None, plugin_version=None):
        it = cls.__dict__.get("__it__")
        if it is not None:
            return it
        cls.__it__ = it = object.__new__(cls)
        it.init(cli_args, plugin_version)
        return it

    def init(self, cli_args=None, plugin_version=None):

        if cli_args is None:
            raise Exception("No args passed to RedfishConnection()")

        self.cli_args = cli_args
        self._validate_inventory_file()
        self.rf = RedfishConnection(cli_args)

        self.inventory = Inventory(plugin_version, cli_args.inventory_id, cli_args.inventory_name)

    def in_firmware_collection_mode(self, enabled=False):

        self.__in_firmware_collection_mode = True if enabled is True else False

    def _validate_inventory_file(self):

        file_name = self.cli_args.inventory_file
        if file_name is None:
            return

        # will only work on POSIX systems
        # normalize file path
        if file_name[0] != os.sep:
            file_name = os.path.join(os.getcwd(), file_name)

        file_name = os.path.normpath(file_name)
        dir_name = os.path.dirname(file_name)

        # check if directory is a file
        if os.path.isfile(dir_name):
            self.exit_on_error(f"The inventory file destination '{dir_name}' seems to be file.")
        if os.path.isdir(file_name):
            self.exit_on_error(f"The inventory file destination '{file_name}' seems to be directory.")

        # check if directory exists
        if not os.path.exists(dir_name):
            # try to create directory
            try:
                os.makedirs(dir_name, 0o700)
            except OSError:
                self.exit_on_error(f"Unable to create inventory file directory: {dir_name}.")
            except Exception as e:
                self.exit_on_error(f"Unknown exception while creating inventory file directory {dir_name}: {e}")

        # check if directory is writable
        if not os.access(dir_name, os.X_OK | os.W_OK):
            self.exit_on_error(f"Error writing to inventory file directory: {dir_name}")

        if os.path.exists(file_name) and not os.access(file_name, os.W_OK):
            self.exit_on_error(f"Got no permission to write to existing inventory file: {file_name}")

        self.inventory_file = file_name

    def exit_on_error(self, text):

        self.add_output_data("UNKNOWN", text, summary=not self.cli_args.detailed)
        self.do_exit()

    def set_current_command(self, current_command):

        self.__current_command = current_command

    def set_status(self, state):

        if self.__in_firmware_collection_mode is True:
            return

        if self.__return_status == state:
            return

        if state not in list(plugin_status_types.keys()):
            raise Exception(f"Status '{state}' is invalid, needs to be one of these: %s" %
                            list(plugin_status_types.keys()))

        if plugin_status_types[state] > plugin_status_types[self.__return_status]:
            self.__return_status = state

    @staticmethod
    def return_highest_status(status_list):

        if not isinstance(status_list, list):
            raise ValueError("'status_list' must be of type list")

        status_list = list(set(status_list))
        if None in status_list:
            status_list.remove(None)

        if len(status_list) == 0:
            return

        status_list = list(set(status_list))

        return_status = status_list[0]

        for status in status_list:
            if status not in plugin_status_types.keys():
                continue

            if plugin_status_types[status] > plugin_status_types[return_status]:
                return_status = status

        return return_status

    def add_output_data(self, state, text, summary=False, location=None, is_log_entry=False, log_entry_date=None):

        if self.__in_firmware_collection_mode is True:
            return

        self.set_status(state)

        self.__output_data.append(PluginOutputDataEntry(state=state, command=self.__current_command,
                                                        text=text, location=location, is_summary=summary,
                                                        is_log_entry=is_log_entry, log_entry_date=log_entry_date
                                                        ))

    def add_perf_data(self, name, value, perf_uom=None, warning=None, critical=None, location=None):

        if self.__in_firmware_collection_mode is True:
            return

        perf_string = "'%s'=%s" % (name.replace(" ", "_"), value)

        if perf_uom is not None:
            perf_string += perf_uom

        if critical is not None and warning is None:
            warning = ""

        if warning is not None:
            perf_string += ";%s" % str(warning)

        if critical is not None:
            perf_string += ";%s" % str(critical)

        self.__perf_data.append(perf_string)

    def add_data_retrieval_error(self, class_name, redfish_data=None, redfish_url=None):

        if self.__in_firmware_collection_mode is True:
            return

        if isinstance(redfish_url, str):
            redfish_url = redfish_url.replace("//", "/")

        retrieval_error = self.rf.get_error(redfish_data, redfish_url)
        if retrieval_error is not None:
            retrieval_error = f"No {class_name.inventory_item_name} data returned for " \
                              f"API URL '{redfish_url}': {retrieval_error}"

        self.inventory.add_issue(class_name, retrieval_error)

    def return_output_data(self):

        ordered_output_data = dict()
        return_text = list()
        command_locations = dict()
        command_summary_locations = dict()
        problem_command = list()

        for command in sorted(self.__output_data.get_commands()):

            command_locations[command] = self.__output_data.get_locations(command, summary=False)
            command_summary_locations[command] = self.__output_data.get_locations(command, summary=True)

            log_most_recent = None
            log_entry_counter = dict()
            log_all_counter = 0

            output_entries = self.__output_data.get_command_entries(command)

            if "log" in command.lower():
                output_entries = sorted(output_entries, key=lambda x: x.log_entry_date, reverse=True)

            for entry in output_entries:
                if ordered_output_data.get(entry.state) is None:
                    ordered_output_data[entry.state] = list()

                if entry.log_entry is True:
                    if log_most_recent is None:
                        log_most_recent = entry

                    if plugin_status_types[entry.state] > plugin_status_types[log_most_recent.state]:
                        log_most_recent = entry

                    if self.cli_args.max is not None and log_all_counter >= self.cli_args.max:
                        continue

                    log_all_counter += 1

                    if log_entry_counter.get(entry.state):
                        log_entry_counter[entry.state] += 1
                    else:
                        log_entry_counter[entry.state] = 1

                ordered_output_data[entry.state].append(entry)

            # add log summary if command is a log command
            if log_most_recent is not None and log_most_recent.state == "OK":
                message_summary = " and ".join(["%d %s" % (value, key) for key, value in log_entry_counter.items()])

                log_text = f"{command} contains {message_summary} entries."
                if self.cli_args.detailed is False:
                    log_text += f" Most recent notable: {log_most_recent.output_text()}"

                ordered_output_data[log_most_recent.state].append(
                    PluginOutputDataEntry(state=log_most_recent.state, is_summary=True, text=log_text)
                )

        if self.__return_status != "OK":

            for status_type_name, _ in sorted(plugin_status_types.items(), key=lambda item: item[1], reverse=True):

                if status_type_name == "OK":
                    continue

                for entry in ordered_output_data.get(status_type_name, list()):
                    # add command to problem commands to avoid printing summary for this command
                    problem_command.append(entry.command)
                    add_location = True if len(command_locations.get(entry.command, list())) > 1 else False
                    return_text.append(entry.output_text(add_location))

        for entry in ordered_output_data.get("OK", list()):
            if entry.is_summary is True and entry.command not in problem_command:
                add_location = True if len(command_summary_locations.get(entry.command, list())) > 1 else False
                return_text.append(entry.output_text(add_location))

        if self.cli_args.detailed is True:
            for entry in ordered_output_data.get("OK", list()):
                if entry.is_summary is False:
                    add_location = True if len(command_locations.get(entry.command, list())) > 1 else False
                    return_text.append(entry.output_text(add_location))

        return_string = "\n".join(return_text)

        # append perf data if there is any
        if len(self.__perf_data) > 0:
            return_string += "|" + " ".join(self.__perf_data)

        return return_string

    def get_return_status(self, level=False):

        if level is True:
            return plugin_status_types[self.__return_status]

        return self.__return_status

    def do_exit(self):

        if self.cli_args.nosession is True:
            self.rf.terminate_session()

        # return inventory and exit with 0
        if self.cli_args.inventory is True and self.inventory is not None:
            inventory_json = self.inventory.to_json()
            if self.inventory_file is not None:

                try:
                    with open(self.inventory_file, 'w') as writer:
                        writer.write(inventory_json)
                except Exception as e:
                    self.set_status("UNKNOWN")
                    return_text = f"[UNKNOWN]: Unable to write to inventory file: {e}"
                    return_state = self.get_return_status(True)
                else:
                    return_state = 0
                    return_text = "[OK]: Successfully written inventory file"

                    if self.get_return_status() == "UNKNOWN":
                        return_text += " but inventory data might be incomplete"

                print(return_text)
                exit(return_state)
            else:
                print(inventory_json)
                exit(0)

        # add all retrieval issues to output
        if self.inventory is not None:
            for item_name, issues in self.inventory.get_issues().items():
                if len(self.inventory.get(item_name)) == 0:
                    self.add_output_data("UNKNOWN", "Request error: %s" % ", ".join(issues))

        print(self.return_output_data())

        exit(self.get_return_status(True))

# EOF
