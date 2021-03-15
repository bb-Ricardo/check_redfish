# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import os

from cr_module.classes import plugin_status_types
from cr_module.classes.redfish import RedfishConnection
from cr_module.classes.inventory import Inventory


class PluginData:

    rf = None
    inventory = None
    cli_args = None
    inventory_file = None

    __perf_data = list()
    __output_data = dict()
    __log_output_data = dict()
    __summary_data = dict()
    __return_status = "OK"
    __current_command = "global"
    __in_firmware_collection_mode = False

    def __init__(self, cli_args=None, plugin_version=None):

        if cli_args is None:
            raise Exception("No args passed to RedfishConnection()")

        self.cli_args = cli_args
        self._validate_inventory_file()
        self.rf = RedfishConnection(cli_args)

        self.inventory = Inventory(plugin_version, cli_args.inventory_id)

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
            if status is None:
                continue

            if plugin_status_types[status] > plugin_status_types[return_status]:
                return_status = status

        return return_status

    def add_output_data(self, state, text, summary=False, location=None):

        if self.__in_firmware_collection_mode is True:
            return

        self.set_status(state)

        status_data_entry = {
            "state": state,
            "text": text,
            "location": location,
            "summary": summary
        }

        if self.__output_data.get(self.__current_command) is None:
            self.__output_data[self.__current_command] = list()

        self.__output_data[self.__current_command].append(status_data_entry)

    def add_log_output_data(self, state, text):

        self.set_status(state)

        if self.__log_output_data.get(self.__current_command) is None:
            self.__log_output_data[self.__current_command] = list()

        self.__log_output_data[self.__current_command].append(
            {
                "status": state,
                "text": "[%s]: %s" % (state, text)
            }
        )

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
            retrieval_error = f"No {class_name.inventory_item_name} data returned for API URL '{redfish_url}'"

        self.inventory.add_issue(class_name, retrieval_error)

    def return_output_data(self):

        return_text = list()

        for command in self.__output_data.keys():

            # get state of non summary entries
            non_summary_states = [x.get("state") for x in self.__output_data[command] if x['summary'] is False]

            if len(non_summary_states) == 0:
                non_summary_states.append("OK")

            if self.return_highest_status(non_summary_states) == "OK" and self.cli_args.detailed is False:
                summary_locations = [x.get("location") for x in self.__output_data[command] if x['summary'] is True]
                summary_return_status = self.return_highest_status(
                    [x.get("state") for x in self.__output_data[command] if x['summary'] is True]
                )

                if None in summary_locations:
                    summary_locations.remove(None)

                summary_text_list = list()
                if len(set(summary_locations)) > 1:
                    for entry in [x for x in self.__output_data[command] if x['summary'] is True]:
                        summary_text_list.append("%s: %s" % (entry.get("location"), entry.get("text")))
                else:
                    summary_text_list = [x.get("text") for x in self.__output_data[command] if x['summary'] is True]

                return_text.append(f"[{summary_return_status}]: %s" % ", ".join(summary_text_list))

            else:
                entry_locations = [x.get("location") for x in self.__output_data[command] if x['summary'] is False]

                for status_type_name, _ in sorted(plugin_status_types.items(), key=lambda item: item[1], reverse=True):

                    entry_list = [x for x in self.__output_data[command]
                                  if x['summary'] is False and x["state"] == status_type_name]

                    if len(entry_list) == 0:
                        continue

                    if None in entry_locations:
                        entry_locations.remove(None)

                    for entry in entry_list:
                        if entry.get("state") != "OK" or self.cli_args.detailed is True:
                            entry_text = entry.get("text")
                            if len(set(entry_locations)) > 1:
                                entry_text = "%s: %s" % (entry.get("location"), entry_text)

                            return_text.append("[%s]: %s" % (entry.get("state"), entry_text))

        # add data from log commands
        for command, log_entries in self.__log_output_data.items():

            command_status = "OK"
            most_recent = dict()
            log_entry_counter = dict()

            for log_entry in log_entries:

                if self.cli_args.detailed is True:
                    return_text.append(log_entry.get("text"))
                else:

                    if plugin_status_types[log_entry.get("status")] > plugin_status_types[command_status]:
                        command_status = log_entry.get("status")

                    if log_entry_counter.get(log_entry.get("status")):
                        log_entry_counter[log_entry.get("status")] += 1
                    else:
                        log_entry_counter[log_entry.get("status")] = 1

                    if most_recent.get(log_entry.get("status")) is None:
                        most_recent[log_entry.get("status")] = log_entry.get("text")

            if self.cli_args.detailed is False:

                message_summary = " and ".join(["%d %s" % (value, key) for key, value in log_entry_counter.items()])

                return_text.append(f"[{command_status}]: Found {message_summary} {command} entries. "
                                   f"Most recent notable: %s" % most_recent.get(command_status))

        return_string = "\n".join(return_text)

        # append perfdata if there is any
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
