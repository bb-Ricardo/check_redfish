

from .redfish import RedfishConnection
from .inventory import Inventory
from cr_module.classes import status_types


class PluginData:

    rf = None
    inventory = None
    cli_args = None

    __perf_data = list()
    __output_data = dict()
    __log_output_data = dict()
    __return_status = "OK"
    __current_command = "global"

    def __init__(self, cli_args=None):

        if cli_args is None:
            raise Exception("No args passed to RedfishConnection()")

        self.cli_args = cli_args
        self.rf = RedfishConnection(cli_args)

        self.inventory = Inventory()

    def set_current_command(self, current_command=None):

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

    def add_output_data(self, state=None, text=None, summary=False):

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

    def add_log_output_data(self, state=None, text=None):

        if state is None:
            raise Exception("state not set")

        if text is None:
            raise Exception("text not set")

        self.set_status(state)

        if self.__log_output_data.get(self.__current_command) is None:
            self.__log_output_data[self.__current_command] = list()

        self.__log_output_data[self.__current_command].append(
            {
                "status": state,
                "text": "[%s]: %s" % (state, text)
            }
        )

    def add_perf_data(self, name, value, perf_uom=None, warning=None, critical=None):

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

            if self.__output_data[command].get("issues_found") is False and self.cli_args.detailed is False:
                return_text.append("[%s]: %s" % (
                    self.__output_data[command].get("summary_state"), self.__output_data[command].get("summary")))
            else:
                for status_type_name, _ in sorted(status_types.items(), key=lambda item: item[1], reverse=True):

                    if self.__output_data[command].get(status_type_name) is None:
                        continue

                    for data_output in self.__output_data[command].get(status_type_name):
                        if status_type_name != "OK" or self.cli_args.detailed is True:
                            return_text.append("[%s]: %s" % (status_type_name, data_output))

        # add data from log commands
        for command, log_entries in self.__log_output_data.items():

            command_status = "OK"
            most_recent = dict()
            log_entry_counter = dict()

            for log_entry in log_entries:

                if self.cli_args.detailed is True:
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
            return status_types[self.__return_status]

        return self.__return_status

    def do_exit(self):

        # return inventory and exit with 0
        if self.cli_args.inventory is True and self.inventory is not None:
            print(self.inventory.to_json())
            exit(0)

        print(self.return_output_data())

        exit(self.get_return_status(True))

# EOF
