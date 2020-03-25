
import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter

from cr_module.classes import plugin_status_types
from . import __long_description__, __version__, __version_date__
from .classes.redfish import default_conn_max_retries, default_conn_timeout


def grab(structure=None, path=None, separator="."):
    """
        get data from a complex object/json structure with a
        "." separated path information. If a part of a path
        is not not present then this function returns "None".

        example structure:
            data_structure = {
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

    # noinspection PyBroadException
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
        if status_data.upper() in plugin_status_types.keys():
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
                            status_value.upper() in plugin_status_types.keys():
                        status_value = status_value.upper()
                    return_data[key] = status_value

    return return_data


def parse_command_line():
    """parse command line arguments
    Also add current version and version date to description
    """

    # define command line options
    parser = ArgumentParser(
        description=__long_description__ + "\nVersion: " + __version__ + " (" + __version_date__ + ")",
        formatter_class=RawDescriptionHelpFormatter, add_help=False)

    group = parser.add_argument_group(title="mandatory arguments")
    group.add_argument("-H", "--host",
                       help="define the host to request. To change the port just add ':portnumber' to this parameter.")

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
    group.add_argument("-v", "--verbose", action='store_true',
                       help="this will add all https requests and responses to output, "
                            "also adds inventory source data to all inventory objects")
    group.add_argument("-d", "--detailed", action='store_true',
                       help="always print detailed result")
    group.add_argument("-m", "--max", type=int,
                       help="set maximum of returned items for --sel or --mel")
    group.add_argument("-r", "--retries", type=int, default=default_conn_max_retries,
                       help="set number of maximum retries (default: %d)" % default_conn_max_retries)
    group.add_argument("-t", "--timeout", type=int, default=default_conn_timeout,
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
                       help="request bmc info and status")
    group.add_argument("--info", dest="requested_query", action='append_const', const="info",
                       help="request system information")
    group.add_argument("--firmware", dest="requested_query", action='append_const', const="firmware",
                       help="request firmware information")
    group.add_argument("--sel", dest="requested_query", action='append_const', const="sel",
                       help="request System Log status")
    group.add_argument("--mel", dest="requested_query", action='append_const', const="mel",
                       help="request Management Processor Log status")
    group.add_argument("--all", dest="requested_query", action='append_const', const="all",
                       help="request all of the above information at once.")

    # inventory
    group = parser.add_argument_group(title="query inventory information (no health check)")
    group.add_argument("-i", "--inventory", action='store_true',
                       help="return inventory in json format instead of regular plugin output")

    result = parser.parse_args()

    if result.help:
        parser.print_help()
        print("")
        exit(0)

    if result.requested_query is None:
        parser.error("You need to specify at least one query command.")

    # need to check this our self otherwise it's not
    # possible to put the help command into a arguments group
    if result.host is None:
        parser.error("no remote host defined")

    return result


