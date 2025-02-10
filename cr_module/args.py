# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from argparse import ArgumentParser, RawDescriptionHelpFormatter

from cr_module.classes.redfish import default_conn_max_retries, default_conn_timeout

def parse_command_line(description: str, version: str, version_date: str):
    """parse command line arguments
    Also add current version and version date to description
    """

    # define command line options
    parser = ArgumentParser(
        description=f"{description}\nVersion: {version} ({version_date})",
        formatter_class=RawDescriptionHelpFormatter, add_help=False)

    group = parser.add_argument_group(title="mandatory arguments")
    group.add_argument("-H", "--host",
                       help="define the host to request. To change the port just add ':portnumber' to this parameter")

    group = parser.add_argument_group(title="authentication arguments")
    group.add_argument("-u", "--username", help="the login user name")
    group.add_argument("-p", "--password", help="the login password")
    group.add_argument("-f", "--authfile", help="authentication file with user name and password")
    group.add_argument("--sessionfile", help="define name of session file")
    group.add_argument("--sessionfiledir", help="define directory where the plugin saves session files")
    group.add_argument("--sessionlock", action='store_true', help="prevents multiple sessions and locks the session file when connecting")
    group.add_argument("--nosession", action='store_true',
                       help="Don't establish a persistent session and log out after check is finished")

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
                       help=f"set number of maximum retries (default: {default_conn_max_retries})")
    group.add_argument("-t", "--timeout", type=int, default=default_conn_timeout,
                       help=f"set number of request timeout per try/retry (default: {default_conn_timeout})")
    group.add_argument("--log_exclude",
                       help="a comma separated list of log lines (regex) "
                            "to exclude from log status checks (--sel, --mel)")
    group.add_argument("--ignore_missing_ps", action='store_true',
                       help="ignore the fact that no power supplies are present and report the status "
                            "of the power subsystem")
    group.add_argument("--ignore_unavailable_resources", action='store_true',
                       help="ignore all 'UNKNOWN' errors which indicate missing resources and report as OK")
    group.add_argument("--enable_bmc_security_warning", action='store_true',
                       help="return status WARNING if BMC security issues are detected (HPE iLO only)")

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
                       help="request all of the above information at once")

    # inventory
    group = parser.add_argument_group(title="query inventory information (no health check)")
    group.add_argument("-i", "--inventory", action='store_true',
                       help="return inventory in json format instead of regular plugin output")
    group.add_argument("--inventory_id",
                       help="set an ID which can be used to identify this host in the destination inventory")
    group.add_argument("--inventory_name",
                       help="set a name which can be used to identify this host in the destination inventory")
    group.add_argument("--inventory_file",
                       help="set file to write the inventory output to. Otherwise stdout will be used.")

    result = parser.parse_args()

    if result.help:
        parser.print_help()
        print("")
        exit(0)

    if result.requested_query is None:
        parser.error("You need to specify at least one query command.")

    # need to check this our self otherwise it's not
    # possible to put the help command into an arguments group
    if result.host is None:
        parser.error("No remote host defined")

    return result
