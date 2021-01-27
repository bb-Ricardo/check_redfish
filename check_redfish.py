#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

description = """
This is a monitoring/inventory plugin to check components and
health status of systems which support Redfish.
It will also create a inventory of all components of a system.

R.I.P. IPMI
"""

__version__ = "1.1.0"
__version_date__ = "2020-11-23"
__author__ = "Ricardo Bartels <ricardo.bartels@telekom.de>"
__description__ = "Check Redfish Plugin"
__license__ = "MIT"


import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter

from cr_module.classes.plugin import PluginData
from cr_module.system_chassi import get_system_info, get_chassi_data, get_system_data
from cr_module.nic import get_network_interfaces
from cr_module.storage import get_storage
from cr_module.bmc import get_bmc_info
from cr_module.firmware import get_firmware_info
from cr_module.event import get_event_log
from cr_module.classes.redfish import default_conn_max_retries, default_conn_timeout
from cr_module.classes.inventory import Fan, PowerSupply, Temperature, Memory, Processor

plugin = None


def parse_command_line():
    """parse command line arguments
    Also add current version and version date to description
    """

    # define command line options
    parser = ArgumentParser(
        description=f"{description}\nVersion: {__version__} ({__version_date__})",
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
    # possible to put the help command into a arguments group
    if result.host is None:
        parser.error("No remote host defined")

    return result


if __name__ == "__main__":
    # start here
    args = parse_command_line()

    if args.verbose:
        # initialize logger
        logging.basicConfig(level="DEBUG", format='%(asctime)s - %(levelname)s: %(message)s')

    # initialize plugin object
    plugin = PluginData(args, plugin_version=__version__)

    # try to get systems, managers and chassis IDs
    plugin.rf.discover_system_properties()

    # get basic information
    plugin.rf.determine_vendor()

    if any(x in args.requested_query for x in ['power', 'all']):    get_chassi_data(plugin, PowerSupply)
    if any(x in args.requested_query for x in ['temp', 'all']):     get_chassi_data(plugin, Temperature)
    if any(x in args.requested_query for x in ['fan', 'all']):      get_chassi_data(plugin, Fan)
    if any(x in args.requested_query for x in ['proc', 'all']):     get_system_data(plugin, Processor)
    if any(x in args.requested_query for x in ['memory', 'all']):   get_system_data(plugin, Memory)
    if any(x in args.requested_query for x in ['nic', 'all']):      get_network_interfaces(plugin)
    if any(x in args.requested_query for x in ['storage', 'all']):  get_storage(plugin)
    if any(x in args.requested_query for x in ['bmc', 'all']):      get_bmc_info(plugin)
    if any(x in args.requested_query for x in ['info', 'all']):     get_system_info(plugin)
    if any(x in args.requested_query for x in ['firmware', 'all']): get_firmware_info(plugin)
    if any(x in args.requested_query for x in ['mel', 'all']):      get_event_log(plugin, "Manager")
    if any(x in args.requested_query for x in ['sel', 'all']):      get_event_log(plugin, "System")

    plugin.do_exit()

# EOF
