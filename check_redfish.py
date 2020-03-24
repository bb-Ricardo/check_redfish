#!/usr/bin/env python3



# import build-in modules
import logging
import pickle
import os
import tempfile

import pprint
import json
import datetime
import sys




plugin = None


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

    # get basic information
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
