#!/usr/bin/env python3

import logging

from cr_module.common import grab, parse_command_line
from cr_module.classes.plugin import PluginData
from cr_module.power import get_single_chassi_power
from cr_module.temp import get_single_chassi_temp
from cr_module.fan import get_single_chassi_fan
from cr_module.system_chassi import get_system_info
from cr_module.proc import get_single_system_procs
from cr_module.mem import get_single_system_mem
from cr_module.nic import get_single_system_nics, get_system_nics_fujitsu
from cr_module.storage import get_storage
from cr_module.bmc import get_bmc_info
from cr_module.firmware import get_firmware_info
from cr_module.event import get_event_log

plugin = None


def get_chassi_data(plugin_object, data_type=None):

    if data_type is None or data_type not in ["power", "temp", "fan"]:
        raise Exception("Unknown data_type not set for get_chassi_data(): %s", type)

    if plugin_object.rf.connection.system_properties is None:
        plugin_object.rf.discover_system_properties()

    chassis = grab(plugin_object.rf.connection.system_properties, "chassis")

    if chassis is None or len(chassis) == 0:
        plugin_object.add_output_data("UNKNOWN", "No 'chassis' property found in root path '/redfish/v1'")
        return

    for chassi in chassis:
        if data_type == "power":
            get_single_chassi_power(chassi)
        if data_type == "temp":
            get_single_chassi_temp(chassi)
        if data_type == "fan":
            get_single_chassi_fan(chassi)

    return


def get_system_data(plugin_object, data_type):

    if data_type is None or data_type not in ["procs", "mem", "nics"]:
        plugin_object.add_output_data("UNKNOWN", "Internal ERROR, data_type not set for get_system_data()")
        return

    if plugin_object.rf.connection.system_properties is None:
        plugin_object.rf.discover_system_properties()

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

    # try to get systems, managers and chassis IDs
    plugin.rf.discover_system_properties()

    # get basic information
    plugin.rf.determine_vendor()

    if any(x in args.requested_query for x in ['power', 'all']):    get_chassi_data(plugin, "power")
    if any(x in args.requested_query for x in ['temp', 'all']):     get_chassi_data(plugin, "temp")
    if any(x in args.requested_query for x in ['fan', 'all']):      get_chassi_data(plugin, "fan")
    if any(x in args.requested_query for x in ['proc', 'all']):     get_system_data(plugin, "procs")
    if any(x in args.requested_query for x in ['memory', 'all']):   get_system_data(plugin, "mem")
    if any(x in args.requested_query for x in ['nic', 'all']):      get_system_data(plugin, "nics")
    if any(x in args.requested_query for x in ['storage', 'all']):  get_storage(plugin)
    if any(x in args.requested_query for x in ['bmc', 'all']):      get_bmc_info(plugin)
    if any(x in args.requested_query for x in ['info', 'all']):     get_system_info(plugin)
    if any(x in args.requested_query for x in ['firmware', 'all']): get_firmware_info(plugin)
    if any(x in args.requested_query for x in ['mel', 'all']):      get_event_log(plugin, "Manager")
    if any(x in args.requested_query for x in ['sel', 'all']):      get_event_log(plugin, "System")

    plugin.do_exit()

# EOF
