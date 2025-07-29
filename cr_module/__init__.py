# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.common import grab
from cr_module.classes.plugin import PluginData

system_power_state = None
system_power_on_time = None
system_power_on_time_discovered = False
system_booting = False
system_booting_discovered = False

system_boot_max_seconds = 300

# function has been placed here to avoid circular dependencies
def get_system_power_state():

    global system_power_state

    if system_power_state is not None:
        return system_power_state

    plugin_object = PluginData()

    for system in plugin_object.rf.get_system_properties("systems") or list():
        system_state = grab(plugin_object.rf.get(system), "PowerState")
        if system_state is not None:
            system_power_state = system_state
            break

    if system_power_state is None:
        system_power_state = "On"

    return system_power_state

def get_system_power_on_time():

    global system_power_on_time, system_power_on_time_discovered

    if system_power_on_time_discovered is True:
        return system_power_on_time

    plugin_object = PluginData()

    for system in plugin_object.rf.get_system_properties("systems") or list():

        system_power_on_time = grab(
            plugin_object.rf.get(system),
            f"Oem.{plugin_object.rf.vendor_dict_key}.CurrentPowerOnTimeSeconds")

        if system_power_on_time is not None:
            break

    system_power_on_time_discovered = True

    return system_power_on_time

def system_is_booting():

    global system_booting, system_booting_discovered

    if system_booting_discovered is True:
        return system_booting

    plugin_object = PluginData()

    for system in plugin_object.rf.get_system_properties("systems") or list():
        # used by HPE iLO 6
        system_discovered = grab(
            plugin_object.rf.get(system),
            f"Oem.{plugin_object.rf.vendor_dict_key}.DeviceDiscoveryComplete.ServerFirmwareInventoryComplete")

        if system_discovered is True:
            system_booting_discovered = True
            system_booting = False
            return system_booting

        if grab(plugin_object.rf.get(system), "Status.State") == "Starting":
            system_booting_discovered = True
            system_booting = True
            return system_booting

    power_on_time = get_system_power_on_time()
    if power_on_time is not None and power_on_time <= system_boot_max_seconds:
        system_booting = True

    system_booting_discovered = True

    return system_booting

# EOF
