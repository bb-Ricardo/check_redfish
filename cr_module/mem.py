# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import Memory
from cr_module.common import get_status_data, grab


def get_single_system_mem(plugin_object, redfish_url):
    plugin_object.set_current_command("Mem")

    systems_response = plugin_object.rf.get(redfish_url)

    if systems_response.get("error"):
        plugin_object.add_data_retrieval_error(Memory, systems_response, redfish_url)
        return

    system_id = systems_response.get("Id")

    if systems_response.get("MemorySummary"):

        memory_status = get_status_data(grab(systems_response, "MemorySummary.Status"))

        # DELL is HealthRollUp not HealthRollup
        # Fujitsu is just Health and not HealthRollup
        health = memory_status.get("HealthRollup") or memory_status.get("Health")

        if health == "OK" and plugin_object.cli_args.detailed is False and plugin_object.cli_args.inventory is False:

            total_mem = grab(systems_response, "MemorySummary.TotalSystemMemoryGiB") or 0

            if plugin_object.rf.vendor == "Dell" and total_mem % 1024 != 0:
                total_mem = total_mem * 1024 ** 3 / 1000 ** 3

            plugin_object.add_output_data("OK", "All memory modules (Total %dGB) are in good condition" %
                                          total_mem, summary=True, location=f"System {system_id}")
            return

    system_response_memory_key = "Memory"
    if grab(systems_response, f"Oem.{plugin_object.rf.vendor_dict_key}.Links.{system_response_memory_key}"):
        memory_path_dict = grab(systems_response, f"Oem.{plugin_object.rf.vendor_dict_key}.Links")
    else:
        memory_path_dict = systems_response

    if memory_path_dict.get(system_response_memory_key) is None:
        issue_text = f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_memory_key}'"
        plugin_object.inventory.add_issue(Memory, issue_text)
        return

    redfish_url = memory_path_dict.get(system_response_memory_key).get(
        "@odata.id") + "%s" % plugin_object.rf.vendor_data.expand_string

    memory_response = plugin_object.rf.get_view(redfish_url)

    if memory_response.get("error"):
        plugin_object.add_data_retrieval_error(Memory, memory_response, redfish_url)
        return

    num_dimms = 0
    size_sum = 0

    if memory_response.get("Members") or memory_response.get(system_response_memory_key):

        for mem_module in memory_response.get("Members") or memory_response.get(system_response_memory_key):

            if mem_module.get("@odata.context"):
                mem_module_response = mem_module
            else:
                mem_module_response = plugin_object.rf.get(mem_module.get("@odata.id"))

                if mem_module_response.get("error"):
                    plugin_object.add_data_retrieval_error(Memory, mem_module_response, redfish_url)
                    continue

            if mem_module_response.get("Id"):

                # get size
                module_size = mem_module_response.get("SizeMB") or mem_module_response.get("CapacityMiB") or 0

                module_size = int(module_size)

                # DELL fix for iDRAC 8
                if plugin_object.rf.vendor == "Dell" and module_size % 1024 != 0:
                    module_size = round(module_size * 1024 ** 2 / 1000 ** 2)

                # get name
                module_name = mem_module_response.get("SocketLocator") or mem_module_response.get(
                    "DeviceLocator") or mem_module_response.get("Name")

                if module_name is None:
                    module_name = "UnknownNameLocation"

                # get status
                status_data = get_status_data(mem_module_response.get("Status"))

                if plugin_object.rf.vendor == "HPE" and grab(mem_module_response,
                                                             f"Oem.{plugin_object.rf.vendor_dict_key}.DIMMStatus"):
                    status_data["State"] = grab(mem_module_response,
                                                f"Oem.{plugin_object.rf.vendor_dict_key}.DIMMStatus")

                elif mem_module_response.get("DIMMStatus"):

                    status_data["State"] = mem_module_response.get("DIMMStatus")

                mem_inventory = Memory(
                    name=module_name,
                    id=mem_module_response.get("Id"),
                    health_status=status_data.get("Health"),
                    operation_status=status_data.get("State"),
                    size_in_mb=module_size,
                    manufacturer=mem_module_response.get("Manufacturer"),
                    serial=mem_module_response.get("SerialNumber"),
                    socket=grab(mem_module_response, "MemoryLocation.Socket"),
                    slot=grab(mem_module_response, "MemoryLocation.Slot"),
                    channel=grab(mem_module_response, "MemoryLocation.Channel"),
                    speed=mem_module_response.get("OperatingSpeedMhz"),
                    part_number=mem_module_response.get("PartNumber"),
                    type=mem_module_response.get("MemoryDeviceType") or mem_module_response.get("MemoryType"),
                    base_type=mem_module_response.get("BaseModuleType"),
                    system_ids=system_id
                )

                if plugin_object.cli_args.verbose:
                    mem_inventory.source_data = mem_module_response

                plugin_object.inventory.add(mem_inventory)

                if mem_inventory.operation_status in ["Absent", "NotPresent"]:
                    continue

                num_dimms += 1
                size_sum += module_size

                if mem_inventory.operation_status in ["GoodInUse", "Operable"]:
                    plugin_status = "OK"
                    status_text = mem_inventory.operation_status
                else:
                    plugin_status = mem_inventory.health_status
                    status_text = plugin_status

                status_text = f"Memory module {mem_inventory.name} (%.1fGB) status is: {status_text}" % (
                            mem_inventory.size_in_mb / 1024)

                plugin_object.add_output_data("CRITICAL" if plugin_status not in ["OK", "WARNING"] else plugin_status,
                                              status_text, location=f"System {system_id}")

            else:
                plugin_object.add_output_data("UNKNOWN",
                                              "No memory data returned for API URL '%s'" % mem_module.get("@odata.id"),
                                              location=f"System {system_id}")

    if num_dimms == 0:
        issue_text = f"Returned data from API URL '{redfish_url}' contains no processor information"
        plugin_object.inventory.add_issue(Memory, issue_text)
    else:
        plugin_object.add_output_data("OK", f"All {num_dimms} memory modules (Total %.1fGB) are in good condition" % (
                    size_sum / 1024), summary=True, location=f"System {system_id}")

    return

# EOF
