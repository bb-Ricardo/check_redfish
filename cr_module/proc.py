# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import Processor
from cr_module.classes.plugin import PluginData
from cr_module.common import get_status_data, grab
from cr_module import get_system_power_state


def get_single_system_procs(redfish_url):

    plugin_object = PluginData()

    plugin_object.set_current_command("Procs")

    systems_response = plugin_object.rf.get(redfish_url)

    if systems_response.get("error"):
        plugin_object.add_data_retrieval_error(Processor, systems_response, redfish_url)
        return

    system_id = systems_response.get("Id")

    system_power_state = get_system_power_state().upper()

    if systems_response.get("ProcessorSummary"):

        proc_status = get_status_data(grab(systems_response, "ProcessorSummary.Status"))

        # DELL is HealthRollUp not HealthRollup
        # Fujitsu is just Health and not HealthRollup
        health = proc_status.get("HealthRollup") or proc_status.get("Health")

        proc_count = grab(systems_response, "ProcessorSummary.Count")
        proc_count_text = ""
        if proc_count is not None:
            proc_count_text = f"({proc_count}) "

        if health == "OK" and plugin_object.cli_args.detailed is False and plugin_object.cli_args.inventory is False:
            plugin_object.add_output_data("OK", f"All processors {proc_count_text}are in good condition", summary=True)
            return

    system_response_proc_key = "Processors"
    if systems_response.get(system_response_proc_key) is None:
        issue_text = f"Returned data from API URL '{redfish_url}' has no attribute '{system_response_proc_key}'"
        plugin_object.inventory.add_issue(Processor, issue_text)
        return

    processors_link = grab(systems_response, f"{system_response_proc_key}/@odata.id", separator="/")

    processors_response = plugin_object.rf.get_view(f"{processors_link}{plugin_object.rf.vendor_data.expand_string}")

    if processors_response.get("error"):
        plugin_object.add_data_retrieval_error(Processor, processors_response, processors_link)
        return

    if processors_response.get("Members") is not None or processors_response.get(system_response_proc_key) is not None:

        num_procs = 0
        for proc in processors_response.get("Members") or processors_response.get(system_response_proc_key) or list():

            if proc.get("@odata.context"):
                proc_response = proc
            else:
                proc_response = plugin_object.rf.get(proc.get("@odata.id"))

                if proc_response.get("error"):
                    plugin_object.add_data_retrieval_error(Processor, proc_response, proc.get("@odata.id"))
                    continue

            if proc_response.get("Id"):

                status_data = get_status_data(proc_response.get("Status"))

                model = proc_response.get("Model")

                vendor_data = grab(proc_response, f"Oem.{plugin_object.rf.vendor_dict_key}")

                if plugin_object.rf.vendor == "Dell" and grab(vendor_data, "DellProcessor") is not None:
                    vendor_data = grab(vendor_data, "DellProcessor")

                # get current/regular speed
                current_speed = grab(vendor_data, "CurrentClockSpeedMHz") or grab(vendor_data, "RatedSpeedMHz") or \
                    grab(vendor_data, "FrequencyMHz")

                # try to extract speed from model if current_speed is None
                # Intel XEON CPUs
                if current_speed is None and model is not None and "GHz" in model:
                    model_speed = model.split("@")[-1].strip().replace("GHz", "")
                    # noinspection PyBroadException
                    try:
                        current_speed = int(float(model_speed) * 1000)
                    except Exception:
                        pass

                # get cache information
                level_1_cache_kib = grab(vendor_data, "L1CacheKiB")
                level_2_cache_kib = grab(vendor_data, "L2CacheKiB")
                level_3_cache_kib = grab(vendor_data, "L3CacheKiB")

                if plugin_object.rf.vendor == "Dell":
                    level_1_cache_kib = grab(vendor_data, "Cache1InstalledSizeKB")
                    level_2_cache_kib = grab(vendor_data, "Cache2InstalledSizeKB")
                    level_3_cache_kib = grab(vendor_data, "Cache3InstalledSizeKB")

                #                   HPE                           Lenovo
                vendor_cache_data = grab(vendor_data, "Cache") or grab(vendor_data, "CacheInfo") or list()

                for cpu_cache in vendor_cache_data:

                    #            HPE                                 Lenovo
                    cache_size = cpu_cache.get("InstalledSizeKB") or cpu_cache.get("InstalledSizeKByte")
                    cache_level = cpu_cache.get("Name") or cpu_cache.get("CacheLevel")

                    if cache_size is None or cache_level is None:
                        continue

                    if "L1" in cache_level:
                        level_1_cache_kib = cache_size * 1000 / 1024
                    if "L2" in cache_level:
                        level_2_cache_kib = cache_size * 1000 / 1024
                    if "L3" in cache_level:
                        level_3_cache_kib = cache_size * 1000 / 1024

                proc_serial = grab(proc_response, f"Oem.{plugin_object.rf.vendor_dict_key}.SerialNumber") or \
                    proc_response.get("SN") or proc_response.get("SerialNumber")

                proc_inventory = Processor(
                    name=proc_response.get("Name"),
                    id=proc_response.get("Id"),
                    model=model,
                    socket=proc_response.get("Socket"),
                    health_status=status_data.get("Health"),
                    operation_status=status_data.get("State"),
                    cores=proc_response.get("TotalCores"),
                    threads=proc_response.get("TotalThreads"),
                    current_speed=current_speed,
                    max_speed=proc_response.get("MaxSpeedMHz"),
                    manufacturer=proc_response.get("Manufacturer"),
                    instruction_set=proc_response.get("InstructionSet"),
                    architecture=proc_response.get("ProcessorArchitecture"),
                    serial=proc_serial,
                    system_ids=system_id,
                    L1_cache_kib=level_1_cache_kib,
                    L2_cache_kib=level_2_cache_kib,
                    L3_cache_kib=level_3_cache_kib,
                    type=proc_response.get("ProcessorType")
                )

                if plugin_object.cli_args.verbose:
                    proc_inventory.source_data = proc_response

                plugin_object.inventory.add(proc_inventory)

                if proc_inventory.operation_status == "Absent":
                    continue

                if proc_response.get("ProcessorType") == "GPU" and proc_response.get("Status") is None:
                    continue

                num_procs += 1

                plugin_status = proc_inventory.health_status
                if system_power_state != "ON":
                    plugin_status = "OK"

                status_text = f"Processor {proc_inventory.socket} ({proc_inventory.model}) status is: " \
                              f"{proc_inventory.health_status}"

                plugin_object.add_output_data("CRITICAL" if plugin_status not in ["OK", "WARNING"] else plugin_status,
                                              status_text, location=f"System {system_id}")

            else:
                plugin_object.add_output_data("UNKNOWN",
                                              "No processor data returned for API URL '%s'" %
                                              proc_response.get("@odata.id"), location=f"System {system_id}")

        if num_procs == 0:
            issue_text = f"Returned data from API URL '{processors_link}' contains no processor information"
            plugin_object.inventory.add_issue(Processor, issue_text)

        else:
            plugin_object.add_output_data("OK", "All processors (%d) are in good condition" % num_procs,
                                          summary=True, location=f"System {system_id}")
    else:
        plugin_object.inventory.add_issue(Processor, f"No processor data returned for API URL '{redfish_url}'")

    # add Dell CPU usage
    if plugin_object.rf.vendor == "Dell":
        for chassi in plugin_object.rf.get_system_properties("chassis") or list():

            cpu_usage_url = chassi.rstrip("/") + "/Sensors/SystemBoardCPUUsage"

            chassi_id = chassi.rstrip("/").split("/")[-1]

            cpu_usage_response = plugin_object.rf.get(cpu_usage_url)

            if not cpu_usage_response.get("error"):
                cpu_usage_value = grab(cpu_usage_response, "Reading")
                cpu_usage_units = grab(cpu_usage_response, "ReadingUnits")
                if cpu_usage_value is not None and cpu_usage_units is not None:

                    # noinspection PyBroadException
                    try:
                        cpu_usage_int = int(cpu_usage_value)

                        plugin_object.add_output_data("OK", f"Current CPU usage {cpu_usage_int}{cpu_usage_units}",
                                                      location=f"System {system_id}")

                        plugin_object.add_perf_data(f"cpu_usage", cpu_usage_int,
                                                    perf_uom="%" if cpu_usage_units == "%" else None,
                                                    location=f"Chassi {chassi_id}")

                    except Exception:
                        pass

    # add HPE CPU usage
    if plugin_object.rf.vendor == "HPE":

        cpu_util_metric_endpoint = "/redfish/v1/TelemetryService/MetricReports/CPUUtilCustom1/"

        cpu_usage_response = plugin_object.rf.get(cpu_util_metric_endpoint)

        if not cpu_usage_response.get("error"):
            cpu_usage_value = grab(cpu_usage_response, "MetricValues")
            cpu_usage_units = "%"
            if isinstance(cpu_usage_value, list) and len(cpu_usage_value) > 0:
                cpu_usage = grab(cpu_usage_value[-1], "MetricValue")

                # noinspection PyBroadException
                try:
                    cpu_usage_int = int(cpu_usage)

                    plugin_object.add_output_data("OK", f"Current CPU usage {cpu_usage_int}{cpu_usage_units}",
                                                  location=f"System {system_id}")

                    plugin_object.add_perf_data(f"cpu_usage", cpu_usage_int, perf_uom=cpu_usage_units,
                                                location=f"System {system_id}")

                except Exception:
                    pass

    return

# EOF
