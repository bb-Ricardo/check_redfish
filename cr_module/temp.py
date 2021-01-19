# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import Temperature
from cr_module.common import get_status_data, grab


def get_single_chassi_temp(plugin_object, redfish_url):

    plugin_object.set_current_command("Temp")

    chassi_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin_object.rf.get_view(redfish_url)

    if thermal_data.get("error"):
        plugin_object.add_data_retrieval_error(Temperature, thermal_data, redfish_url)
        return

    default_text = ""
    temp_num = 0
    if "Temperatures" in thermal_data:

        for temp in thermal_data.get("Temperatures"):

            status_data = get_status_data(grab(temp, "Status"))

            status = status_data.get("Health")
            state = status_data.get("State")

            name = temp.get("Name")
            member_id = grab(temp, "MemberId")

            if member_id is None:
                member_id = name

            temp_inventory = Temperature(
                name=name,
                id=member_id,
                health_status=status,
                operation_status=state,
                physical_context=temp.get("PhysicalContext"),
                min_reading=temp.get("MinReadingRangeTemp"),
                max_reading=temp.get("MaxReadingRangeTemp"),
                lower_threshold_non_critical=None if temp.get("LowerThresholdNonCritical") == "N/A" else temp.get(
                    "LowerThresholdNonCritical"),
                lower_threshold_critical=None if temp.get("LowerThresholdCritical") == "N/A" else temp.get(
                    "LowerThresholdCritical"),
                lower_threshold_fatal=None if temp.get("LowerThresholdFatal") == "N/A" else temp.get(
                    "LowerThresholdFatal"),
                upper_threshold_non_critical=None if temp.get("UpperThresholdNonCritical") == "N/A" else temp.get(
                    "UpperThresholdNonCritical"),
                upper_threshold_critical=None if temp.get("UpperThresholdCritical") == "N/A" else temp.get(
                    "UpperThresholdCritical"),
                upper_threshold_fatal=None if temp.get("UpperThresholdFatal") == "N/A" else temp.get(
                    "UpperThresholdFatal"),
                chassi_ids=chassi_id
            )

            if plugin_object.cli_args.verbose:
                temp_inventory.source_data = temp

            temp_inventory.reading_unit = "Celsius"
            if temp.get("ReadingCelsius") is not None:
                temp_inventory.reading = temp.get("ReadingCelsius")
            elif temp.get("ReadingFahrenheit") is not None:
                temp_inventory.reading = temp.get("ReadingFahrenheit")
                temp_inventory.reading_unit = "Fahrenheit"
            else:
                temp_inventory.reading = 0

            # add relations
            temp_inventory.add_relation(plugin_object.rf.get_system_properties(), temp.get("Links"))
            temp_inventory.add_relation(plugin_object.rf.get_system_properties(), temp.get("RelatedItem"))

            plugin_object.inventory.add(temp_inventory)

            if state in ["Absent", "Disabled", "UnavailableOffline"]:
                continue

            if status is None:
                status = "OK" if state == "Enabled" else state

            current_temp = temp_inventory.reading
            critical_temp = temp_inventory.upper_threshold_critical
            warning_temp = temp_inventory.upper_threshold_non_critical

            temp_num += 1

            if str(warning_temp) in ["0", "N/A"]:
                warning_temp = None

            if warning_temp is not None and float(current_temp) >= float(warning_temp):
                status = "WARNING"

            if str(critical_temp) in ["0", "N/A"]:
                critical_temp = None

            if critical_temp is not None and float(current_temp) >= float(critical_temp):
                status = "CRITICAL"

            critical_temp_text = "N/A"
            if critical_temp is not None:
                critical_temp_text = "%.1f" % float(critical_temp)

            status_text = f"Temp sensor {temp_inventory.name} status is: " \
                          f"{status} (%.1f °C) (max: {critical_temp_text} °C)" % current_temp

            plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text,
                                          location=f"Chassi {chassi_id}")

            plugin_object.add_perf_data(f"temp_{temp_inventory.name}", float(current_temp), warning=warning_temp,
                                        critical=critical_temp, location=f"Chassi {chassi_id}")

        default_text = f"All temp sensors ({temp_num}) are in good condition"
    else:
        default_text = "no temp sensors detected"
        plugin_object.inventory.add_issue(Temperature, f"No temp sensor data returned for API URL '{redfish_url}'")

    plugin_object.add_output_data("OK", default_text, summary=True, location=f"Chassi {chassi_id}")

    return

# EOF
