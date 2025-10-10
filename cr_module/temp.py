# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import Temperature
from cr_module.classes.plugin import PluginData
from cr_module.common import get_status_data, grab
from cr_module import get_system_power_state


def get_single_chassis_temp(redfish_url, chassis_id, thermal_data, _):

    plugin_object = PluginData()

    plugin_object.set_current_command("Temp")

    num_chassis = len(plugin_object.rf.get_system_properties("chassis") or list())

    if thermal_data.get("error"):
        plugin_object.add_data_retrieval_error(Temperature, thermal_data, redfish_url)
        return

    system_power_state = get_system_power_state().upper()

    temp_num = 0
    if "Temperatures" in thermal_data:

        for temp in thermal_data.get("Temperatures") or list():

            status_data = get_status_data(grab(temp, "Status"))

            status = status_data.get("Health")
            state = status_data.get("State")

            name = temp.get("Name")
            member_id = grab(temp, "MemberId")

            if member_id is None:
                member_id = name

            # prefix with chassis id if system has more then one
            if num_chassis > 1:
                member_id = f"{chassis_id}.{member_id}"

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
                chassis_ids=chassis_id
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

            if not state or state.lower() in ["absent", "disabled", "disable", "unavailableoffline", "standbyoffline"]:
                continue

            if status is None:
                status = "OK" if "enable" in state.lower() else state

            current_temp = temp_inventory.reading
            critical_temp = temp_inventory.upper_threshold_critical
            warning_temp = temp_inventory.upper_threshold_non_critical

            temp_num += 1

            if isinstance(warning_temp, (int, float)):
                warning_temp = int(warning_temp)

                if 0 > current_temp >= warning_temp:
                    status = "WARNING"

            if isinstance(critical_temp, (int, float)):
                critical_temp = int(critical_temp)

                if 0 > current_temp >= critical_temp:
                    status = "CRITICAL"


            if system_power_state != "ON":
                status = "OK"

            status_text = f"Temp sensor {temp_inventory.name} status is: {status} ({current_temp} °C)"
            if critical_temp is not None:
                status_text += f" (max: {critical_temp} °C)"

            plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text,
                                          location=f"Chassis {chassis_id}")

            temp_name = temp_inventory.name
            if num_chassis > 1:
                temp_name = f"{chassis_id}.{temp_name}"

            plugin_object.add_perf_data(f"temp_{temp_name}", current_temp, warning=warning_temp,
                                        critical=critical_temp, location=f"Chassis {chassis_id}")

        if len(thermal_data.get("Temperatures")) > 0:
            default_text = f"All temp sensors ({temp_num}) are in good condition"
        else:
            default_text = f"Chassis has no temp sensors installed/reported"

    elif grab(thermal_data, "ThermalMetrics/@odata.id", separator="/") is not None:

        thermal_metrics = plugin_object.rf.get(grab(thermal_data, "ThermalMetrics/@odata.id", separator="/"))

        for thermal_metric in thermal_metrics.get("TemperatureReadingsCelsius") or list():

            name = thermal_metric.get("DeviceName")
            member_id = name

            # prefix with chassis id if system has more then one
            if num_chassis > 1:
                member_id = f"{chassis_id}.{member_id}"

            temp_inventory = Temperature(
                name=name,
                id=member_id,
                physical_context=thermal_metric.get("PhysicalContext"),
                reading_unit="Celsius",
                reading=thermal_metric.get("Reading"),
                chassis_ids=chassis_id
            )

            if plugin_object.cli_args.verbose:
                temp_inventory.source_data = thermal_metric

            plugin_object.inventory.add(temp_inventory)

            status_text = f"Temp sensor '{temp_inventory.name}' reading: {temp_inventory.reading} °C"

            plugin_object.add_output_data("OK", status_text, location=f"Chassis {chassis_id}")

            plugin_object.add_perf_data(f"temp_{temp_inventory.id}", temp_inventory.reading,
                                        location=f"Chassis {chassis_id}")

        if len(thermal_metrics.get("TemperatureReadingsCelsius", [])) > 0:
            default_text = f"Reported {len(thermal_metrics.get('TemperatureReadingsCelsius'))} temperature metrics"
        else:
            default_text = f"Chassis has no temp sensors installed/reported"
    else:
        default_text = "No temp sensors detected"
        plugin_object.inventory.add_issue(Temperature, f"No temp sensor data returned for API URL '{redfish_url}'")

    plugin_object.add_output_data("OK", default_text, summary=True, location=f"Chassis {chassis_id}")

    return

# EOF
