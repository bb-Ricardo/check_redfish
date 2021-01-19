# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.common import get_status_data, grab
from cr_module.classes.inventory import Fan


def get_single_chassi_fan(plugin_object, redfish_url):
    plugin_object.set_current_command("Fan")

    chassi_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin_object.rf.get_view(redfish_url)

    if thermal_data.get("error"):
        plugin_object.add_data_retrieval_error(Fan, thermal_data, redfish_url)
        return

    fan_num = 0
    if "Fans" in thermal_data:
        for fan in thermal_data.get("Fans"):

            status_data = get_status_data(grab(fan, "Status"))

            member_id = grab(fan, "MemberId")
            name = fan.get("FanName") or fan.get("Name")

            if member_id is None:
                member_id = name

            # This helps on systems where the same MemberId could be assigned to multiple instances
            if grab(fan, "SensorNumber") is not None:
                member_id = f"{member_id}.{grab(fan, 'SensorNumber')}"

            physical_context = fan.get("PhysicalContext")

            oem_data = grab(fan, f"Oem.{plugin_object.rf.vendor_dict_key}")
            if physical_context is None:
                physical_context = grab(oem_data, "Location") or grab(oem_data, "Position")

            fan_inventory = Fan(
                id=member_id,
                name=name,
                health_status=status_data.get("Health"),
                operation_status=status_data.get("State"),
                physical_context=physical_context,
                min_reading=fan.get("MinReadingRange"),
                max_reading=fan.get("MaxReadingRange"),
                lower_threshold_non_critical=fan.get("LowerThresholdNonCritical"),
                lower_threshold_critical=fan.get("LowerThresholdCritical"),
                lower_threshold_fatal=fan.get("LowerThresholdFatal"),
                upper_threshold_non_critical=fan.get("UpperThresholdNonCritical"),
                upper_threshold_critical=fan.get("UpperThresholdCritical"),
                upper_threshold_fatal=fan.get("UpperThresholdFatal"),
                location=grab(fan, f"Oem.{plugin_object.rf.vendor_dict_key}.Location.Info"),
                chassi_ids=chassi_id
            )

            if plugin_object.cli_args.verbose:
                fan_inventory.source_data = fan

            text_units = ""
            fan_status = fan_inventory.health_status

            # add relations
            fan_inventory.add_relation(plugin_object.rf.get_system_properties(), fan.get("Links"))
            fan_inventory.add_relation(plugin_object.rf.get_system_properties(), fan.get("RelatedItem"))

            perf_units = ""
            text_speed = ""

            # DELL, Fujitsu, Huawei
            if fan.get("ReadingRPM") is not None or fan.get("ReadingUnits") == "RPM":
                fan_inventory.reading = fan.get("ReadingRPM") or fan.get("Reading")
                fan_inventory.reading_unit = "RPM"

                text_units = " RPM"

            # HP, Lenovo
            else:
                fan_inventory.reading = fan.get("Reading")
                fan_inventory.reading_unit = fan.get("ReadingUnits")

                if fan_inventory.reading_unit == "Percent":
                    text_units = "%"
                    perf_units = "%"

            if fan_inventory.reading is not None:
                text_speed = f" ({fan_inventory.reading}{text_units})"

            plugin_object.inventory.add(fan_inventory)

            if fan_inventory.operation_status == "Absent":
                continue

            if fan_inventory.health_status is None:
                fan_status = "OK" if fan_inventory.operation_status == "Enabled" else fan_inventory.operation_status

            fan_num += 1

            fan_name = fan_inventory.name
            if fan_name.lower().startswith("fan"):
                fan_name = fan_name[3:].strip()

            status_text = f"Fan '{fan_name}'{text_speed} status is: {fan_status}"

            plugin_object.add_output_data("CRITICAL" if fan_status not in ["OK", "WARNING"] else fan_status,
                                          status_text,  location=f"Chassi {chassi_id}")

            if fan_inventory.reading is not None:
                plugin_object.add_perf_data(f"Fan_{fan_inventory.name}", int(fan_inventory.reading),
                                            perf_uom=perf_units, warning=plugin_object.cli_args.warning,
                                            critical=plugin_object.cli_args.critical, location=f"Chassi {chassi_id}")

        default_text = f"All fans ({fan_num}) are in good condition"
    else:
        default_text = "no FAN detected"
        plugin_object.inventory.add_issue(Fan, f"No FAN data returned for API URL '{redfish_url}'")

    # get FanRedundancy status
    fan_redundancies = thermal_data.get("FanRedundancy") or thermal_data.get("Redundancy")

    if fan_redundancies is not None:
        status_text = ""
        for fan_redundancy in fan_redundancies:

            fr_status = get_status_data(fan_redundancy.get("Status"))

            status = fr_status.get("Health")

            if status is not None:
                status_text = "fan redundancy status is: %s" % fr_status.get("State")

                plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status,
                                              status_text[0].upper() + status_text[1:], location=f"Chassi {chassi_id}")

        if len(status_text) != 0:
            default_text += f" and {status_text}"

    plugin_object.add_output_data("OK", default_text, summary=True, location=f"Chassi {chassi_id}")

    return plugin_object

# EOF
