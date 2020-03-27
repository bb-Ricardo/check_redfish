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

    default_text = ""
    fan_num = 0
    if "Fans" in thermal_data:
        for fan in thermal_data.get("Fans"):

            status_data = get_status_data(grab(fan, "Status"))

            member_id = grab(fan, "MemberId")
            name = fan.get("FanName") or fan.get("Name")

            if member_id is None:
                member_id = name

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

            text_speed = f" ({fan_inventory.reading}{text_units})"

            plugin_object.inventory.add(fan_inventory)

            if fan_inventory.operation_status == "Absent":
                continue

            if fan_inventory.health_status is None:
                fan_status = "OK" if fan_inventory.operation_status == "Enabled" else fan_inventory.operation_status

            fan_num += 1

            status_text = f"Fan '{fan_inventory.name}'{text_speed} status is: {fan_status}"

            plugin_object.add_output_data("CRITICAL" if fan_status not in ["OK", "WARNING"] else fan_status,
                                          status_text)

            if fan_inventory.reading is not None:
                plugin_object.add_perf_data(f"Fan_{fan_inventory.name}", int(fan_inventory.reading),
                                            perf_uom=perf_units, warning=plugin_object.cli_args.warning,
                                            critical=plugin_object.cli_args.critical)

        default_text = f"All fans ({fan_num}) are in good condition"
    else:
        plugin_object.add_output_data("UNKNOWN", f"No thermal data returned for API URL '{redfish_url}'")

    # get FanRedundancy status
    fan_redundancies = plugin_object.rf.get_view(redfish_url).get("FanRedundancy")
    if fan_redundancies is None:
        fan_redundancies = plugin_object.rf.get_view(redfish_url).get("Redundancy")

    if fan_redundancies:
        status_text = ""
        for fan_redundancy in fan_redundancies:

            fr_status = get_status_data(fan_redundancy.get("Status"))

            status = fr_status.get("Health")

            if status is not None:
                status_text = "fan redundancy status is: %s" % fr_status.get("State")

                plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status,
                                              status_text[0].upper() + status_text[1:])

        if len(status_text) != 0:
            default_text += f" and {status_text}"

    plugin_object.add_output_data("OK", default_text, summary=True)

    return plugin_object

# EOF
