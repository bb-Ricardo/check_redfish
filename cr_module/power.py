# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import PowerSupply
from cr_module.classes.plugin import PluginData
from cr_module.common import get_status_data, grab
from cr_module import get_system_power_state


def get_single_chassi_power(redfish_url, chassi_id, power_data):

    plugin_object = PluginData()

    plugin_object.set_current_command("Power")

    num_chassis = len(plugin_object.rf.get_system_properties("chassis") or list())

    if power_data.get("error"):
        plugin_object.add_data_retrieval_error(PowerSupply, power_data, redfish_url)
        return

    power_supplies = power_data.get("PowerSupplies", list())

    system_power_state = get_system_power_state().upper()

    fujitsu_power_sensors = None
    if plugin_object.rf.vendor == "Fujitsu":
        fujitsu_power_sensors = grab(power_data, f"Oem.{plugin_object.rf.vendor_dict_key}.ChassisPowerSensors")

    issue_detected = False
    ps_num = 0
    ps_absent = 0
    if len(power_supplies) > 0:
        for ps in power_supplies:

            ps_num += 1

            status_data = get_status_data(grab(ps, "Status"))

            health = status_data.get("Health")
            operational_status = status_data.get("State")
            part_number = ps.get("PartNumber")
            model = ps.get("Model") or part_number
            last_power_output = ps.get("LastPowerOutputWatts") or ps.get("PowerOutputWatts")
            capacity_in_watt = ps.get("PowerCapacityWatts")
            bay = None

            oem_data = grab(ps, f"Oem.{plugin_object.rf.vendor_dict_key}")

            if oem_data is not None:

                if plugin_object.rf.vendor == "HPE":
                    bay = grab(oem_data, "BayNumber")
                    ps_hp_status = grab(oem_data, "PowerSupplyStatus.State")
                    if ps_hp_status is not None and ps_hp_status == "Unknown":
                        health = "CRITICAL"

                elif plugin_object.rf.vendor == "Lenovo":
                    bay = grab(oem_data, "Location.Info")

                if last_power_output is None and grab(oem_data, "PowerOutputWatts") is not None:
                    last_power_output = grab(oem_data, "PowerOutputWatts")

            if plugin_object.rf.vendor == "Ami" and health is None and operational_status == "Present":
                health = "OK"

            if bay is None:
                bay = ps_num

            if capacity_in_watt is None:
                capacity_in_watt = grab(ps, "InputRanges.0.OutputWattage")

            # special Fujitsu case
            if fujitsu_power_sensors is not None and last_power_output is None:
                for fujitsu_power_sensor in fujitsu_power_sensors:
                    if fujitsu_power_sensor.get("Designation") is not None and \
                            fujitsu_power_sensor.get("Designation").startswith(ps.get("Name")):
                        last_power_output = fujitsu_power_sensor.get("CurrentPowerConsumptionW")

            ps_id = grab(ps, "MemberId") or ps_num
            # prefix with chassi id if system has more then one
            if num_chassis > 1:
                ps_id = f"{chassi_id}.{ps_id}"

            ps_inventory = PowerSupply(
                id=ps_id,
                name=ps.get("Name"),
                model=model,
                bay=bay,
                health_status=health,
                operation_status=operational_status,
                last_power_output=last_power_output,
                serial=ps.get("SerialNumber"),
                type=ps.get("PowerSupplyType"),
                capacity_in_watt=capacity_in_watt,
                firmware=ps.get("FirmwareVersion"),
                vendor=ps.get("Manufacturer"),
                input_voltage=ps.get("LineInputVoltage"),
                part_number=ps.get("SparePartNumber") or ps.get("PartNumber"),
                chassi_ids=chassi_id
            )

            if plugin_object.cli_args.verbose:
                ps_inventory.source_data = ps

            plugin_object.inventory.add(ps_inventory)

            printed_status = health
            printed_model = ""

            if operational_status == "Absent":
                printed_status = operational_status
                health = "OK"
                ps_absent += 1

            if plugin_object.rf.vendor == "Ami" and health is None and operational_status == "Present":
                printed_status = operational_status

            if health is None and operational_status == "Enabled":
                printed_status = operational_status
                health = "OK"

            if grab(ps, "Status") is None:
                printed_status = "UNKNOWN (no status returned)"
                health = "OK"

            if model is not None:
                printed_model = "(%s) " % model.strip()

            status_text = "Power supply {bay} {model}status is: {status}".format(
                bay=str(bay), model=printed_model, status=printed_status)

            if system_power_state != "ON" and health is None:
                health = "OK"

            if health != "OK":
                issue_detected = True

            plugin_object.add_output_data("CRITICAL" if health not in ["OK", "WARNING"] else health,
                                          status_text, location=f"Chassi {chassi_id}")

            if last_power_output is not None:
                if num_chassis > 1:
                    bay = f"{chassi_id}.{bay}"

                plugin_object.add_perf_data(f"ps_{bay}", int(last_power_output), location=f"Chassi {chassi_id}")

        default_text = "All power supplies (%d) are in good condition" % (ps_num - ps_absent)

    else:
        default_text = "No power supplies detected"
        if plugin_object.cli_args.ignore_missing_ps is False or plugin_object.in_firmware_collection_mode() is False:
            issue_detected = True
            plugin_object.inventory.add_issue(PowerSupply, f"No power supply data returned for API URL '{redfish_url}'")

    # get PowerRedundancy status
    power_redundancies = power_data.get("PowerRedundancy") or power_data.get("Redundancy")

    if power_redundancies:
        pr_status_summary_text = ""
        pr_num = 0
        for power_redundancy in power_redundancies:

            if power_redundancy.get("Status") is not None:
                pr_status = get_status_data(grab(power_redundancy, "Status"))
                status = pr_status.get("Health")
                state = pr_status.get("State")

                if status is not None:
                    pr_num += 1
                    status = status.upper()

                    status_text = f"Power redundancy {pr_num} status is: {state}"

                    pr_status_summary_text += f" {status_text}"

                    plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status,
                                                  status_text, location=f"Chassi {chassi_id}")

        if len(pr_status_summary_text) != 0:
            default_text += f" and{pr_status_summary_text}"

    # get Voltages status
    voltages_num = 0
    for voltage in power_data.get("Voltages", list()):

        if voltage.get("Status") is not None:
            voltage_status = get_status_data(grab(voltage, "Status"))
            status = voltage_status.get("Health")
            state = voltage_status.get("State")
            reading = voltage.get("ReadingVolts")
            name = voltage.get("Name")

            if status is not None:
                voltages_num += 1

                status_text = f"Voltage {name} (status: {status}/{state}): {reading}V"

                plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status,
                                              status_text, location=f"Chassi {chassi_id}")

                if reading is not None and name is not None:
                    # noinspection PyBroadException
                    try:
                        if num_chassis > 1:
                            name = f"{chassi_id}.{name}"

                        plugin_object.add_perf_data(f"voltage_{name}", float(reading),
                                                    location=f"Chassi {chassi_id}")
                    except Exception:
                        pass

    if voltages_num > 0:
        default_text += f" and {voltages_num} Voltages are OK"

    power_control_num = 0
    power_control_data = power_data.get("PowerControl", list())

    # Cisco workaround
    if isinstance(power_control_data, dict):
        power_control_data = [power_control_data]

    for power_control in power_control_data:

        if power_control.get("Status") is None:
            continue

        power_control_status = get_status_data(grab(power_control, "Status"))
        status = power_control_status.get("Health")
        state = power_control_status.get("State")
        name = power_control.get("Name")
        reading = power_control.get("PowerConsumedWatts")

        if status is None:
            continue

        if str(reading) == "0":
            reading = None

        power_control_num += 1

        if plugin_object.rf.vendor == "Ami" and state == "Disabled":
            status = "OK"

        if reading is not None:
            status_text = f"{name} (status: {status}/{state}) current consumption: {reading}W"
        else:
            status_text = f"{name} status: {status}/{state}"

        if status != "OK":
            issue_detected = True

        plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status,
                                      status_text, location=f"Chassi {chassi_id}")

        if reading is not None and name is not None:
            # noinspection PyBroadException
            try:
                plugin_object.add_perf_data(f"power_control_{name}", float(reading),
                                            location=f"Chassi {chassi_id}")
            except Exception:
                pass

    if plugin_object.rf.vendor == "Supermicro":
        battery = grab(power_data, f"Oem.{plugin_object.rf.vendor_dict_key}.Battery")
        if battery is not None:
            battery_status = get_status_data(grab(battery, "Status"))
            status = battery_status.get("Health")
            state = battery_status.get("State")
            name = battery.get("Name")

            status_text = f"{name} status: {status}/{state}"

            if status != "OK":
                print("ISSUE Power control")
                issue_detected = True

            plugin_object.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status,
                                          status_text, location=f"Chassi {chassi_id}")

    if issue_detected is False:
        plugin_object.add_output_data("OK", default_text, summary=True, location=f"Chassi {chassi_id}")

    return

# EOF
