# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes import plugin_status_types
from cr_module.classes.inventory import System, Chassis, Fan, PowerSupply, Temperature, Memory, Processor
from cr_module.classes.plugin import PluginData
from cr_module.common import get_status_data, grab
from cr_module.power import get_single_chassis_power
from cr_module.temp import get_single_chassis_temp
from cr_module.fan import get_single_chassis_fan
from cr_module.proc import get_single_system_procs
from cr_module.mem import get_single_system_mem


def get_chassis_data(data_type):

    plugin_object = PluginData()

    chassis = plugin_object.rf.get_system_properties("chassis") or list()

    if len(chassis) == 0:
        plugin_object.inventory.add_issue(data_type, "No 'chassis' property found in root path '/redfish/v1'")
        return

    handler = {
        PowerSupply: get_single_chassis_power,
        Temperature: get_single_chassis_temp,
        Fan: get_single_chassis_fan
    }

    if data_type not in handler.keys():
        raise AttributeError(f"Unknown data_type used for get_chassis_data(): {type(data_type)}")

    data_point = "Power" if data_type == PowerSupply else "Thermal"

    for chassis_url in chassis:

        chassis_id = chassis_url.rstrip("/").split("/")[-1]

        chassis_data = plugin_object.rf.get(chassis_url)
        discovered_url = grab(chassis_data, f"{data_point}/@odata.id", separator="/")

        # add compatibility layer for HPE Compute Scale-up Server 3200
        query_sensors = False
        if discovered_url is None:
            discovered_url = grab(chassis_data, f"{data_point}Subsystem/@odata.id", separator="/")
            query_sensors = True

        sensors_url = grab(chassis_data, f"Sensors/@odata.id", separator="/")
        sensors_data = list()

        if sensors_url is not None and query_sensors and data_type in [Fan]:
            sensors_url_data = plugin_object.rf.get_view(sensors_url)
            for sensor in sensors_url_data.get("Members", list()):

                if sensor.get("@odata.context") or "Name" in list(sensor.keys()):
                    sensors_data.append(sensor)
                else:
                    sensor_response = plugin_object.rf.get(sensor.get("@odata.id"))
                    if sensor_response.get("error") is None:
                        sensors_data.append(sensor_response)

        fallback_url = f"{chassis_url}/{data_point}"

        chassis_power_thermal_data = None
        discovered_url_data = None

        # power/thermal data present
        if discovered_url is not None:
            discovered_url_data = plugin_object.rf.get_view(discovered_url)

            if discovered_url_data.get("error") is None and str(discovered_url_data) != "{'Members': []}":
                chassis_power_thermal_data = discovered_url_data

        # fallback also failed
        if chassis_power_thermal_data is None:

            # there is just no data endpoint
            if discovered_url is None:
                if data_type == PowerSupply:
                    plugin_object.set_current_command("Power")
                    default_text = f"Chassis {chassis_id} has no power supplies installed/reported"
                elif data_type == Temperature:
                    plugin_object.set_current_command("Temp")
                    default_text = f"Chassis {chassis_id} has no temp sensors installed/reported"
                else:
                    plugin_object.set_current_command("Fan")
                    default_text = f"Chassis {chassis_id} has no fans installed/reported"

                plugin_object.add_output_data("OK", default_text, summary=True, location=f"Chassis {chassis_id}")
                continue

            # there seems to be an error retrieving data
            if discovered_url is not None and discovered_url_data is not None:
                # hand over to handle returned data
                handler.get(data_type)(discovered_url, chassis_id, discovered_url_data, sensors_data)

        else:
            data_url = discovered_url if discovered_url is not None else fallback_url
            handler.get(data_type)(data_url, chassis_id, chassis_power_thermal_data, sensors_data)

    return


def get_system_data(data_type):

    plugin_object = PluginData()

    systems = plugin_object.rf.get_system_properties("systems") or list()

    if len(systems) == 0:
        plugin_object.inventory.add_issue(data_type, "No 'systems' property found in root path '/redfish/v1'")
        return

    for system in systems:
        if data_type == Processor:
            get_single_system_procs(system)
        elif data_type == Memory:
            get_single_system_mem(system)
        else:
            raise AttributeError("Unknown data_type not set for get_system_data(): %s", type(data_type))

    return


def get_system_info():

    plugin_object = PluginData()

    plugin_object.set_current_command("System Info")

    systems = plugin_object.rf.get_system_properties("systems") or list()

    if len(systems) == 0:
        plugin_object.inventory.add_issue(System, "No 'systems' property found in root path '/redfish/v1'")
        return

    for system in systems:
        get_single_system_info(system)

    # add chassis inventory here too
    if plugin_object.cli_args.inventory is True:

        for chassis in plugin_object.rf.get_system_properties("chassis") or list():
            get_single_chassis_info(chassis)

    return


def get_single_system_info(redfish_url):

    plugin_object = PluginData()

    system_response = plugin_object.rf.get(redfish_url)

    system_id = redfish_url.rstrip("/").split("/")[-1]

    if system_response is None:
        plugin_object.inventory.add_issue(System, f"No system information data returned for API URL '{redfish_url}'")
        return
    elif system_response.get("error"):
        plugin_object.add_data_retrieval_error(System, system_response, redfish_url)
        return

    # get model data
    model = system_response.get("Model")
    # Huawei system
    if plugin_object.rf.vendor == "Huawei":
        huawei_model = grab(system_response, f"Oem.{plugin_object.rf.vendor_dict_key}.ProductName")

        if huawei_model is not None:
            model = huawei_model

    if model is None:
        model = plugin_object.rf.connection.root.get("Product")

    # get memory size
    mem_size = grab(system_response, "MemorySummary.TotalSystemMemoryGiB")

    # Dell system
    # just WHY?
    if plugin_object.rf.vendor == "Dell" and mem_size is not None and int(mem_size) % 16 != 0:
        mem_size = round(mem_size * 1024 ** 3 / 1000 ** 3)

    status_data = get_status_data(system_response.get("Status"))

    manufacturer = system_response.get("Manufacturer")
    if manufacturer is None:
        manufacturer = plugin_object.rf.vendor


    system_inventory = System(
        id=system_response.get("Id"),
        name=system_response.get("Name"),
        manufacturer=manufacturer,
        serial=system_response.get("SerialNumber"),
        health_status=status_data.get("Health"),
        operation_status=status_data.get("State"),
        power_state=system_response.get("PowerState"),
        bios_version=system_response.get("BiosVersion"),
        host_name=system_response.get("HostName"),
        indicator_led=system_response.get("IndicatorLED"),
        cpu_num=grab(system_response, "ProcessorSummary.Count"),
        part_number=system_response.get("PartNumber"),
        mem_size=mem_size,
        model=model,
        type=system_response.get("SystemType")
    )

    if plugin_object.cli_args.verbose:
        system_inventory.source_data = system_response

    # add relations
    system_inventory.add_relation(plugin_object.rf.get_system_properties(), system_response.get("Links"))

    plugin_object.inventory.add(system_inventory)

    host_name = "NOT SET"
    if system_inventory.host_name is not None and len(system_inventory.host_name) > 0:
        host_name = system_inventory.host_name

    status_text_data = list()
    status_text_data.append(f"INFO: {system_inventory.manufacturer} {system_inventory.model} "
                            f"(CPU: {system_inventory.cpu_num}, MEM: {system_inventory.mem_size}GB)")
    status_text_data.append(f"BIOS: {system_inventory.bios_version}")
    status_text_data.append(f"Serial: {system_inventory.serial}")
    if plugin_object.rf.vendor == "Dell":
        status_text_data.append(f"ServiceTag: {system_response.get('SKU')}")
    status_text_data.append(f"Power: {system_inventory.power_state}")
    status_text_data.append(f"Name: {host_name}")

    status_text = " - ".join(status_text_data)

    system_health_print_status = \
        "CRITICAL" if system_inventory.health_status not in ["OK", "WARNING"] else system_inventory.health_status

    # add DellSensorCollection if present
    dell_sensors = list()
    if plugin_object.rf.vendor == "Dell":

        dell_empty_slots = list()

        dell_slot_collection = \
            grab(system_response, f"Links.Oem.{plugin_object.rf.vendor_dict_key}.DellSlotCollection")

        # collect info about empty slots
        if dell_slot_collection is not None and dell_slot_collection.get("@odata.id") is not None:
            collection_response = plugin_object.rf.get(dell_slot_collection.get("@odata.id"))

            if collection_response is not None and (
                    collection_response.get("Members") is None or len(collection_response.get("Members")) > 0):

                for dell_slot in collection_response.get("Members"):

                    if dell_slot.get("EmptySlot") is True:
                        dell_empty_slots.append(dell_slot.get("Id"))

        dell_sensor_collection = \
            grab(system_response, f"Links.Oem.{plugin_object.rf.vendor_dict_key}.DellSensorCollection")

        if dell_sensor_collection is not None and dell_sensor_collection.get("@odata.id") is not None:
            collection_response = plugin_object.rf.get(dell_sensor_collection.get("@odata.id"))

            num_members = 0
            if collection_response is not None and (
                    collection_response.get("Members") is None or len(collection_response.get("Members")) > 0):

                for dell_sensor in collection_response.get("Members"):

                    # skip if sensor slot is empty
                    if any(x.startswith(dell_sensor.get("Id")) for x in dell_empty_slots):
                        continue

                    # skip unknown DIMM and CPU status
                    if dell_sensor.get('CurrentState') == dell_sensor.get('HealthState') and \
                            dell_sensor.get('HealthState').upper() == "UNKNOWN":
                        continue

                    num_members += 1

                    this_sensor_status = "OK"

                    if dell_sensor.get('EnabledState') == "Enabled" and system_inventory.power_state.upper() == "ON":
                        if "WARNING" in dell_sensor.get('HealthState').upper():
                            this_sensor_status = "WARNING"
                        elif dell_sensor.get('HealthState') != "OK":
                            this_sensor_status = "CRITICAL"

                    dell_sensors.append({this_sensor_status: 'Sensor "%s": %s (%s/%s)' % (
                        dell_sensor.get('ElementName'),
                        dell_sensor.get('HealthState'),
                        dell_sensor.get('EnabledState'),
                        dell_sensor.get('CurrentState')
                    )})

        # get the most severe state from system and sensors
        if len(dell_sensors) > 0:
            dell_sensor_states = [k for d in dell_sensors for k in d]
            system_health_print_status = \
                plugin_object.return_highest_status(dell_sensor_states + [system_health_print_status])

            if plugin_object.cli_args.detailed is False:
                dell_sensor_text = list()
                for status_type_name, _ in sorted(plugin_status_types.items(), key=lambda item: item[1], reverse=True):
                    state_count = dell_sensor_states.count(status_type_name)
                    if state_count == 1:
                        dell_sensor_text.append(f"{state_count} health sensor in '{status_type_name}' state")
                    elif state_count > 1:
                        dell_sensor_text.append(f"{state_count} health sensors are in '{status_type_name}' state")

                status_text += " - " + ", ".join(dell_sensor_text)

    plugin_object.add_output_data(system_health_print_status, status_text,
                                  summary=True,
                                  location=f"System {system_id}")

    for dell_sensor in dell_sensors:
        for status, sensor in dell_sensor.items():
            plugin_object.add_output_data(status, sensor, location=f"System {system_id}")

    # add ILO data
    if plugin_object.rf.vendor == "HPE":
        plugin_object.add_output_data("OK", "%s - FW: %s" %
                                      (plugin_object.rf.vendor_data.get_bmc_model(),
                                       plugin_object.rf.vendor_data.bmc_firmware_version),
                                      location=f"System {system_id}")

        power_regulator_mode = grab(system_response, f"Oem.{plugin_object.rf.vendor_dict_key}.PowerRegulatorMode")
        power_auto_on = grab(system_response, f"Oem.{plugin_object.rf.vendor_dict_key}.PowerAutoOn")

        power_text = list()
        if power_regulator_mode is not None:
            power_text.append(f"Power Regulator Mode: {power_regulator_mode}")

        if power_auto_on is not None:
            power_text.append(f"Power Auto On: {power_auto_on}")

        if len(power_text):
            plugin_object.add_output_data("OK", " - ".join(power_text), location=f"System {system_id}")

    # add SDCard status
    if plugin_object.rf.vendor == "Fujitsu":
        sd_card = plugin_object.rf.get(redfish_url + "/Oem/ts_fujitsu/SDCard")

        if sd_card.get("Inserted") is True and sd_card.get("Mounted") is True:
            sd_card_status = sd_card.get("Status")
            sd_card_capacity = sd_card.get("CapacityMB")
            sd_card_free_space = sd_card.get("FreeSpaceMB")

            status_text = f"SDCard Capacity {sd_card_capacity}MB and {sd_card_free_space}MB free space left."
            plugin_object.add_output_data("CRITICAL" if sd_card_status not in ["OK", "WARNING"] else sd_card_status,
                                          status_text, location=f"System {system_id}")

    return


def get_single_chassis_info(redfish_url):

    plugin_object = PluginData()

    chassis_response = plugin_object.rf.get(redfish_url)

    if chassis_response is None:
        plugin_object.inventory.add_issue(Chassis, f"No chassis information data returned for API URL '{redfish_url}'")
        return
    elif chassis_response.get("error"):
        plugin_object.add_data_retrieval_error(Chassis, chassis_response, redfish_url)
        return

    # get status data
    status_data = get_status_data(chassis_response.get("Status"))

    chassis_inventory = Chassis(
        id=chassis_response.get("Id"),
        name=chassis_response.get("Name"),
        manufacturer=chassis_response.get("Manufacturer"),
        serial=chassis_response.get("SerialNumber"),
        health_status=status_data.get("Health"),
        operation_status=status_data.get("State"),
        sku=chassis_response.get("SKU"),
        indicator_led=chassis_response.get("IndicatorLED"),
        model=chassis_response.get("Model"),
        type=chassis_response.get("ChassisType")
    )

    # add Supermicro data
    if grab(chassis_response, "Oem.Supermicro") is not None:
        chassis_inventory.manufacturer = "Supermicro"
        chassis_inventory.model = chassis_response.get("PartNumber")

    if plugin_object.cli_args.verbose:
        chassis_inventory.source_data = chassis_response

    # add relations
    chassis_inventory.add_relation(plugin_object.rf.get_system_properties(), chassis_response.get("Links"))

    plugin_object.inventory.add(chassis_inventory)

    return

# EOF
