# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import (
    Firmware, PhysicalDrive, LogicalDrive, StorageController, StorageEnclosure, PowerSupply
)
from cr_module.system_chassi import get_chassi_data
from cr_module.common import grab, get_status_data
from cr_module.storage import get_storage


# noinspection PyShadowingNames
def get_firmware_info(plugin_object):
    plugin_object.set_current_command("Firmware Info")

    # call dedicated firmware functions for HPE iLO4 and Fujitsu
    if (plugin_object.rf.vendor == "HPE" and plugin_object.rf.vendor_data.ilo_version.lower() == "ilo 4") \
            or plugin_object.rf.vendor == "Fujitsu":

        system_ids = plugin_object.rf.get_system_properties("systems")

        if system_ids is None or len(system_ids) == 0:
            plugin_object.inventory.add_issue(Firmware, "No 'systems' property found in root path '/redfish/v1'")
            return

        for system_id in system_ids:

            if plugin_object.rf.vendor == "Fujitsu":
                get_firmware_info_fujitsu(plugin_object, system_id)
            else:
                get_firmware_info_hpe_ilo4(plugin_object, system_id)

    else:
        get_firmware_info_generic(plugin_object)

    # return gathered firmware information
    firmware_health_summary = "OK"
    firmware_status_entries = list()
    for firmware_inventory in plugin_object.inventory.get(Firmware):

        firmware_health = "OK"

        if firmware_inventory.health_status is not None:

            if firmware_inventory.health_status == "CRITICAL":
                firmware_health = firmware_inventory.health_status
                firmware_health_summary = firmware_inventory.health_status

            if firmware_inventory.health_status == "WARNING":
                firmware_health = firmware_inventory.health_status
                if firmware_health_summary != "CRITICAL":
                    firmware_health_summary = firmware_inventory.health_status

        name = firmware_inventory.name
        firmware_id = ""

        if plugin_object.rf.vendor != "HPE" and firmware_inventory.id is not None and \
                firmware_inventory.name != firmware_inventory.id:

            firmware_id = f" ({firmware_inventory.id})"

        location = ""
        if firmware_inventory.location is not None:
            location = f" ({firmware_inventory.location})"

        firmware_status_entries.append({
            "health": firmware_health,
            "firmware": f"{name}{firmware_id}{location}: {firmware_inventory.version}"
        })

    summary_text = f"Found %d firmware entries." % len(plugin_object.inventory.get(Firmware))
    if plugin_object.cli_args.detailed is False:
        summary_text += f" Use '--detailed' option to display them."

    plugin_object.add_output_data(firmware_health_summary, summary_text, summary=not plugin_object.cli_args.detailed)

    firmware_status_entries = sorted(firmware_status_entries, key=lambda k: k["firmware"])
    if plugin_object.cli_args.detailed is True:
        for entry in firmware_status_entries:
            plugin_object.add_output_data(entry.get("health"), entry.get("firmware"))

    # remove inventory date if not requested
    if any(x in plugin_object.cli_args.requested_query for x in ['storage', 'all']) is False:
        plugin_object.inventory.unset(PhysicalDrive)
        plugin_object.inventory.unset(LogicalDrive)
        plugin_object.inventory.unset(StorageController)
        plugin_object.inventory.unset(StorageEnclosure)
    if any(x in plugin_object.cli_args.requested_query for x in ['power', 'all']) is False:
        plugin_object.inventory.unset(PowerSupply)

    return


# noinspection PyShadowingNames
def get_firmware_info_hpe_ilo4(plugin_object, system_id):

    redfish_url = f"{system_id}/FirmwareInventory/"

    firmware_response = plugin_object.rf.get(redfish_url)

    fw_id = 0
    for key, firmware_entry in firmware_response.get("Current").items():

        for firmware_entry_object in firmware_entry:

            fw_id += 1

            firmware_inventory = Firmware(
                id=fw_id,
                name=firmware_entry_object.get("Name").replace("iLO", "iLO4"),
                version=firmware_entry_object.get("VersionString"),
                location=firmware_entry_object.get("Location")
            )

            if plugin_object.cli_args.verbose:
                firmware_inventory.source_data = firmware_entry_object

            plugin_object.inventory.add(firmware_inventory)

    if firmware_response.get("error"):
        plugin_object.add_data_retrieval_error(Firmware, firmware_response, redfish_url)

    if any(x in plugin_object.cli_args.requested_query for x in ['storage', 'all']) is False:
        plugin_object.in_firmware_collection_mode(True)
        get_storage(plugin_object)
        plugin_object.in_firmware_collection_mode(False)

    for drive in plugin_object.inventory.get(PhysicalDrive):
        fw_id += 1

        firmware_inventory = Firmware(
            id=fw_id,
            name=f"Drive {drive.model}",
            version=drive.firmware,
            location=drive.location
        )
        if plugin_object.cli_args.verbose:
            firmware_inventory.source_data = drive.source_data

        plugin_object.inventory.add(firmware_inventory)

    for storage_enclosure in plugin_object.inventory.get(StorageEnclosure):
        fw_id += 1

        if storage_enclosure.firmware is None:
            continue

        firmware_inventory = Firmware(
            id=fw_id,
            name="Storage Enclosure",
            version=storage_enclosure.firmware,
            location=storage_enclosure.location
        )
        if plugin_object.cli_args.verbose:
            firmware_inventory.source_data = storage_enclosure.source_data

        plugin_object.inventory.add(firmware_inventory)

    return


# noinspection PyShadowingNames
def get_firmware_info_fujitsu(plugin_object, system_id, bmc_only=False):
    # there is room for improvement

    # list of dicts: keys: {name, version, location}
    firmware_entries = list()

    # get iRMC firmware
    manager_ids = plugin_object.rf.get_system_properties("managers")

    if manager_ids is not None and len(manager_ids) > 0:

        manager_response = plugin_object.rf.get(manager_ids[0])

        if manager_response.get("error"):
            plugin_object.add_data_retrieval_error(Firmware, manager_response, manager_ids[0])
            return

        # get configuration
        irmc_configuration_link = grab(manager_response,
                                       f"Oem/{plugin_object.rf.vendor_dict_key}/iRMCConfiguration/@odata.id",
                                       separator="/")

        irmc_configuration = None
        if irmc_configuration_link is not None:
            irmc_configuration = plugin_object.rf.get(irmc_configuration_link)

            if irmc_configuration.get("error"):
                plugin_object.add_data_retrieval_error(Firmware, irmc_configuration, irmc_configuration_link)

        irmc_firmware_information = None
        firmware_information_link = grab(irmc_configuration, f"FWUpdate/@odata.id", separator="/")
        if firmware_information_link is not None:
            irmc_firmware_information = plugin_object.rf.get(firmware_information_link)

            if irmc_firmware_information.get("error"):
                plugin_object.add_data_retrieval_error(Firmware, irmc_firmware_information, irmc_configuration_link)

        if irmc_firmware_information is not None:
            for bmc_fw_bank in ["iRMCFwImageHigh", "iRMCFwImageLow"]:
                fw_info = irmc_firmware_information.get(bmc_fw_bank)
                if fw_info is not None:
                    firmware_entries.append(
                        {"id": bmc_fw_bank,
                         "name": "%s iRMC" % fw_info.get("FirmwareRunningState"),
                         "version": "%s, Booter %s, SDDR: %s/%s (%s)" % (
                             fw_info.get("FirmwareVersion"),
                             fw_info.get("BooterVersion"),
                             fw_info.get("SDRRVersion"),
                             fw_info.get("SDRRId"),
                             fw_info.get("FirmwareBuildDate")
                         ),
                         "location": "System Board"
                         }
                    )

        # special case:
        #   Firmware information was requested from bmc check.
        #   So we just return the bmc firmware list
        if bmc_only is True:
            return firmware_entries

    # get power supply and storage firmware
    plugin_object.in_firmware_collection_mode(True)
    if any(x in plugin_object.cli_args.requested_query for x in ['power', 'all']) is False:
        get_chassi_data(plugin_object, PowerSupply)
    if any(x in plugin_object.cli_args.requested_query for x in ['storage', 'all']) is False:
        get_storage(plugin_object)
    plugin_object.in_firmware_collection_mode(False)

    for power_supply in plugin_object.inventory.get(PowerSupply):

        firmware_entries.append({
            "id": f"{power_supply.name}",
            "name": f"Power Supply {power_supply.vendor} {power_supply.model}",
            "version": f"{power_supply.firmware}",
            "location": f"{power_supply.name}"
        })

    for drive in plugin_object.inventory.get(PhysicalDrive):

        firmware_entries.append({
            "id": f"Drive:{drive.id}",
            "name": f"Drive {drive.name}",
            "version": f"{drive.firmware}",
            "location": f"Slot {drive.bay}"
        })

    # get other firmware
    redfish_url = f"{system_id}/Oem/%s/FirmwareInventory/" % plugin_object.rf.vendor_dict_key

    system_id_num = system_id.rstrip("/").split("/")[-1]

    firmware_response = plugin_object.rf.get(redfish_url)

    if firmware_response.get("error"):
        plugin_object.add_data_retrieval_error(Firmware, firmware_response, redfish_url)

    # get BIOS
    if firmware_response.get("SystemBIOS"):
        firmware_entries.append({
            "id": f"System:{system_id_num}",
            "name": "SystemBIOS",
            "version": "%s" % firmware_response.get("SystemBIOS"),
            "location": "System Board"
        })

    # get other components
    for key, value in firmware_response.items():

        if key.startswith("@"):
            continue

        if isinstance(value, dict) and value.get("@odata.id") is not None:
            component_type = value.get("@odata.id").rstrip("/").split("/")[-1]
            component_fw_data = plugin_object.rf.get(value.get("@odata.id"))

            if component_fw_data.get("error"):
                plugin_object.add_data_retrieval_error(Firmware, component_fw_data, value.get("@odata.id"))

            component_id = 0
            for component_entry in component_fw_data.get("Ports", list()):
                component_id += 1

                component_name = component_entry.get("AdapterName")
                component_location = component_entry.get("ModuleName")
                component_bios_version = component_entry.get("BiosVersion")
                component_fw_version = component_entry.get("FirmwareVersion")
                component_slot = component_entry.get("SlotId")
                component_port = component_entry.get("PortId")

                firmware_entries.append({
                    "id": f"{component_type}_Port_{component_id}",
                    "name": f"{component_name}",
                    "version": f"{component_fw_version} (BIOS: {component_bios_version})",
                    "location": f"{component_location} {component_slot}/{component_port}"
                })

            component_id = 0
            for component_entry in component_fw_data.get("Adapters", list()):
                component_id += 1

                component_name = component_entry.get("ModuleName")
                component_pci_segment = component_entry.get("PciSegment")
                component_bios_version = component_entry.get("BiosVersion")
                component_fw_version = component_entry.get("FirmwareVersion")

                firmware_entries.append({
                    "id": f"{component_type}_Adapter_{component_id}",
                    "name": f"{component_name} controller",
                    "version": f"{component_fw_version} (BIOS: {component_bios_version})",
                    "location": f"{system_id_num}:{component_pci_segment}"
                })

    # add firmware entry to inventory
    for fw_entry in firmware_entries:

        firmware_inventory = Firmware(**fw_entry)

        if plugin_object.cli_args.verbose:
            firmware_inventory.source_data = fw_entry

        plugin_object.inventory.add(firmware_inventory)

    return


def get_firmware_info_generic(plugin_object):

    if plugin_object.rf.connection.root.get("UpdateService") is None:
        plugin_object.inventory.add_issue(Firmware,
                                          "URL '/redfish/v1/UpdateService' unavailable. "
                                          "Unable to retrieve firmware information.")
        return

    redfish_url = f"/redfish/v1/UpdateService/FirmwareInventory{plugin_object.rf.vendor_data.expand_string}"

    firmware_response = plugin_object.rf.get(redfish_url)

    if firmware_response.get("error"):
        plugin_object.add_data_retrieval_error(Firmware, firmware_response, redfish_url)

    # older Cisco CIMC versions reported Firmware inventory in a different fashion
    if plugin_object.rf.vendor == "Cisco":
        if firmware_response.get("@odata.id") is None:
            redfish_url = f"/redfish/v1/UpdateService/{plugin_object.rf.vendor_data.expand_string}"
            firmware_response = plugin_object.rf.get(redfish_url)
            if firmware_response.get("error"):
                plugin_object.add_data_retrieval_error(Firmware, firmware_response, redfish_url)

        if firmware_response.get("FirmwareInventory") is not None:
            firmware_response["Members"] = firmware_response.get("FirmwareInventory")

    for firmware_member in firmware_response.get("Members"):

        if firmware_member.get("@odata.type"):
            firmware_entry = firmware_member
        else:
            firmware_entry = plugin_object.rf.get(firmware_member.get("@odata.id"))

            if firmware_entry.get("error"):
                plugin_object.add_data_retrieval_error(Firmware, firmware_entry, firmware_member.get("@odata.id"))
                continue

        # get name and id
        component_name = f"{firmware_entry.get('Name')}"
        component_id = firmware_entry.get("Id")

        if component_id == component_name and firmware_entry.get("SoftwareId") is not None:
            component_name = firmware_entry.get("SoftwareId")

        if component_id is None:
            component_id = component_name

        # on Dell system skip power supplies and disk and collect them separately
        # only one of the disk and power supply is reported not all of them
        if plugin_object.rf.vendor == "Dell" and component_name is not None:
            if "power supply" in component_name.lower():
                continue
            if "disk " in component_name.lower():
                continue

        if component_name.lower().startswith("firmware:"):
            component_name = component_name[9:]

        # get firmware version
        component_version = firmware_entry.get("Version")
        if component_version is not None:
            component_version = component_version.strip().replace("\n", "")

        if grab(firmware_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.FirmwareBuild") is not None:
            component_version = f"{component_version} %s" % \
                                grab(firmware_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.FirmwareBuild")

        # get location
        component_location = grab(firmware_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.PositionId")

        if plugin_object.rf.vendor == "HPE":
            component_location = grab(firmware_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.DeviceContext")

        if component_location is None and firmware_entry.get("SoftwareId") is not None:
            component_location = firmware_entry.get("SoftwareId")

        # get status
        status_data = get_status_data(firmware_entry.get("Status"))

        firmware_inventory = Firmware(
            id=component_id,
            name=component_name,
            health_status=status_data.get("Health"),
            operation_status=status_data.get("State"),
            version=component_version,
            location=component_location,
            updateable=firmware_entry.get("Updateable")
        )

        if plugin_object.cli_args.verbose:
            firmware_inventory.source_data = firmware_entry

        plugin_object.inventory.add(firmware_inventory)

    if plugin_object.rf.vendor in ["Dell", "Cisco", "Lenovo"]:
        get_drives = True
        get_controllers = False
        get_power = True
        plugin_object.in_firmware_collection_mode(True)
        if any(x in plugin_object.cli_args.requested_query for x in ['storage', 'all']) is False:
            get_storage(plugin_object)
        if any(x in plugin_object.cli_args.requested_query for x in ['power', 'all']) is False:
            get_chassi_data(plugin_object, PowerSupply)
        plugin_object.in_firmware_collection_mode(False)

        # vendor specific conditions
        if plugin_object.rf.vendor == "Cisco":
            get_controllers = True
        if plugin_object.rf.vendor == "Lenovo":
            for fw_object in plugin_object.inventory.get(Firmware):
                if fw_object.name.lower().startswith("disk"):
                    get_drives = False
                if fw_object.name.lower().startswith("power"):
                    get_power = False

        fw_id = len(plugin_object.inventory.get(Firmware)) - 1
        if get_drives is True:
            for drive in plugin_object.inventory.get(PhysicalDrive):
                fw_id += 1

                firmware_inventory = Firmware(
                    id=fw_id,
                    name=f"Drive {drive.name}",
                    version=drive.firmware,
                    location=drive.location
                )
                if plugin_object.cli_args.verbose:
                    firmware_inventory.source_data = drive.source_data

                plugin_object.inventory.add(firmware_inventory)

        if get_controllers is True:
            for storage_controller in plugin_object.inventory.get(StorageController):
                fw_id += 1

                if storage_controller.firmware is None:
                    continue

                firmware_inventory = Firmware(
                    id=fw_id,
                    name=f"Storage Controller {storage_controller.name}",
                    version=storage_controller.firmware,
                    location=storage_controller.location
                )
                if plugin_object.cli_args.verbose:
                    firmware_inventory.source_data = storage_controller.source_data

                plugin_object.inventory.add(firmware_inventory)

        for storage_enclosure in plugin_object.inventory.get(StorageEnclosure):
            fw_id += 1

            if storage_enclosure.firmware is None:
                continue

            firmware_inventory = Firmware(
                id=fw_id,
                name="Storage Enclosure",
                version=storage_enclosure.firmware,
                location=storage_enclosure.bay
            )
            if plugin_object.cli_args.verbose:
                firmware_inventory.source_data = storage_enclosure.source_data

            plugin_object.inventory.add(firmware_inventory)

        if get_power is True:
            for power_supply in plugin_object.inventory.get(PowerSupply):
                fw_id += 1

                if power_supply.firmware is None:
                    continue

                firmware_inventory = Firmware(
                    id=fw_id,
                    name=f"Power Supply {power_supply.model}",
                    version=power_supply.firmware,
                    location=f"Slot {power_supply.bay}"
                )
                if plugin_object.cli_args.verbose:
                    firmware_inventory.source_data = power_supply.source_data

                plugin_object.inventory.add(firmware_inventory)

    return

# EOF
