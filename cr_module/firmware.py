
from cr_module.classes.inventory import Firmware
from cr_module.common import grab, get_status_data


# noinspection PyShadowingNames
def get_firmware_info(plugin_object):
    plugin_object.set_current_command("Firmware Info")

    # call dedicated firmware functions for HPE iLO4 and Fujitsu
    if (plugin_object.rf.vendor == "HPE" and plugin_object.rf.vendor_data.ilo_version.lower() == "ilo 4") \
            or plugin_object.rf.vendor == "Fujitsu":

        if plugin_object.rf.connection.system_properties is None:
            plugin_object.rf.discover_system_properties()

        system_ids = plugin_object.rf.connection.system_properties.get("systems")

        if system_ids is None or len(system_ids) == 0:
            plugin_object.add_output_data("UNKNOWN", f"No 'systems' property found in root path '/redfish/v1'")
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

        if plugin_object.cli_args.detailed is True:
            plugin_object.add_output_data(firmware_health,
                                          f"{name}{firmware_id}{location}: {firmware_inventory.version}")

    if plugin_object.cli_args.detailed is False:
        plugin_object.add_output_data(firmware_health_summary,
                                      "Found %d firmware entries. Use '--detailed' option to display them." %
                                      len(plugin_object.inventory.get(Firmware)), summary=True)

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
                name=firmware_entry_object.get("Name"),
                version=firmware_entry_object.get("VersionString"),
                location=firmware_entry_object.get("Location")
            )

            if plugin_object.cli_args.verbose:
                firmware_inventory.source_data = firmware_entry_object

            plugin_object.inventory.add(firmware_inventory)

    return


# noinspection PyShadowingNames
def get_firmware_info_fujitsu(plugin_object, system_id, bmc_only=False):
    # there is room for improvement

    # list of dicts: keys: {name, version, location}
    firmware_entries = list()

    if plugin_object.rf.connection.system_properties is None:
        plugin_object.rf.discover_system_properties()

    # get iRMC firmware
    manager_ids = plugin_object.rf.connection.system_properties.get("managers")

    if manager_ids is not None and len(manager_ids) > 0:

        manager_response = plugin_object.rf.get(manager_ids[0])

        # get configuration
        irmc_configuration_link = grab(manager_response,
                                       f"Oem/{plugin_object.rf.vendor_dict_key}/iRMCConfiguration/@odata.id",
                                       separator="/")

        irmc_configuration = None
        if irmc_configuration_link is not None:
            irmc_configuration = plugin_object.rf.get(irmc_configuration_link)

        irmc_firmware_information = None
        firmware_information_link = grab(irmc_configuration, f"FWUpdate/@odata.id", separator="/")
        if firmware_information_link is not None:
            irmc_firmware_information = plugin_object.rf.get(firmware_information_link)

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

    # get power supply firmware
    chassi_ids = plugin_object.rf.connection.system_properties.get("chassis")

    if chassi_ids is not None and len(chassi_ids) > 0:

        for chassi_id in chassi_ids:
            power_data = plugin_object.rf.get(f"{chassi_id}/Power")

            if power_data.get("PowerSupplies") is not None and len(power_data.get("PowerSupplies")) > 0:

                for ps_data in power_data.get("PowerSupplies"):
                    ps_manufacturer = ps_data.get("Manufacturer")
                    ps_location = ps_data.get("Name")
                    ps_model = ps_data.get("Model")
                    ps_fw_version = ps_data.get("FirmwareVersion")

                    firmware_entries.append({
                        "id": f"{ps_location}",
                        "name": f"Power Supply {ps_manufacturer} {ps_model}",
                        "version": f"{ps_fw_version}",
                        "location": f"{ps_location}"
                    })

    # get hard drive firmware
    redfish_url = f"{system_id}/Storage" + "%s" % plugin_object.rf.vendor_data.expand_string

    storage_response = plugin_object.rf.get(redfish_url)

    for storage_member in storage_response.get("Members"):

        if storage_member.get("@odata.context"):
            controller_response = storage_member
        else:
            controller_response = plugin_object.rf.get(storage_member.get("@odata.id"))

        for controller_drive in controller_response.get("Drives"):
            drive_response = plugin_object.rf.get(controller_drive.get("@odata.id"))

            if drive_response.get("Name") is not None:
                drive_name = drive_response.get("Name")
                drive_firmware = drive_response.get("Revision")
                drive_slot = grab(drive_response, f"Oem.{plugin_object.rf.vendor_dict_key}.SlotNumber")
                drive_storage_controller = controller_response.get("Id")

                firmware_entries.append({
                    "id": f"Drive:{drive_storage_controller}:{drive_slot}",
                    "name": f"Drive {drive_name}",
                    "version": f"{drive_firmware}",
                    "location": f"{drive_storage_controller}:{drive_slot}"
                })

    # get other firmware
    redfish_url = f"{system_id}/Oem/%s/FirmwareInventory/" % plugin_object.rf.vendor_dict_key

    system_id_num = system_id.rstrip("/").split("/")[-1]

    firmware_response = plugin_object.rf.get(redfish_url)

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

            if component_fw_data.get("Ports") is not None and len(component_fw_data.get("Ports")) > 0:

                component_id = 0
                for component_entry in component_fw_data.get("Ports"):
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

            if component_fw_data.get("Adapters") is not None and len(component_fw_data.get("Adapters")) > 0:

                component_id = 0
                for component_entry in component_fw_data.get("Adapters"):
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
        plugin_object.add_output_data("UNKNOWN",
                                      "URL '/redfish/v1/UpdateService' unavailable. "
                                      "Unable to retrieve firmware information.",
                                      summary=not plugin_object.cli_args.detailed)
        return

    if plugin_object.rf.vendor == "Cisco":
        redfish_url = "/redfish/v1/UpdateService/" + "%s" % plugin_object.rf.vendor_data.expand_string
    else:
        redfish_url = "/redfish/v1/UpdateService/FirmwareInventory/" + "%s" % plugin_object.rf.vendor_data.expand_string

    firmware_response = plugin_object.rf.get(redfish_url)

    if plugin_object.rf.vendor == "Cisco" and firmware_response.get("FirmwareInventory") is not None:
        firmware_response["Members"] = firmware_response.get("FirmwareInventory")

    for firmware_member in firmware_response.get("Members"):

        if firmware_member.get("@odata.type"):
            firmware_entry = firmware_member
        else:
            firmware_entry = plugin_object.rf.get(firmware_member.get("@odata.id"))

        # get name and id
        component_name = firmware_entry.get("Name")
        component_id = firmware_entry.get("Id")

        if component_id == component_name and firmware_entry.get("SoftwareId") is not None:
            component_name = firmware_entry.get("SoftwareId")

        if component_id is None:
            component_id = component_name

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

    return

# EOF
