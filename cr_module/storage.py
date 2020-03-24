
def get_storage():

    global plugin

    plugin.set_current_command("Storage")

    if plugin.rf.connection.system_properties is None:
        discover_system_properties()

    systems = plugin.rf.connection.system_properties.get("systems")

    if systems is None or len(systems) == 0:
        plugin.add_output_data("UNKNOWN", "No 'systems' property found in root path '/redfish/v1'")
        return

    for system in systems:

        if plugin.rf.vendor == "HPE":
            get_storage_hpe(system)

        else:
            get_storage_generic(system)

    return

def get_storage_hpe(system):

    def get_disks(link, type = "DiskDrives"):

        disks_response = plugin.rf.get("%s/%s/?$expand=." % (link,type))

        if disks_response.get("Members") is None:
            if type == "DiskDrives":
                plugin.add_output_data("OK", f"no {type} found for this Controller")
            return

        for disk in disks_response.get("Members"):

            if disk.get("@odata.context"):
                disk_response = disk
            else:
                disk_response = plugin.rf.get(disk.get("@odata.id"))

            # skip already processed disks
            if disk_response.get("@odata.id") in system_drives_list:
                continue
            else:
                system_drives_list.append(disk_response.get("@odata.id"))

            status_data = get_status_data(disk_response.get("Status"))

            # get disk size
            disk_size = None
            if disk_response.get("CapacityLogicalBlocks") is not None and \
               disk_response.get("BlockSizeBytes") is not None:
                disk_size = int(disk_response.get("CapacityLogicalBlocks")) * int(disk_response.get("BlockSizeBytes"))
            elif disk_response.get("CapacityMiB"):
                disk_size = int(disk_response.get("CapacityMiB")) * 1024 ** 2
            elif disk_response.get("CapacityGB"):
                disk_size = disk_response.get("CapacityGB") * 1000 ** 3

            # get location
            drive_location = None
            if disk_response.get("LocationFormat") is not None and disk_response.get("Location") is not None:
                drive_location = dict(zip(disk_response.get("LocationFormat").lower().split(":"), disk_response.get("Location").split(":")))

            predicted_media_life_left_percent = None
            if disk_response.get("SSDEnduranceUtilizationPercentage") is not None:
                try:
                    predicted_media_life_left_percent = 100 - int(disk_response.get("SSDEnduranceUtilizationPercentage"))
                except:
                    pass

            pd_inventory = PhysicalDrive(
                # drive id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id,disk_response.get("Id")),
                name  = disk_response.get("Name"),
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                model = disk_response.get("Model"),
                firmware = grab(disk_response, "FirmwareVersion.Current.VersionString"),
                serial = disk_response.get("SerialNumber"),
                location = disk_response.get("Location"),
                part_number = disk_response.get("PartNumber"),
                type = disk_response.get("MediaType"),
                speed_in_rpm = disk_response.get("RotationalSpeedRpm"),
                failure_predicted = disk_response.get("FailurePredicted"),
                predicted_media_life_left_percent = predicted_media_life_left_percent,
                size_in_byte = disk_size,
                power_on_hours = disk_response.get("PowerOnHours"),
                interface_type = disk_response.get("InterfaceType"),
                interface_speed = disk_response.get("InterfaceSpeedMbps"),
                encrypted = disk_response.get("EncryptedDrive"),
                bay = None if drive_location is None else drive_location.get("bay"),
                temperature = disk_response.get("CurrentTemperatureCelsius")
            )

            if drive_location is not None:
                pd_inventory.storage_port = drive_location.get("controllerport")
            pd_inventory.storage_controller_ids = controller_inventory.id
            pd_inventory.system_ids = system_id

            if args.verbose:
                pd_inventory.source_data = disk_response

            plugin.inventory.add(pd_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "physical_drive_ids", pd_inventory.id)

            size = int(pd_inventory.size_in_byte / 1000 ** 3)

            drive_status_reasons = ""
            if pd_inventory.health_status != "OK":
                drive_status_reasons_list = disk_response.get("DiskDriveStatusReasons")
                if "None" in drive_status_reasons_list:
                    drive_status_reasons_list.remove("None")

                if len(drive_status_reasons_list) > 0:
                    drive_status_reasons = " (%s)" % (", ".join(drive_status_reasons_list))

            status_text = f"Physical Drive ({pd_inventory.location}) {size}GB Status: {pd_inventory.health_status}{drive_status_reasons}"

            plugin.add_output_data("CRITICAL" if pd_inventory.health_status not in ["OK", "WARNING"] else pd_inventory.health_status, status_text)

    def get_logical_drives(link):

        ld_response = plugin.rf.get("%s/LogicalDrives/?$expand=." % link)

        if ld_response.get("Members") is None:
            plugin.add_output_data("OK", "no logical drives found for this Controller")
            return

        for logical_drive in ld_response.get("Members"):

            if logical_drive.get("@odata.context"):
                logical_drive_response = logical_drive
            else:
                logical_drive_response = plugin.rf.get(logical_drive.get("@odata.id"))

            status_data = get_status_data(logical_drive_response.get("Status"))

            # get size
            size = logical_drive_response.get("CapacityMiB")
            if size is not None:
                size = int(size) * 1024 ** 2
                printed_size = size / 1000 ** 3
            else:
                printed_size = 0

            ld_inventory = LogicalDrive(
                # logical drive id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id, logical_drive_response.get("Id")),
                name  = logical_drive_response.get("LogicalDriveName"),
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                type = logical_drive_response.get("LogicalDriveType"),
                size_in_byte = size,
                raid_type = logical_drive_response.get("Raid"),
                encrypted = logical_drive_response.get("LogicalDriveEncryption")
            )

            if args.verbose:
                ld_inventory.source_data = logical_drive_response

            data_drives_link = grab(logical_drive_response, "Links/DataDrives/@odata.id", separator="/")

            if data_drives_link is not None:
                data_drives_response = plugin.rf.get(data_drives_link)

                for data_drive in data_drives_response.get("Members"):
                    data_drive_id = ("{}:{}".format(
                        controller_inventory.id, data_drive.get("@odata.id").rstrip("/").split("/")[-1]))

                    ld_inventory.update("physical_drive_ids", data_drive_id, True)
                    plugin.inventory.append(PhysicalDrive, data_drive_id, "logical_drive_ids", ld_inventory.id)

            ld_inventory.storage_controller_ids = controller_inventory.id
            ld_inventory.system_ids = system_id

            plugin.inventory.add(ld_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "logical_drive_ids", ld_inventory.id)

            status_text = f"Logical Drive ({ld_inventory.id}) %.1fGB (RAID {ld_inventory.raid_type}) Status: {ld_inventory.health_status}" % \
                printed_size

            plugin.add_output_data("CRITICAL" if ld_inventory.health_status not in ["OK", "WARNING"] else ld_inventory.health_status, status_text)

    def get_enclosures(link):

        enclosures_response = plugin.rf.get("%s/StorageEnclosures/?$expand=." % link)

        if enclosures_response.get("Members") is None:
            plugin.add_output_data("OK", "no storage enclosures found for this Controller")
            return

        for enclosure in enclosures_response.get("Members"):

            if enclosure.get("@odata.context"):
                enclosure_response = enclosure
            else:
                enclosure_response = plugin.rf.get(enclosure.get("@odata.id"))

            status_data = get_status_data(enclosure_response.get("Status"))

            # get location
            enclosure_location = None
            if enclosure_response.get("LocationFormat") is not None and enclosure_response.get("Location") is not None:
                enclosure_location = dict(zip(enclosure_response.get("LocationFormat").lower().split(":"), enclosure_response.get("Location").split(":")))

            enclosure_inventory = StorageEnclosure(
                # enclosure id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id, enclosure_response.get("Id")),
                name = enclosure_response.get("Name"),
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                serial = enclosure_response.get("SerialNumber"),
                storage_port = None if enclosure_location is None else enclosure_location.get("controller"),
                model = enclosure_response.get("Model"),
                location = enclosure_response.get("Location"),
                firmware = grab(enclosure_response, "FirmwareVersion.Current.VersionString"),
                num_bays = enclosure_response.get("DriveBayCount")
            )

            if args.verbose:
                enclosure_inventory.source_data = enclosure_response

            enclosure_inventory.storage_controller_ids = controller_inventory.id
            enclosure_inventory.system_ids = system_id

            # set relation between disk drives and enclosures
            for drive in plugin.inventory.base_structure.get("physical_drives"):

                # get list of drives for each enclosure
                if drive.location is not None and enclosure_inventory.location is not None and \
                    drive.location.startswith(enclosure_inventory.location):
                    enclosure_inventory.update("physical_drive_ids", drive.id, True)
                    plugin.inventory.append(PhysicalDrive, drive.id, "storage_enclosure_ids", enclosure_inventory.id)

            plugin.inventory.add(enclosure_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "storage_enclosure_ids", enclosure_inventory.id)


            status_text = f"StorageEnclosure ({enclosure_inventory.location}) Status: {enclosure_inventory.health_status}"

            plugin.add_output_data("CRITICAL" if enclosure_inventory.health_status not in ["OK", "WARNING"] else enclosure_inventory.health_status, status_text)

    global plugin

    plugin.set_current_command("Storage")

    system_id = system.rstrip("/").split("/")[-1]

    redfish_url = f"{system}/SmartStorage/"

    storage_response = plugin.rf.get(redfish_url)

    storage_status = get_status_data(storage_response.get("Status"))
    status = storage_status.get("Health")

    if status == "OK" and args.detailed == False and args.inventory == False:
        plugin.add_output_data("OK", f"Status of HP SmartArray is: {status}", summary = True)
        return

    # unhealthy
    redfish_url = f"{system}/SmartStorage/ArrayControllers/?$expand=."

    system_drives_list = list()
    array_controllers_response = plugin.rf.get(redfish_url)

    if array_controllers_response.get("Members"):

        for array_controller in array_controllers_response.get("Members"):

            if array_controller.get("@odata.context"):
                controller_response = array_controller
            else:
                controller_response = plugin.rf.get(array_controller.get("@odata.id"))

            if controller_response.get("Id"):

                status_data = get_status_data(controller_response.get("Status"))

                backup_power_present = False
                if controller_response.get("BackupPowerSourceStatus") == "Present":
                    backup_power_present = True

                controller_inventory = StorageController(
                    id = controller_response.get("Id"),
                    name  = controller_response.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    model = controller_response.get("Model"),
                    manufacturer = "HPE",
                    firmware = grab(controller_response, "FirmwareVersion.Current.VersionString"),
                    serial = controller_response.get("SerialNumber"),
                    location = controller_response.get("Location"),
                    backup_power_present = backup_power_present,
                    cache_size_in_mb = controller_response.get("CacheMemorySizeMiB"),
                    system_ids = system_id
                )

                if args.verbose:
                    controller_inventory.source_data = controller_response

                plugin.inventory.add(controller_inventory)

                if controller_inventory.operation_status == "Absent":
                    continue

                status_text = f"{controller_inventory.model} (FW: {controller_inventory.firmware}) status is: {controller_inventory.health_status}"

                plugin.add_output_data("CRITICAL" if controller_inventory.health_status not in ["OK", "WARNING"] else controller_inventory.health_status, status_text)

                get_disks(array_controller.get("@odata.id"))
                get_disks(array_controller.get("@odata.id"), "UnconfiguredDrives")
                get_logical_drives(array_controller.get("@odata.id"))
                get_enclosures(array_controller.get("@odata.id"))
            else:
                plugin.add_output_data("UNKNOWN", "No array controller data returned for API URL '%s'" % array_controller.get("@odata.id"))

    else:
        plugin.add_output_data("UNKNOWN", f"No array controller data returned for API URL '{redfish_url}'")

    return

def get_storage_generic(system):

    def get_drive(drive_link):

        drive_response = plugin.rf.get(drive_link)

        if drive_response.get("Name") is None:
            plugin.add_output_data("UNKNOWN", f"Unable to retrieve disk infos: {drive_link}")
            return

        # get status data
        status_data = get_status_data(drive_response.get("Status"))

        # get disk size
        disk_size = None
        if drive_response.get("CapacityLogicalBlocks") is not None and \
           drive_response.get("BlockSizeBytes") is not None:
            disk_size = int(drive_response.get("CapacityLogicalBlocks")) * int(drive_response.get("BlockSizeBytes"))
        elif drive_response.get("CapacityBytes"):
            disk_size = drive_response.get("CapacityBytes")
        elif drive_response.get("CapacityMiB"):
            disk_size = int(drive_response.get("CapacityMiB")) * 1024 ** 2
        elif drive_response.get("CapacityGB"):
            disk_size = drive_response.get("CapacityGB") * 1000 ** 3

        drive_oem_data = grab(drive_response, f"Oem.{plugin.rf.vendor_dict_key}")

        temperature = None
        bay = None
        storage_port = None
        power_on_hours = drive_response.get("PowerOnHours")
        if drive_oem_data is not None:
            temperature = drive_oem_data.get("TemperatureCelsius") or drive_oem_data.get("TemperatureC")
            if power_on_hours is None:
                power_on_hours = drive_oem_data.get("HoursOfPoweredUp") or drive_oem_data.get("PowerOnHours")
            bay = drive_oem_data.get("SlotNumber")

        # Dell
        dell_disk_data = grab(drive_oem_data, "DellPhysicalDisk")
        if dell_disk_data is not None:
            if bay is None:
                bay = dell_disk_data.get("Slot")
            storage_port = dell_disk_data.get("Connector")

        interface_speed = None
        if drive_response.get("NegotiatedSpeedGbs") is not None:
            interface_speed = int(drive_response.get("NegotiatedSpeedGbs")) * 1000

        encrypted = None
        if drive_response.get("EncryptionStatus") is not None:
            if drive_response.get("EncryptionStatus").lower() == "encrypted":
                encrypted = True
            else:
                encrypted = False

        pd_inventory = PhysicalDrive(
            # drive id repeats per controller
            # prefix drive id with controller id
            id = "{}:{}".format(controller_inventory.id,drive_response.get("Id")),
            name  = drive_response.get("Name"),
            health_status = status_data.get("Health"),
            operation_status = status_data.get("State"),
            model = drive_response.get("Model"),
            manufacturer = drive_response.get("Manufacturer"),
            firmware = drive_response.get("FirmwareVersion") or drive_response.get("Revision"),
            serial = drive_response.get("SerialNumber"),
            location = grab(drive_response, "Location.0.Info") or grab(drive_response, "PhysicalLocation.0.Info"),
            type = drive_response.get("MediaType"),
            speed_in_rpm = drive_response.get("RotationalSpeedRpm") or drive_response.get("RotationSpeedRPM"),
            failure_predicted = drive_response.get("FailurePredicted"),
            predicted_media_life_left_percent = drive_response.get("PredictedMediaLifeLeftPercent"),
            part_number = drive_response.get("PartNumber"),
            size_in_byte = disk_size,
            power_on_hours = power_on_hours,
            interface_type = drive_response.get("Protocol"),
            interface_speed = interface_speed,
            encrypted = encrypted,
            storage_port = storage_port,
            bay = bay,
            temperature = temperature,
            system_ids = system_response.get("Id"),
            storage_controller_ids = controller_inventory.id
        )

        if args.verbose:
            pd_inventory.source_data = drive_response

        plugin.inventory.add(pd_inventory)

        plugin.inventory.append(StorageController, controller_inventory.id, "physical_drive_ids", pd_inventory.id)

        if pd_inventory.location is None or pd_inventory.name == pd_inventory.location:
            location_string = ""
        else:
            location_string = f"{pd_inventory.location} "

        if pd_inventory.health_status is not None:
            drives_status_list.append(pd_inventory.health_status)

        if pd_inventory.size_in_byte is not None and pd_inventory.size_in_byte > 0:
            size_string = "%0.2fGiB" % (pd_inventory.size_in_byte / ( 1000 ** 3))
        else:
            size_string = "0GiB"

        status_text = f"Physical Drive {pd_inventory.name} {location_string}({pd_inventory.model} / {pd_inventory.type} / {pd_inventory.interface_type}) {size_string} status: {pd_inventory.health_status}"

        plugin.add_output_data("OK" if pd_inventory.health_status in ["OK", None] else pd_inventory.health_status, status_text)

    def get_volumes(volumes_link):

        volumes_response = plugin.rf.get(volumes_link)

        if len(volumes_response.get("Members")) == 0:
            return

        for volume_member in volumes_response.get("Members"):

            volume_data = plugin.rf.get(volume_member.get("@odata.id"))

            if volume_data.get("Name") is None:
                continue

            # get status data
            status_data = get_status_data(volume_data.get("Status"))

            # get size
            size = volume_data.get("CapacityBytes") or 0
            if size is not None:
                printed_size = int(size) / ( 1000 ** 3)
            else:
                printed_size = 0

            name = volume_data.get("Name")

            raid_level = volume_data.get("VolumeType")
            volume_name = volume_data.get("Description")

            oem_data = grab(volume_data, f"Oem.{plugin.rf.vendor_dict_key}")
            if oem_data is not None:
                if plugin.rf.vendor == "Huawei":
                    raid_level = oem_data.get("VolumeRaidLevel")
                    volume_name = oem_data.get("VolumeName")

                if plugin.rf.vendor in ["Fujitsu", "Lenovo"]:
                    raid_level = oem_data.get("RaidLevel")
                    volume_name = oem_data.get("Name")

            ld_inventory = LogicalDrive(
                # logical drive id repeats per controller
                # prefix drive id with controller id
                id = "{}:{}".format(controller_inventory.id, volume_data.get("Id")),
                name = volume_name,
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                type = volume_data.get("VolumeType"),
                size_in_byte = size,
                raid_type = raid_level,
                encrypted = volume_data.get("Encrypted"),
                system_ids = system_response.get("Id"),
                storage_controller_ids = controller_inventory.id
            )

            if args.verbose:
                ld_inventory.source_data = volume_data

            data_drives_links = grab(volume_data, "Links.Drives")

            if data_drives_links is not None:

                for data_drive in data_drives_links:
                    data_drive_id = ("{}:{}".format(
                        controller_inventory.id, data_drive.get("@odata.id").rstrip("/").split("/")[-1]))

                    ld_inventory.update("physical_drive_ids", data_drive_id, True)
                    plugin.inventory.append(PhysicalDrive, data_drive_id, "logical_drive_ids", ld_inventory.id)

            if ld_inventory.health_status is not None:
                volume_status_list.append(ld_inventory.health_status)

            plugin.inventory.add(ld_inventory)

            plugin.inventory.append(StorageController, controller_inventory.id, "logical_drive_ids", ld_inventory.id)

            status_text = "Logical Drive %s (%s) %.0fGiB (%s) Status: %s" % \
                (name, ld_inventory.name, printed_size, ld_inventory.raid_type, ld_inventory.health_status)

            plugin.add_output_data("OK" if ld_inventory.health_status in ["OK", None] else ld_inventory.health_status, status_text)

    def get_enclosures(enclosure_link):

        # skip chassis listed as enclosures
        if enclosure_link in plugin.rf.connection.system_properties.get("chassis"):
            return

        enclosure_response = plugin.rf.get(enclosure_link)

        if enclosure_response.get("Name") is None:
            plugin.add_output_data("UNKNOWN", f"Unable to retrieve enclosure infos: {enclosure_link}")
            return

        chassis_type = enclosure_response.get("ChassisType")
        power_state = enclosure_response.get("PowerState")

        status_data = get_status_data(enclosure_response.get("Status"))

        enclosure_inventory = StorageEnclosure(
            # enclosure id repeats per controller
            # prefix drive id with controller id
            id = "{}:{}".format(controller_inventory.id, enclosure_response.get("Id")),
            name = enclosure_response.get("Name"),
            health_status = status_data.get("Health"),
            operation_status = status_data.get("State"),
            serial = enclosure_response.get("SerialNumber"),
            model = enclosure_response.get("Model"),
            manufacturer = enclosure_response.get("Manufacturer"),
            location = enclosure_response.get("Location"),
            firmware = enclosure_response.get("FirmwareVersion"),
            num_bays = enclosure_response.get("DriveBayCount"),
            storage_controller_ids = controller_inventory.id,
            system_ids = system_response.get("Id")
        )

        if args.verbose:
            enclosure_inventory.source_data = enclosure_response

        # set relation between disk drives and enclosures
        data_drives_links = grab(enclosure_response, "Links.Drives")

        if data_drives_links is not None:

            for data_drive in data_drives_links:
                data_drive_id = ("{}:{}".format(
                    controller_inventory.id, data_drive.get("@odata.id").rstrip("/").split("/")[-1]))

                enclosure_inventory.update("physical_drive_ids", data_drive_id, True)
                plugin.inventory.append(PhysicalDrive, data_drive_id, "storage_enclosure_ids", enclosure_inventory.id)

        plugin.inventory.add(enclosure_inventory)

        plugin.inventory.append(StorageController, controller_inventory.id, "storage_enclosure_ids", enclosure_inventory.id)

        if enclosure_inventory.health_status is not None:
            enclosure_status_list.append(enclosure_inventory.health_status)

        status_text = f"{chassis_type} {enclosure_inventory.name} (Power: {power_state}) Status: {enclosure_inventory.health_status}"

        plugin.add_output_data("OK" if enclosure_inventory.health_status in ["OK", None] else enclosure_inventory.health_status, status_text)

    def condensed_status_from_list(status_list):

        status = None

        status_list = list(set(status_list))

        # remove default state
        if "OK" in status_list:
            status_list.remove("OK")

        if len(status_list) == 0:
            status = "OK"
        elif len(status_list) == 1 and status_list[0] == "WARNING":
            status = "WARNING"
        else:
            status = "CRITICAL"

        return status

    global plugin

    plugin.set_current_command("Storage")

    system_response = plugin.rf.get(system)

    storage_response = None

    storage_link = grab(system_response, "Storage/@odata.id", separator="/")
    if storage_link is not None:
        storage_response = plugin.rf.get(f"{storage_link}{plugin.rf.vendor_data.expand_string}")

    system_drives_list = list()
    drives_status_list = list()
    storage_controller_names_list = list()
    storage_controller_id_list = list()
    storage_status_list = list()
    volume_status_list = list()
    enclosure_status_list = list()

    if storage_response is not None:

        for storage_member in storage_response.get("Members"):

            if storage_member.get("@odata.context"):
                controller_response = storage_member
            else:
                controller_response = plugin.rf.get(storage_member.get("@odata.id"))

            if controller_response.get("StorageControllers"):

                # if StorageControllers is just a dict then wrap it in a list (like most vendors do it)
                if isinstance(controller_response.get("StorageControllers"), dict):
                    controller_response["StorageControllers"] = [ controller_response.get("StorageControllers") ]

                for storage_controller in controller_response.get("StorageControllers"):

                    status_data = get_status_data(storage_controller.get("Status"))

                    controller_oem_data = grab(storage_controller, f"Oem.{plugin.rf.vendor_dict_key}")

                    cache_size_in_mb = None
                    backup_power_present = False
                    model = storage_controller.get("Model")
                    if controller_oem_data is not None:
                        cache_size_in_mb = controller_oem_data.get("MemorySizeMiB")
                        if controller_oem_data.get("Type") is not None:
                            model = controller_oem_data.get("Type")
                        if controller_oem_data.get("CapacitanceStatus") is not None:
                            backup_power_present = True
                        if controller_oem_data.get("BackupUnit") is not None:
                            backup_power_present = True

                    # Cisco
                    if controller_response.get("Id") is None:
                        controller_response["Id"] = controller_response.get("@odata.id").rstrip("/").split("/")[-1]

                    if storage_controller.get("MemberId") is not None and \
                            controller_response.get("Id") != storage_controller.get("MemberId"):
                        id = "{}:{}".format(controller_response.get("Id"), storage_controller.get("MemberId"))
                    else:
                        id = controller_response.get("Id")

                    controller_inventory = StorageController(
                        id = id,
                        name  = storage_controller.get("Name"),
                        health_status = status_data.get("Health"),
                        operation_status = status_data.get("State"),
                        model = model,
                        manufacturer = storage_controller.get("Manufacturer"),
                        firmware = storage_controller.get("FirmwareVersion"),
                        serial = storage_controller.get("SerialNumber"),
                        location = grab(storage_controller, f"Oem.{plugin.rf.vendor_dict_key}.Location.Info"),
                        backup_power_present = backup_power_present,
                        cache_size_in_mb = cache_size_in_mb,
                        system_ids = system_response.get("Id")
                    )

                    if args.verbose:
                        controller_inventory.source_data = controller_response

                    if controller_inventory.name is None:
                        controller_inventory.name = "Storage controller"

                    plugin.inventory.add(controller_inventory)

                    # ignore absent controllers
                    if controller_inventory.operation_status == "Absent":
                        continue

                    if controller_inventory.health_status is not None:
                        storage_status_list.append(controller_inventory.health_status)

                    storage_controller_names_list.append(f"{controller_inventory.name} {controller_inventory.model}")
                    storage_controller_id_list.append(controller_response.get("@odata.id"))

                    if controller_inventory.location is None:
                        location_string = ""
                    else:
                        location_string = f"{controller_inventory.location} "

                    status_text = f"{controller_inventory.name} {controller_inventory.model} {location_string}(FW: {controller_inventory.firmware}) status is: {controller_inventory.health_status}"

                    plugin.add_output_data("OK" if controller_inventory.health_status in ["OK", None] else controller_inventory.health_status, status_text)

                    # Huawei
                    if grab(controller_oem_data, "CapacitanceStatus") is not None:
                        cap_model = controller_oem_data.get("CapacitanceName")
                        cap_status = get_status_data(controller_oem_data.get("CapacitanceStatus")).get("Health")
                        cap_fault_details = controller_oem_data.get("CapacitanceStatus").get("FaultDetails")

                        cap_status_text = f"Controller capacitor ({cap_model}) status: {cap_status}"

                        if cap_status != "OK" and cap_fault_details is not None:
                            cap_status_text += f" : {cap_fault_details}"

                        plugin.add_output_data("CRITICAL" if cap_status not in ["OK", "WARNING"] else cap_status, cap_status_text)
            else:
                status_data = get_status_data(controller_response.get("Status"))
                controller_inventory = StorageController(
                    id = controller_response.get("Id"),
                    name  = controller_response.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                )

                storage_controller_names_list.append(controller_inventory.name)
                storage_controller_id_list.append(controller_response.get("@odata.id"))

                if args.verbose:
                    controller_inventory.source_data = controller_response

                if controller_inventory.name is None:
                    controller_inventory.name = "Storage controller"

                plugin.inventory.add(controller_inventory)

                # ignore absent controllers
                if controller_inventory.operation_status == "Absent":
                    continue

                status_text = f"Controller {controller_inventory.name} status is: {controller_inventory.health_status}"

                plugin.add_output_data("OK" if controller_inventory.health_status in ["OK", None] else controller_inventory.health_status, status_text)

            for controller_drive in controller_response.get("Drives"):
                system_drives_list.append(controller_drive.get("@odata.id"))
                get_drive(controller_drive.get("@odata.id"))

            # get volumes
            get_volumes(controller_response.get("Volumes").get("@odata.id"))

            # get enclosures
            enclosure_list = grab(controller_response, "Links.Enclosures")

            if isinstance(enclosure_list, list):

                for enclosure_link in enclosure_list:
                    if isinstance(enclosure_link, str):
                        get_enclosures(enclosure_link)
                    else:
                        get_enclosures(enclosure_link.get("@odata.id"))

    # check SimpleStorage
    simple_storage_link = grab(system_response, "SimpleStorage/@odata.id", separator="/")
    if simple_storage_link is not None:

        simple_storage_response = plugin.rf.get(f"{simple_storage_link}{plugin.rf.vendor_data.expand_string}")

        if simple_storage_response.get("Members") is not None and len(simple_storage_response.get("Members")) > 0:

            for simple_storage_member in simple_storage_response.get("Members"):

                if simple_storage_member.get("@odata.context"):
                    simple_storage_controller_response = simple_storage_member
                else:
                    simple_storage_controller_response = plugin.rf.get(simple_storage_member.get("@odata.id"))

                # this controller has already been checked
                if simple_storage_controller_response.get("@odata.id") in storage_controller_id_list or \
                        simple_storage_controller_response.get("Id") in [x.id for x in plugin.inventory.get(StorageController)]:
                    continue

                status_data = get_status_data(simple_storage_controller_response.get("Status"))

                controller_inventory = StorageController(
                    id = simple_storage_controller_response.get("Id"),
                    name  = simple_storage_controller_response.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    model = simple_storage_controller_response.get("Description"),
                    system_ids = system_response.get("Id")
                )

                if args.verbose:
                    controller_inventory.source_data = simple_storage_controller_response

                plugin.inventory.add(controller_inventory)

                if status_data.get("State") != "Enabled":
                    continue

                if simple_storage_controller_response.get("Devices") is not None and len(simple_storage_controller_response.get("Devices")) > 0:

                    if controller_inventory.health_status is not None:
                        storage_status_list.append(controller_inventory.health_status)

                    storage_controller_names_list.append(f"{controller_inventory.name}")

                    status_text = f"{controller_inventory.name} status: {controller_inventory.health_status}"
                    plugin.add_output_data("OK" if controller_inventory.health_status in ["OK", None] else controller_inventory.health_status, status_text)

                    disk_id = 0
                    enclosure_id = 0
                    for simple_storage_device in simple_storage_controller_response.get("Devices"):

                        name = simple_storage_device.get("Name")
                        manufacturer = simple_storage_device.get("Manufacturer")
                        model = simple_storage_device.get("Model")
                        capacity = simple_storage_device.get("CapacityBytes")
                        status_data = get_status_data(simple_storage_device.get("Status"))

                        if capacity is not None:

                            disk_id += 1
                            pd_inventory = PhysicalDrive(
                                id = "{}:{}".format(controller_inventory.id,disk_id),
                                name = name,
                                health_status = status_data.get("Health"),
                                operation_status = status_data.get("State"),
                                model = model,
                                manufacturer = manufacturer,
                                size_in_byte = capacity,
                                system_ids = system_response.get("Id"),
                                storage_controller_ids = controller_inventory.id
                            )

                            plugin.inventory.add(pd_inventory)

                            plugin.inventory.append(StorageController, controller_inventory.id, "physical_drive_ids", pd_inventory.id)
                        else:

                            enclosure_id += 1

                            enclosure_inventory = StorageEnclosure(
                                id = "{}:{}".format(controller_inventory.id, enclosure_id),
                                name = name,
                                health_status = status_data.get("Health"),
                                operation_status = status_data.get("State"),
                                model = model,
                                manufacturer = system_response.get("Manufacturer"),
                                system_ids = system_response.get("Id"),
                                storage_controller_ids = controller_inventory.id
                            )

                            plugin.inventory.add(enclosure_inventory)

                            plugin.inventory.append(StorageController, controller_inventory.id, "storage_enclosure_ids", enclosure_inventory.id)

                        status_text = f"{manufacturer} {name} {model}"

                        if capacity is not None:
                            try:
                                status_text += " (size: %0.2f GiB)" % (int(capacity) / 1000 ** 3)
                            except Exception:
                                pass

                        # skip device if state is not "Enabled"
                        if status_data.get("State") != "Enabled":
                            continue

                        status = status_data.get("Health")

                        if status_data is not None:
                            drives_status_list.append(status)

                        status_text += f" status: {status}"

                        plugin.add_output_data("OK" if status in ["OK", None] else status, status_text)


    # check additional drives
    system_drives = grab(system_response, f"Oem.{plugin.rf.vendor_dict_key}.StorageViewsSummary.Drives")

    if system_drives is not None:
        for system_drive in system_drives:
            drive_url = grab(system_drive, "Link/@odata.id", separator="/")
            if drive_url not in system_drives_list:
                system_drives_list.append(drive_url)
                # create placeholder for storage controller
                controller_inventory = StorageController(id = 0)
                get_drive(drive_url)

    condensed_storage_status = condensed_status_from_list(storage_status_list)
    condensed_drive_status = condensed_status_from_list(drives_status_list)
    condensed_volume_status = condensed_status_from_list(volume_status_list)
    condensed_enclosure_status = condensed_status_from_list(enclosure_status_list)

    if len(storage_controller_names_list) == 0 and len(system_drives_list) == 0:
        plugin.add_output_data("UNKNOWN", "No storage controller and disk drive data found in system", summary = not args.detailed)
    elif args.detailed == False:
        if len(storage_controller_names_list) == 0 and len(system_drives_list) != 0:

            drive_summary_status = "All system drives are in good condition (No storage controller found)"

            plugin.add_output_data(condensed_drive_status, drive_summary_status, summary = True)

        elif len(storage_controller_names_list) != 1 and len(system_drives_list) == 0:

            storage_summary_status = "All storage controllers (%s) are in good condition (No system drives found)" % (", ".join(storage_controller_names_list))

            plugin.add_output_data(condensed_storage_status, storage_summary_status, summary = True)
        else:
            condensed_summary_status = condensed_status_from_list([condensed_storage_status, condensed_drive_status, condensed_volume_status, condensed_enclosure_status])

            if condensed_summary_status == "OK":
                summary_status = "All storage controllers (%s), volumes and disk drives are in good condition" % (", ".join(storage_controller_names_list))
            else:
                summary_status = "One or more storage components report an issue"

            plugin.add_output_data(condensed_summary_status, summary_status, summary = True)

    return