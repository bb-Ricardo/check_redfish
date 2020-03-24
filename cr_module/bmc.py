
def get_bmc_info():

    global plugin

    plugin.set_current_command("BMC Info")

    managers = plugin.rf.connection.system_properties.get("managers")

    if managers is None or len(managers) == 0:
        plugin.add_output_data("UNKNOWN", "No 'managers' property found in root path '/redfish/v1'")
        return

    for manager in managers:

        get_bmc_info_generic(manager)

    return

def get_bmc_info_generic(redfish_url):

    global plugin

    """
    Possible Infos to add
    * NTP Status
    * NTP servers configured
    * BMC accounts
    * BIOS settings (maybe, varies a lot between vendors)
    """

    view_response = plugin.rf.get_view(f"{redfish_url}{plugin.rf.vendor_data.expand_string}")

    # HPE iLO 5 view
    if view_response.get("ILO"):
        manager_response = view_response.get("ILO")[0]
    else:
        manager_response = view_response

    # get model
    bmc_model = manager_response.get("Model")
    bmc_fw_version = manager_response.get("FirmwareVersion")

    if plugin.rf.vendor == "HPE":
        bmc_model = " ".join(bmc_fw_version.split(" ")[0:2])

    if plugin.rf.vendor == "Dell":
        if bmc_model == "13G Monolithic":
            bmc_model = "iDRAC 8"
        if bmc_model in [ "14G Monolithic", "15G Monolithic" ]:
            bmc_model = "iDRAC 9"

    status_text = f"{bmc_model} (Firmware: {bmc_fw_version})"

    # get status data
    status_data = get_status_data(manager_response.get("Status"))
    manager_inventory = Manager(
        id = manager_response.get("Id"),
        type = manager_response.get("ManagerType"),
        name = manager_response.get("Name"),
        health_status = status_data.get("Health"),
        operation_status = status_data.get("State"),
        model = bmc_model,
        firmware = bmc_fw_version
    )

    if args.verbose:
        manager_inventory.source_data = manager_response

    # add relations
    manager_inventory.add_relation(plugin.rf.connection.system_properties, manager_response.get("Links"))

    plugin.inventory.add(manager_inventory)

    # workaround for older ILO versions
    if manager_inventory.health_status is not None:
        bmc_status = manager_inventory.health_status
    elif manager_inventory.operation_status == "Enabled":
        bmc_status = "OK"
    else:
        bmc_status = "UNKNOWN"

    plugin.add_output_data("CRITICAL" if bmc_status not in ["OK", "WARNING"] else bmc_status, status_text)

    # BMC Network interfaces
    manager_nic_response = None

    if plugin.rf.vendor == "HPE" and view_response.get("ILOInterfaces") is not None:
        manager_nic_response = { "Members": view_response.get("ILOInterfaces") }
    else:
        manager_nics_link = grab(manager_response, "EthernetInterfaces/@odata.id", separator="/")
        if manager_nics_link is not None:
            manager_nic_response = plugin.rf.get(f"{manager_nics_link}{plugin.rf.vendor_data.expand_string}")

    if manager_nic_response is not None:

        if manager_nic_response.get("Members") is None or len(manager_nic_response.get("Members")) == 0:

            status_text = f"{status_text} but no informations about the BMC network interfaces found"
        else:

            #if args.detailed is False:
            status_text = f"{status_text} and all nics are in 'OK' state."

            for manager_nic_member in manager_nic_response.get("Members"):

                if manager_nic_member.get("@odata.context"):
                    manager_nic = manager_nic_member
                else:
                    manager_nic = plugin.rf.get(manager_nic_member.get("@odata.id"))

                status_data = get_status_data(manager_nic.get("Status"))

                def get_ip_adresses(type):

                    list_of_addresses = list()

                    ip_addresses = grab(manager_nic, type)

                    # Cisco
                    if isinstance(ip_addresses, dict):
                        if ip_addresses.get("Address") is not None:
                            list_of_addresses.append(ip_addresses.get("Address"))

                    if isinstance(ip_addresses, list):
                        for ip_address in ip_addresses:
                            if ip_address.get("Address") is not None:
                                list_of_addresses.append(ip_address.get("Address"))

                    list_of_addresses = list(set(list_of_addresses))

                    return [address for address in list_of_addresses if address not in ['::', '0.0.0.0']]

                # get and sanitize MAC address
                mac_address = manager_nic.get("PermanentMACAddress")
                if mac_address is not None:
                    mac_address = mac_address.upper()

                if plugin.rf.vendor == "Dell":
                    id = manager_nic.get("Id")
                else:
                    id = "{}:{}".format(manager_inventory.id,manager_nic.get("Id"))

                network_inventory = NIC(
                    id = id,
                    name = manager_nic.get("Name"),
                    health_status = status_data.get("Health"),
                    operation_status = status_data.get("State"),
                    current_speed = manager_nic.get("SpeedMbps"),
                    autoneg = manager_nic.get("AutoNeg"),
                    full_duplex = manager_nic.get("FullDuplex"),
                    hostname = manager_nic.get("HostName"),
                    mac_address = mac_address,
                    manager_ids = manager_inventory.id,
                    system_ids = manager_inventory.system_ids,
                    chassi_ids = manager_inventory.chassi_ids,
                    ipv4_addresses = get_ip_adresses("IPv4Addresses"),
                    ipv6_addresses = get_ip_adresses("IPv6Addresses"),
                    link_type = "Ethernet",
                    link_status = manager_nic.get("LinkStatus")
                )

                if args.verbose:
                    network_inventory.source_data = manager_nic

                plugin.inventory.add(network_inventory)

                if plugin.rf.vendor == "Cisco" and manager_nic.get("InterfaceEnabled") is True:
                    network_inventory.operation_status = "Enabled"

                # Huawei is completely missing any status information
                if plugin.rf.vendor == "Huawei" and network_inventory.operation_status is None:
                    network_inventory.operation_status = "Enabled"

                nic_status = None
                if network_inventory.health_status:
                    nic_status = network_inventory.health_status
                elif network_inventory.operation_status == "Enabled":
                    nic_status = "OK"
                else:
                    nic_status = "UNKNOWN"

                if network_inventory.operation_status in ["Disabled", None]:
                    continue

                host_name = network_inventory.hostname or "no hostname set"

                ip_addresses_string = None
                ip_addresses = [*network_inventory.ipv4_addresses, *network_inventory.ipv6_addresses]
                if len(ip_addresses) > 0:
                    ip_addresses_string = "/".join(ip_addresses)

                duplex = autoneg = None
                if network_inventory.full_duplex is not None:
                    duplex = "full" if network_inventory.full_duplex is True else "half"
                if network_inventory.autoneg is not None:
                    autoneg = "on" if network_inventory.autoneg is True else "off"

                nic_status_text  = f"NIC {network_inventory.id} '{host_name}' (IPs: {ip_addresses_string}) "
                nic_status_text += f"(speed: {network_inventory.current_speed}, autoneg: {autoneg}, duplex: {duplex}) status: {nic_status}"

                plugin.add_output_data("CRITICAL" if nic_status not in ["OK", "WARNING"] else nic_status, nic_status_text)

    # get license information
    # get vendor informations
    vendor_data = grab(manager_response, f"Oem.{plugin.rf.vendor_dict_key}")

    bmc_licenses = list()
    if plugin.rf.vendor == "HPE":

        ilo_license_string = grab(vendor_data, "License.LicenseString")
        ilo_license_key = grab(vendor_data, "License.LicenseKey")

        bmc_licenses.append(f"{ilo_license_string} ({ilo_license_key})")

    elif plugin.rf.vendor == "Lenovo":

        fod_link = grab(vendor_data, "FoD/@odata.id", separator="/")

        if fod_link is not None:
            fod_data = plugin.rf.get(f"{fod_link}/Keys{plugin.rf.vendor_data.expand_string}")

            if fod_data.get("Members") is None or len(fod_data.get("Members")) > 0:

                for fod_member in fod_data.get("Members"):
                    if manager_nic_member.get("@odata.context"):
                        licenses_data = fod_member
                    else:
                        licenses_data = plugin.rf.get(fod_member.get("@odata.id"))

                    lic_status = licenses_data.get("Status") # valid
                    lic_expire_date = licenses_data.get("Expires") # NO CONSTRAINTS
                    lic_description = licenses_data.get("Description")

                    license_string = f"{lic_description}"
                    if lic_expire_date != "NO CONSTRAINTS":
                        license_string += " (expires: {lic_expire_date}"

                    license_string += f" Status: {lic_status}"
                    bmc_licenses.append(license_string)

    elif plugin.rf.vendor == "Fujitsu":

        # get configuration
        iRMCConfiguration_link = grab(vendor_data, f"iRMCConfiguration/@odata.id", separator="/")

        iRMCConfiguration = None
        if iRMCConfiguration_link is not None:
            iRMCConfiguration = plugin.rf.get(iRMCConfiguration_link)

        license_informations = None
        license_informations_link = grab(iRMCConfiguration, f"Licenses/@odata.id", separator="/")
        if license_informations_link is not None:
            license_informations = plugin.rf.get(license_informations_link)

        if license_informations is not None and license_informations.get("Keys@odata.count") > 0:
            for bmc_license in license_informations.get("Keys"):
                bmc_licenses.append("%s (%s)" % ( bmc_license.get("Name"), bmc_license.get("Type")))

    elif plugin.rf.vendor == "Huawei":

        ibmc_license_link = vendor_data.get("LicenseService")

        if ibmc_license_link is not None and len(ibmc_license_link) > 0:
            ibmc_lic = plugin.rf.get(ibmc_license_link.get("@odata.id"))

            bmc_licenses.append("%s (%s)" % ( ibmc_lic.get("InstalledStatus"), ibmc_lic.get("LicenseClass")))

    manager_inventory.licenses = bmc_licenses

    for bmc_license in bmc_licenses:
        plugin.add_output_data("OK", f"License: {bmc_license}")

    # HP ILO specific stuff
    if plugin.rf.vendor == "HPE":

        # iLO Self Test
        for self_test in vendor_data.get("iLOSelfTestResults"):

            self_test_status = self_test.get("Status")

            if self_test_status in ["Informational", None]:
                continue

            self_test_status = self_test_status.upper()

            self_test_name = self_test.get("SelfTestName")
            self_test_notes = self_test.get("Notes")

            if self_test_notes is not None and len(self_test_notes) != 0:
                self_test_notes = self_test_notes.strip()
                self_test_status_text = f"SelfTest {self_test_name} ({self_test_notes}) status: {self_test_status}"
            else:
                self_test_status_text = f"SelfTest {self_test_name} status: {self_test_status}"

            plugin.add_output_data("CRITICAL" if self_test_status not in ["OK", "WARNING"] else self_test_status, self_test_status_text)

    # Lenovo specific stuff
    if plugin.rf.vendor == "Lenovo":
        redfish_chassi_url = grab(manager_response, "Links/ManagerForChassis/0/@odata.id", separator="/")

        chassi_response = None
        if redfish_chassi_url is not None:
            chassi_response = plugin.rf.get(redfish_chassi_url)

        located_data = grab(chassi_response, f"Oem.{plugin.rf.vendor_dict_key}.LocatedIn")

        if located_data is not None:
            descriptive_name = located_data.get("DescriptiveName")
            rack = located_data.get("Rack")

            system_name_string = f"System name: {descriptive_name} ({rack})"
            if args.detailed:
                plugin.add_output_data("OK", system_name_string)
            else:
                status_text += f" {system_name_string}"

    # get running firmware informations from Fujitsu server
    if plugin.rf.vendor == "Fujitsu":

        for bmc_firmware in get_firmware_info_fujitsu(redfish_url,True):
            plugin.add_output_data("OK", "Firmware: %s: %s" % (bmc_firmware.get("name"), bmc_firmware.get("version")))

    # get Huawei Server location data
    if plugin.rf.vendor == "Huawei":

        ibmc_location = vendor_data.get("DeviceLocation")
        if ibmc_location is not None and len(ibmc_location) > 0:

            location_string = f"Location: {ibmc_location}"
            if args.detailed:
                plugin.add_output_data("OK", location_string)
            else:
                status_text += f" {location_string}"


    plugin.add_output_data("CRITICAL" if bmc_status not in ["OK", "WARNING"] else bmc_status, status_text, summary = True)

    return
