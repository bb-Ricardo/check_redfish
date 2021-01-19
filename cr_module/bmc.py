# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import Manager, NetworkPort
from cr_module.common import get_status_data, grab
from cr_module.firmware import get_firmware_info_fujitsu
from cr_module.nic import get_interface_ip_addresses, format_interface_addresses


def get_bmc_info(plugin_object):

    plugin_object.set_current_command("BMC Info")

    managers = plugin_object.rf.get_system_properties("managers")

    if managers is None or len(managers) == 0:
        plugin_object.inventory.add_issue(Manager, "No 'managers' property found in root path '/redfish/v1'")
        return

    for manager in managers:
        get_bmc_info_generic(plugin_object, manager)

    return


def get_bmc_info_generic(plugin_object, redfish_url):
    """
    Possible Info to add
    * NTP Status
    * NTP servers configured
    * BMC accounts
    * BIOS settings (maybe, varies a lot between vendors)
    """

    view_response = plugin_object.rf.get_view(f"{redfish_url}{plugin_object.rf.vendor_data.expand_string}")

    if view_response.get("error"):
        plugin_object.add_data_retrieval_error(Manager, view_response, redfish_url)
        return

    # HPE iLO 5 view
    if view_response.get("ILO"):
        manager_response = view_response.get("ILO")[0]
    else:
        manager_response = view_response

    # get model
    bmc_model = manager_response.get("Model")
    bmc_fw_version = manager_response.get("FirmwareVersion")

    if plugin_object.rf.vendor == "HPE":
        bmc_model = " ".join(bmc_fw_version.split(" ")[0:2])

    if plugin_object.rf.vendor == "Dell":
        if bmc_model == "13G Monolithic":
            bmc_model = "iDRAC 8"
        if bmc_model in ["14G Monolithic", "15G Monolithic"]:
            bmc_model = "iDRAC 9"

    # some Cisco Systems have a second manager with no attributes which needs to be skipped
    if plugin_object.rf.vendor == "Cisco":
        if manager_response.get("Status") is None:
            return

    status_text = f"{bmc_model} (Firmware: {bmc_fw_version})"

    # get status data
    status_data = get_status_data(manager_response.get("Status"))
    manager_inventory = Manager(
        id=manager_response.get("Id"),
        type=manager_response.get("ManagerType"),
        name=manager_response.get("Name"),
        health_status=status_data.get("Health"),
        operation_status=status_data.get("State"),
        model=bmc_model,
        firmware=bmc_fw_version
    )

    if plugin_object.cli_args.verbose:
        manager_inventory.source_data = manager_response

    # add relations
    manager_inventory.add_relation(plugin_object.rf.get_system_properties(), manager_response.get("Links"))

    plugin_object.inventory.add(manager_inventory)

    # workaround for older ILO versions
    if manager_inventory.health_status is not None:
        bmc_status = manager_inventory.health_status
    elif manager_inventory.operation_status == "Enabled":
        bmc_status = "OK"
    else:
        bmc_status = "UNKNOWN"

    plugin_object.add_output_data("CRITICAL" if bmc_status not in ["OK", "WARNING"] else bmc_status, status_text,
                                  location=f"Manager {manager_inventory.id}")

    # BMC Network interfaces
    manager_nic_response = None
    manager_nic_member = None

    if plugin_object.rf.vendor == "HPE" and view_response.get("ILOInterfaces") is not None:
        manager_nic_response = {"Members": view_response.get("ILOInterfaces")}
    else:
        manager_nics_link = grab(manager_response, "EthernetInterfaces/@odata.id", separator="/")
        if manager_nics_link is not None:
            redfish_url = f"{manager_nics_link}{plugin_object.rf.vendor_data.expand_string}"
            manager_nic_response = plugin_object.rf.get(redfish_url)

            if manager_nic_response.get("error"):
                plugin_object.add_data_retrieval_error(NetworkPort, manager_nic_response, redfish_url)

    if manager_nic_response is not None:

        if manager_nic_response.get("Members") is None or len(manager_nic_response.get("Members")) == 0:

            status_text = f"{status_text} but no information about the BMC network interfaces found"

            plugin_object.inventory.add_issue(NetworkPort, "No information about the BMC network interfaces found")
        else:

            # if args.detailed is False:
            status_text = f"{status_text} and all nics are in 'OK' state."

            for manager_nic_member in manager_nic_response.get("Members"):

                if manager_nic_member.get("@odata.context"):
                    manager_nic = manager_nic_member
                else:
                    manager_nic = plugin_object.rf.get(manager_nic_member.get("@odata.id"))

                    if manager_nic.get("error"):
                        plugin_object.add_data_retrieval_error(NetworkPort, manager_nic,
                                                               manager_nic_member.get("@odata.id"))
                        continue

                status_data = get_status_data(manager_nic.get("Status"))

                if plugin_object.rf.vendor == "Dell":
                    interface_id = manager_nic.get("Id")
                else:
                    interface_id = "{}:{}".format(manager_inventory.id, manager_nic.get("Id"))

                vlan_id = grab(manager_nic, "VLAN.VLANId")
                if vlan_id is None:
                    vlan_id = grab(manager_nic, "VLANId")

                vlan_enabled = grab(manager_nic, "VLAN.VLANEnable")
                if vlan_enabled is None:
                    vlan_enabled = grab(manager_nic, "VLANEnable")

                network_inventory = NetworkPort(
                    id=interface_id,
                    name=manager_nic.get("Name"),
                    health_status=status_data.get("Health"),
                    operation_status=status_data.get("State"),
                    current_speed=manager_nic.get("SpeedMbps"),
                    autoneg=manager_nic.get("AutoNeg"),
                    full_duplex=manager_nic.get("FullDuplex"),
                    hostname=manager_nic.get("HostName"),
                    addresses=format_interface_addresses(manager_nic.get("PermanentMACAddress")),
                    manager_ids=manager_inventory.id,
                    system_ids=manager_inventory.system_ids,
                    chassi_ids=manager_inventory.chassi_ids,
                    ipv4_addresses=get_interface_ip_addresses(manager_nic, "IPv4Addresses"),
                    ipv6_addresses=get_interface_ip_addresses(manager_nic, "IPv6Addresses"),
                    link_type="Ethernet",
                    link_status=f"{manager_nic.get('LinkStatus') or ''}".replace("Link", ""),
                    vlan_id=vlan_id,
                    vlan_enabled=vlan_enabled,
                )

                if plugin_object.cli_args.verbose:
                    network_inventory.source_data = manager_nic

                plugin_object.inventory.add(network_inventory)

                # if we are connected wie via interface IP address then we can assume the link is up
                if network_inventory.link_status is None:
                    for address in network_inventory.ipv4_addresses + network_inventory.ipv6_addresses:
                        if address in plugin_object.cli_args.host:
                            network_inventory.link_status = "Up"

                if plugin_object.rf.vendor == "Cisco" and manager_nic.get("InterfaceEnabled") is True:
                    network_inventory.operation_status = "Enabled"

                # Huawei is completely missing any status information
                if plugin_object.rf.vendor == "Huawei" and network_inventory.operation_status is None:
                    network_inventory.operation_status = "Enabled"

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
                    if nic_status == "OK" and duplex == "half" and network_inventory.current_speed is not None:
                        nic_status = "WARNING"
                        duplex += f" ({nic_status})"

                if network_inventory.autoneg is not None:
                    autoneg = "on" if network_inventory.autoneg is True else "off"

                nic_status_text = f"NIC {network_inventory.id} '{host_name}' (IPs: {ip_addresses_string}) "
                nic_status_text += f"(speed: {network_inventory.current_speed}, " \
                                   f"autoneg: {autoneg}, duplex: {duplex}) status: {nic_status}"

                plugin_object.add_output_data("CRITICAL" if nic_status not in ["OK", "WARNING"] else nic_status,
                                              nic_status_text, location=f"Manager {manager_inventory.id}")

    # get vendor information
    vendor_data = grab(manager_response, f"Oem.{plugin_object.rf.vendor_dict_key}")

    # get license information
    bmc_licenses = list()
    if plugin_object.rf.vendor == "HPE":

        ilo_license_string = grab(vendor_data, "License.LicenseString")
        ilo_license_key = grab(vendor_data, "License.LicenseKey")

        bmc_licenses.append(f"{ilo_license_string} ({ilo_license_key})")

    elif plugin_object.rf.vendor == "Lenovo":

        fod_link = grab(vendor_data, "FoD/@odata.id", separator="/")

        if fod_link is not None:
            fod_url = f"{fod_link}/Keys{plugin_object.rf.vendor_data.expand_string}"
            fod_data = plugin_object.rf.get(fod_url)

            if fod_data.get("error"):
                plugin_object.add_data_retrieval_error(Manager, fod_data, fod_url)

            for fod_member in fod_data.get("Members", list()):
                if manager_nic_member is not None and manager_nic_member.get("@odata.context"):
                    licenses_data = fod_member
                else:
                    licenses_data = plugin_object.rf.get(fod_member.get("@odata.id"))

                lic_status = licenses_data.get("Status")  # valid
                lic_expire_date = licenses_data.get("Expires")  # NO CONSTRAINTS
                lic_description = licenses_data.get("Description")

                license_string = f"{lic_description}"
                if lic_expire_date != "NO CONSTRAINTS":
                    license_string += " (expires: {lic_expire_date}"

                license_string += f" Status: {lic_status}"
                bmc_licenses.append(license_string)

    elif plugin_object.rf.vendor == "Fujitsu":

        # get configuration
        irmc_configuration_link = grab(vendor_data, f"iRMCConfiguration/@odata.id", separator="/")

        irmc_configuration = None
        if irmc_configuration_link is not None:
            irmc_configuration = plugin_object.rf.get(irmc_configuration_link)

            if irmc_configuration.get("error"):
                plugin_object.add_data_retrieval_error(Manager, irmc_configuration, irmc_configuration_link)

        license_information = None
        license_information_link = grab(irmc_configuration, f"Licenses/@odata.id", separator="/")
        if license_information_link is not None:
            license_information = plugin_object.rf.get(license_information_link)

            if license_information.get("error"):
                plugin_object.add_data_retrieval_error(Manager, license_information, license_information_link)

        if license_information is not None and license_information.get("Keys@odata.count") > 0:
            for bmc_license in license_information.get("Keys"):
                bmc_licenses.append("%s (%s)" % (bmc_license.get("Name"), bmc_license.get("Type")))

    elif plugin_object.rf.vendor == "Huawei":

        ibmc_license_link = vendor_data.get("LicenseService")

        if ibmc_license_link is not None and len(ibmc_license_link) > 0:
            ibmc_lic = plugin_object.rf.get(ibmc_license_link.get("@odata.id"))

            if ibmc_lic.get("error"):
                plugin_object.add_data_retrieval_error(Manager, ibmc_lic, ibmc_license_link.get("@odata.id"))

            bmc_licenses.append("%s (%s)" % (ibmc_lic.get("InstalledStatus"), ibmc_lic.get("LicenseClass")))

    manager_inventory.licenses = bmc_licenses

    for bmc_license in bmc_licenses:
        plugin_object.add_output_data("OK", f"License: {bmc_license}", location=f"Manager {manager_inventory.id}")

    # HP ILO specific stuff
    if plugin_object.rf.vendor == "HPE":

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

            plugin_object.add_output_data("CRITICAL" if self_test_status not in ["OK", "WARNING"] else self_test_status,
                                          self_test_status_text, location=f"Manager {manager_inventory.id}")

    # Lenovo specific stuff
    if plugin_object.rf.vendor == "Lenovo":
        redfish_chassi_url = grab(manager_response, "Links/ManagerForChassis/0/@odata.id", separator="/")

        chassi_response = None
        if redfish_chassi_url is not None:
            chassi_response = plugin_object.rf.get(redfish_chassi_url)

            if chassi_response.get("error"):
                plugin_object.add_data_retrieval_error(Manager, chassi_response, redfish_chassi_url)

        located_data = grab(chassi_response, f"Oem.{plugin_object.rf.vendor_dict_key}.LocatedIn")

        if located_data is not None:
            descriptive_name = located_data.get("DescriptiveName")
            rack = located_data.get("Rack")

            system_name_string = f"System name: {descriptive_name} ({rack})"
            if plugin_object.cli_args.detailed:
                plugin_object.add_output_data("OK", system_name_string, location=f"Manager {manager_inventory.id}")
            else:
                status_text += f" {system_name_string}"

    # get running firmware information from Fujitsu server
    if plugin_object.rf.vendor == "Fujitsu":

        for bmc_firmware in get_firmware_info_fujitsu(plugin_object, redfish_url, True):
            plugin_object.add_output_data("OK",
                                          "Firmware: %s: %s" % (bmc_firmware.get("name"), bmc_firmware.get("version")),
                                          location=f"Manager {manager_inventory.id}")

    # get Huawei Server location data
    if plugin_object.rf.vendor == "Huawei":

        ibmc_location = vendor_data.get("DeviceLocation")
        if ibmc_location is not None and len(ibmc_location) > 0:

            location_string = f"Location: {ibmc_location}"
            if plugin_object.cli_args.detailed:
                plugin_object.add_output_data("OK", location_string, location=f"Manager {manager_inventory.id}")
            else:
                status_text += f" {location_string}"

    plugin_object.add_output_data("CRITICAL" if bmc_status not in ["OK", "WARNING"] else bmc_status, status_text,
                                  summary=True, location=f"Manager {manager_inventory.id}")

    return

# EOF
