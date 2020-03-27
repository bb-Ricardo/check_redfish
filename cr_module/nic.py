# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import NIC
from cr_module.common import get_status_data, grab


def get_system_nics_fujitsu(plugin_object, redfish_url):

    plugin_object.set_current_command("NICs")

    system_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/NetworkInterfaces{plugin_object.rf.vendor_data.expand_string}"

    nics_response = plugin_object.rf.get(redfish_url)

    num_nic_ports = 0

    if nics_response.get("Members") and len(nics_response.get("Members")) > 0:

        for nic in nics_response.get("Members"):

            if nic.get("Id") is not None:
                nic_member = nic
            else:
                nic_member = plugin_object.rf.get(nic.get("@odata.id"))

            # network functions
            if nic_member.get("NetworkDeviceFunctions") is not None:
                network_functions_link = grab(nic_member, "NetworkDeviceFunctions/@odata.id", separator="/")
            else:
                network_functions_link = grab(nic_member, "Links/NetworkAdapter/@odata.id", separator="/")

            network_functions = plugin_object.rf.get(
                f"{network_functions_link}{plugin_object.rf.vendor_data.expand_string}")

            # network ports
            network_ports = plugin_object.rf.get("%s%s" %
                                                 (grab(nic_member, "NetworkPorts/@odata.id", separator="/"),
                                                  plugin_object.rf.vendor_data.expand_string))

            for network_function in network_functions.get("Members"):

                if network_function.get("Id") is not None:
                    network_function_member = network_function
                else:
                    network_function_member = plugin_object.rf.get(network_function.get("@odata.id"))

                # get port
                network_port_link = network_function_member.get("PhysicalPortAssignment")
                if network_port_link is None:
                    network_port_link = grab(network_function_member, "Links.PhysicalPortAssignment")

                network_port_data = None
                for network_port in network_ports.get("Members"):
                    if network_port.get("@odata.id") == network_port_link.get("@odata.id"):

                        if network_port.get("Id"):
                            network_port_data = network_port
                        else:
                            network_port_data = plugin_object.rf.get(network_port.get("@odata.id"))
                        break

                num_nic_ports += 1

                # get health status
                status_data = get_status_data(network_port_data.get("Status"))

                # get and sanitize MAC address
                mac_address = grab(network_function_member, "Ethernet.PermanentMACAddress")
                if mac_address is not None:
                    mac_address = mac_address.upper()

                # get Link speed
                current_speed = \
                    network_port_data.get("CurrentLinkSpeedMbps") or \
                    grab(network_port_data, "SupportedLinkCapabilities.0.LinkSpeedMbps")

                # get port number
                if network_port_data.get("PhysicalPortNumber"):
                    nic_port_name = "Port " + network_port_data.get("PhysicalPortNumber")
                else:
                    nic_port_name = network_port_data.get("Name")

                # get IP addresses
                ipv4_addresses = grab(network_function_member, f"Oem.{plugin_object.rf.vendor_dict_key}.IPv4Addresses")
                if ipv4_addresses is not None and len(ipv4_addresses) == 0:
                    ipv4_addresses = None

                ipv6_addresses = grab(network_function_member, f"Oem.{plugin_object.rf.vendor_dict_key}.IPv6Addresses")
                if ipv6_addresses is not None and len(ipv6_addresses) == 0:
                    ipv6_addresses = None

                nic_inventory = NIC(
                    id=network_function_member.get("Id"),
                    name=network_function_member.get("Name"),
                    port_name=nic_port_name,
                    health_status=status_data.get("Health"),
                    operation_status=status_data.get("State"),
                    mac_address=mac_address,
                    link_type=network_port_data.get("ActiveLinkTechnology"),
                    current_speed=current_speed,
                    capable_speed=grab(network_port_data, "SupportedLinkCapabilities.0.CapableLinkSpeedMbps.0"),
                    link_status=network_port_data.get("LinkStatus"),
                    ipv4_addresses=ipv4_addresses,
                    ipv6_addresses=ipv6_addresses,
                    system_ids=system_id
                )

                if plugin_object.cli_args.verbose:
                    nic_inventory.source_data = {"nic_functions": network_function_member,
                                                 "nic_port": network_port_data}

                # add relations
                nic_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                           network_function_member.get("Links"))
                nic_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                           network_function_member.get("RelatedItem"))
                nic_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                           network_port_data.get("Links"))
                nic_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                           network_port_data.get("RelatedItem"))

                plugin_object.inventory.add(nic_inventory)

                # ignore interface if state is not Enabled
                if nic_inventory.operation_status != "Enabled":
                    continue

                status_text = f"NIC {nic_inventory.id} ({nic_inventory.name}) {nic_inventory.port_name} "
                status_text += f"(Type: {nic_inventory.link_type}, " \
                               f"Speed: {nic_inventory.current_speed}/{nic_inventory.capable_speed}, " \
                               f"MAC: {nic_inventory.mac_address}) "
                status_text += f"status: {nic_inventory.link_status}"
                plugin_object.add_output_data(
                    "CRITICAL" if nic_inventory.health_status not in ["OK", "WARNING"] else nic_inventory.health_status,
                    status_text)

    if num_nic_ports == 0:
        plugin_object.add_output_data("UNKNOWN", f"No network interface data returned for API URL '{redfish_url}'")

    plugin_object.add_output_data("OK", f"All network interfaces ({num_nic_ports}) are in good condition", summary=True)

    return


def get_single_system_nics(plugin_object, redfish_url):

    plugin_object.set_current_command("NICs")

    system_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/EthernetInterfaces/{plugin_object.rf.vendor_data.expand_string}"

    nics_response = plugin_object.rf.get_view(redfish_url)
    data_members = nics_response.get("EthernetInterfaces") or nics_response.get("Members")

    default_text = ""
    nic_num = 0
    if data_members:

        for nic in data_members:

            if nic.get("@odata.context"):
                nic_response = nic
            else:
                nic_response = plugin_object.rf.get(nic.get("@odata.id"))

            if nic_response.get("Id"):

                nic_num += 1

                # get health status
                status_data = get_status_data(nic_response.get("Status"))

                # get and sanitize MAC address
                mac_address = nic_response.get("PermanentMACAddress")
                if mac_address is not None:
                    mac_address = mac_address.upper()

                nic_inventory = NIC(
                    id=nic_response.get("Id"),
                    name=nic_response.get("Name"),
                    health_status=status_data.get("Health"),
                    operation_status=status_data.get("State"),
                    link_status=nic_response.get("LinkStatus"),
                    mac_address=mac_address,
                    current_speed=nic_response.get("SpeedMbps"),
                    system_ids=system_id
                )

                if plugin_object.cli_args.verbose:
                    nic_inventory.source_data = nic_response

                # add relations
                nic_inventory.add_relation(plugin_object.rf.get_system_properties(), nic_response.get("Links"))
                nic_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                           nic_response.get("RelatedItem"))

                plugin_object.inventory.add(nic_inventory)

                nic_status_string = nic_inventory.health_status
                if nic_status_string is None:
                    nic_status_string = "Undefined"

                status_text = f"NIC {nic_inventory.id} status is: {nic_status_string}"

                plugin_status = nic_inventory.health_status
                if plugin_status is None:
                    plugin_status = "OK"

                if nic_inventory.link_status is not None and nic_inventory.link_status != "NoLink":
                    status_text += f" and link status is '{nic_inventory.link_status}'"

                plugin_object.add_output_data("CRITICAL" if plugin_status not in ["OK", "WARNING"] else plugin_status,
                                              status_text)

            else:
                plugin_object.add_output_data("UNKNOWN",
                                              "No network interface data returned for API URL '%s'" % nic.get(
                                                  "@odata.id"))

        default_text = f"All network interfaces ({nic_num}) are in good condition"
    else:
        plugin_object.add_output_data("UNKNOWN", f"No network interface data returned for API URL '{redfish_url}'")

    plugin_object.add_output_data("OK", default_text, summary=True)

    return
