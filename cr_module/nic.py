# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import NetworkAdapter, NetworkPort
from cr_module.common import get_status_data, grab


def get_network_interfaces(plugin_object):

    systems = plugin_object.rf.get_system_properties("systems") or list()

    if len(systems) == 0:
        plugin_object.inventory.add_issue(NetworkAdapter, "No 'systems' property found in root path '/redfish/v1'")
        return

    for system in systems:
        get_system_nics(plugin_object, system)

    return


def get_interface_ip_addresses(interface_data, protocol_type):
    list_of_addresses = list()

    ip_addresses = grab(interface_data, protocol_type)

    # Cisco
    if isinstance(ip_addresses, dict):
        if ip_addresses.get("Address") is not None:
            list_of_addresses.append(ip_addresses.get("Address"))

    if isinstance(ip_addresses, list):
        for ip_address in ip_addresses:
            if ip_address.get("Address") is not None:
                list_of_addresses.append(ip_address.get("Address"))

    list_of_addresses = list(set(list_of_addresses))

    return [address for address in list_of_addresses if address not in ['', '::', '0.0.0.0']]


def format_interface_addresses(addresses):

    output_list = list()

    if addresses is None:
        return output_list

    if isinstance(addresses, list):
        input_list = addresses
    else:
        input_list = [addresses]

    for address in input_list:

        address = address.upper()

        # add colons to interface address
        if ":" not in address:
            address = ':'.join(address[i:i+2] for i in range(0,len(address),2))

        if address == "00:00:00:00:00:00":
            continue

        output_list.append(address)

    return output_list


def get_system_nics(plugin_object, redfish_url):

    def get_network_port(port_data=None, network_function_id=None, return_data=False):

        # could be
        #  * a string
        #  * a dict with just the link
        #  * a dict with full data
        port_response = None
        redfish_path = None
        if isinstance(port_data, dict):

            if port_data.get("Id") is not None:
                port_response = port_data
            else:
                redfish_path = port_data.get("@odata.id")

        elif isinstance(port_data, str):
            redfish_path = port_data

        # query data
        if port_response is None and redfish_path is not None:
            port_response = plugin_object.rf.get_view(f"{redfish_path}{plugin_object.rf.vendor_data.expand_string}")

            if port_response.get("error"):
                plugin_object.add_data_retrieval_error(NetworkPort, port_response, redfish_path)
                return NetworkPort()

        if port_response is None:
            return NetworkPort()

        # get health status
        status_data = get_status_data(port_response.get("Status"))

        # get Link speed
        current_speed = \
            port_response.get("CurrentLinkSpeedMbps") or \
            grab(port_response, "SupportedLinkCapabilities.0.LinkSpeedMbps") or \
            grab(port_response, "SupportedLinkCapabilities.LinkSpeedMbps")

        if isinstance(current_speed, str):
            current_speed = current_speed.replace("Gbps", "000")

        if str(current_speed) == "-":
            current_speed = None

        # get port number
        if port_response.get("PhysicalPortNumber"):
            nic_port_name = "Port " + port_response.get("PhysicalPortNumber")
        else:
            nic_port_name = port_response.get("Name")

        if plugin_object.rf.vendor == "Cisco" and network_function_id is not None:
            port_id = f"{network_function_id}.{port_response.get('Id')}"
        else:
            port_id = port_response.get('Id')

        if plugin_object.rf.vendor != "Dell":
            port_id = f"{adapter_id}.{port_id}"

        # check if port has already be added
        if port_id in [p.id for p in plugin_object.inventory.get(NetworkPort)]:
            print(f"ALREADY in INVENTORY: {port_id}")
            return

        network_port_inventory = NetworkPort(
            id=port_id,
            name=port_response.get("Name"),
            port_name=nic_port_name,
            health_status=status_data.get("Health"),
            operation_status=status_data.get("State"),
            addresses=format_interface_addresses(grab(port_response, "AssociatedNetworkAddresses")),
            link_type=port_response.get("ActiveLinkTechnology"),
            autoneg=grab(port_response, "SupportedLinkCapabilities.0.AutoSpeedNegotiation"),
            current_speed=current_speed,
            capable_speed=grab(port_response, "SupportedLinkCapabilities.0.CapableLinkSpeedMbps.0"),
            link_status=f"{port_response.get('LinkStatus') or ''}".replace("Link", ""),
            system_ids=system_id
        )

        network_port_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                            port_response.get("Links"))
        network_port_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                            port_response.get("RelatedItem"))

        plugin_object.inventory.add(network_port_inventory)

        if plugin_object.cli_args.verbose:
            network_port_inventory.source_data = {"port": port_response}

        if return_data is True:
            return network_port_inventory

        return

    def get_network_function(function_data=None):

        # could be
        #  * a string
        #  * a dict with just the link
        #  * a dict with full data
        function_response = None
        redfish_path = None
        if isinstance(function_data, dict):

            if function_data.get("Id") is not None:
                function_response = function_data
            else:
                redfish_path = function_data.get("@odata.id")
        elif isinstance(function_data, str):
            redfish_path = function_data

        # query data
        if function_response is None and redfish_path is not None:
            function_response = plugin_object.rf.get_view(f"{redfish_path}{plugin_object.rf.vendor_data.expand_string}")

            if function_response.get("error"):
                plugin_object.add_data_retrieval_error(NetworkPort, function_response, redfish_path)
                return

        port_inventory = None
        if function_response is not None:
            physical_port_path = grab(function_response, "Links.PhysicalPortAssignment") or \
                 grab(function_response, "PhysicalPortAssignment")

            if physical_port_path is None:
                return

            network_function_id = function_response.get("Id")

            port_inventory = get_network_port(physical_port_path, network_function_id, True)

            if plugin_object.cli_args.verbose:
                source_data = getattr(port_inventory, "source_data")
                source_data["function"] = function_response

                port_inventory.update("source_data", source_data)

            port_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                        function_response.get("Links"))
            port_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                        function_response.get("RelatedItem"))

            # get health status
            status_data = get_status_data(function_response.get("Status"))

            if port_inventory.health_status is None:
                port_inventory.health_status = status_data.get("Health")

            if port_inventory.operation_status is None:
                port_inventory.operation_status = status_data.get("State")

            # get and sanitize MAC and WWPN addresses
            port_inventory.update("addresses",
                                  format_interface_addresses(grab(function_response, "Ethernet.PermanentMACAddress")) +
                                  format_interface_addresses(grab(function_response, "Ethernet.MACAddress")) +
                                  format_interface_addresses(grab(function_response, "FibreChannel.PermanentWWPN")) +
                                  format_interface_addresses(grab(function_response, "FibreChannel.WWPN")),
                                  append=True)

            # set VLAN settings
            port_inventory.vlan_id = grab(function_response, "Ethernet.VLAN.VLANId")
            port_inventory.vlan_enabled = grab(function_response, "Ethernet.VLAN.VLANEnable")

            # get IP addresses
            vendor_data = grab(function_response, f"Oem.{plugin_object.rf.vendor_dict_key}")

            if vendor_data is not None:
                port_inventory.ipv4_addresses = get_interface_ip_addresses(vendor_data, "IPv4Addresses")
                port_inventory.ipv6_addresses = get_interface_ip_addresses(vendor_data, "IPv6Addresses")

            # set link type
            port_inventory.update("link_type", function_response.get("NetDevFuncType"))

            if plugin_object.rf.vendor == "Cisco":
                port_inventory.update("os_name", function_response.get("Name"))

            if plugin_object.rf.vendor == "Dell":
                duplex_setting = \
                    grab(function_response, f"Oem.{plugin_object.rf.vendor_dict_key}.DellNIC.LinkDuplex") or ""
                if "full" in duplex_setting.lower():
                    port_inventory.update("full_duplex", True)
                elif "half" in duplex_setting.lower():
                    port_inventory.update("full_duplex", False)

                port_inventory.update("name", grab(function_response,
                                                   f"Oem.{plugin_object.rf.vendor_dict_key}.DellNIC.DeviceDescription"))

        return port_inventory

    plugin_object.set_current_command("NICs")

    system_id = redfish_url.rstrip("/").split("/")[-1]

    if plugin_object.rf.vendor == "HPE":
        system_response = plugin_object.rf.get(redfish_url)

        if system_response.get("error"):
            plugin_object.add_data_retrieval_error(NetworkAdapter, system_response, redfish_url)
            return

        ethernet_interfaces_path = grab(system_response,
                                        f"Oem/{plugin_object.rf.vendor_dict_key}/Links/EthernetInterfaces/@odata.id",
                                        separator="/")
        network_adapter_path = grab(system_response,
                                    f"Oem/{plugin_object.rf.vendor_dict_key}/Links/NetworkAdapters/@odata.id",
                                    separator="/")
    else:
        # assume default urls
        ethernet_interfaces_path = f"{redfish_url}/EthernetInterfaces"
        network_adapter_path = f"{redfish_url}/NetworkInterfaces"

    network_adapter_response = \
        plugin_object.rf.get_view(f"{network_adapter_path}{plugin_object.rf.vendor_data.expand_string}")

    if network_adapter_response.get("error"):
        plugin_object.add_data_retrieval_error(NetworkAdapter, network_adapter_response, network_adapter_path)
        return

    # HPE specific
    if network_adapter_response.get("NetworkAdapters") is not None:
        network_adapter_members = network_adapter_response.get("NetworkAdapters")
    else:
        network_adapter_members = network_adapter_response.get("Members")

    if network_adapter_members and len(network_adapter_members) > 0:

        for adapter in network_adapter_members:

            if adapter.get("Id") is not None:
                nic_member = adapter
            else:
                nic_member = plugin_object.rf.get(adapter.get("@odata.id"))

                if nic_member.get("error"):
                    plugin_object.add_data_retrieval_error(NetworkAdapter, nic_member, adapter.get("@odata.id"))
                    continue

            adapter_path = grab(nic_member, "Links/NetworkAdapter/@odata.id", separator="/") or \
                grab(nic_member, "Links.NetworkAdapter.0")

            # HPE systems
            num_ports = 0
            network_ports = None
            network_functions = None

            if adapter_path is None:

                status_data = get_status_data(nic_member.get("Status"))
                adapter_id = nic_member.get("Id")
                manufacturer = None
                name = nic_member.get("Name")
                model = nic_member.get("Model")
                part_number = nic_member.get("PartNumber")
                serial = nic_member.get("SerialNumber")
                firmware = grab(nic_member, "Firmware.Current.VersionString")

                source_data = nic_member
                num_ports = len(nic_member.get("PhysicalPorts") or list())
            else:
                adapter_response = plugin_object.rf.get(adapter_path)

                if adapter_response.get("error"):
                    plugin_object.add_data_retrieval_error(NetworkAdapter, adapter_response, adapter_path)
                    continue

                source_data = adapter_response

                status_data = get_status_data(adapter_response.get("Status"))

                adapter_id = adapter_response.get("Id")
                manufacturer = adapter_response.get("Manufacturer")
                name = adapter_response.get("Name")
                model = adapter_response.get("Model")
                part_number = adapter_response.get("PartNumber")
                serial = adapter_response.get("SerialNumber")
                firmware = grab(adapter_response, "Firmware.Current.VersionString")

                adapter_controllers = adapter_response.get("Controllers") or list()

                if isinstance(adapter_controllers, dict):
                    adapter_controllers = [adapter_controllers]

                for controller in adapter_controllers:
                    firmware = grab(controller, "FirmwarePackageVersion")

                    network_ports = grab(controller, "Links.NetworkPorts") or \
                        grab(controller, "Link.NetworkPorts")
                    network_functions = grab(controller, "Links.NetworkDeviceFunctions") or \
                        grab(controller, "Link.NetworkDeviceFunctions")

                    num_ports = len(network_ports)

            adapter_inventory = NetworkAdapter(
                id=adapter_id,
                name=name,
                health_status=status_data.get("Health"),
                operation_status=status_data.get("State"),
                model=model,
                manufacturer=manufacturer,
                num_ports=num_ports,
                firmware=firmware,
                part_number=part_number,
                serial=serial,
                system_ids=system_id
            )

            discovered_network_ports = 0
            for network_function in network_functions or list():
                port_inventory_data = get_network_function(network_function)

                if port_inventory_data is not None:
                    adapter_inventory.update("port_ids", port_inventory_data.id, True)

                    port_inventory_data.update("adapter_id", adapter_inventory.id)

                    discovered_network_ports += 1

            if discovered_network_ports == 0:
                for network_port in network_ports or list():
                    port_inventory_data = get_network_port(network_port, return_data=True)

                    if port_inventory_data is not None:
                        adapter_inventory.update("port_ids", port_inventory_data.id, True)

                        port_inventory_data.update("adapter_id", adapter_inventory.id)

            # special case for HPE
            if plugin_object.rf.vendor == "HPE" and len(nic_member.get("PhysicalPorts") or list()) > 0:

                num_port = 0
                for network_port in nic_member.get("PhysicalPorts") or list():
                    num_port += 1

                    port_id = f"{adapter_inventory.id}.{num_port}"

                    status_data = get_status_data(network_port.get("Status"))

                    network_port_inventory = NetworkPort(
                        id=port_id,
                        adapter_id=adapter_inventory.id,
                        os_name=network_port.get("Name"),
                        port_name=num_port,
                        health_status=status_data.get("Health"),
                        operation_status=status_data.get("State"),
                        addresses=format_interface_addresses(grab(network_port, "MacAddress")),
                        ipv4_addresses=get_interface_ip_addresses(network_port, "IPv4Addresses"),
                        ipv6_addresses=get_interface_ip_addresses(network_port, "IPv6Addresses"),
                        full_duplex=grab(network_port, "FullDuplex"),
                        current_speed=grab(network_port, "SpeedMbps"),
                        link_status=f"{network_port.get('LinkStatus') or ''}".replace("Link", ""),
                        system_ids=system_id
                    )

                    adapter_inventory.update("port_ids", port_id, True)

                    plugin_object.inventory.add(network_port_inventory)

                    if plugin_object.cli_args.verbose:
                        network_port_inventory.source_data = {"port": network_port}

            if plugin_object.cli_args.verbose:
                adapter_inventory.source_data = source_data

            plugin_object.inventory.add(adapter_inventory)

    if len(plugin_object.inventory.get(NetworkPort)) == 0:
        ethernet_interface_response = \
            plugin_object.rf.get_view(f"{ethernet_interfaces_path}{plugin_object.rf.vendor_data.expand_string}")

        if ethernet_interface_response.get("error"):
            plugin_object.add_data_retrieval_error(NetworkPort, ethernet_interface_response, ethernet_interfaces_path)
            return

        # HPE specific
        if ethernet_interface_response.get("EthernetInterfaces") is not None:
            ethernet_interface_members = ethernet_interface_response.get("EthernetInterfaces")
        else:
            ethernet_interface_members = ethernet_interface_response.get("Members")

        if ethernet_interface_members and len(ethernet_interface_members) > 0:

            for interface in ethernet_interface_members:

                if interface.get("Id") is not None:
                    interface_member = interface
                else:
                    interface_member = plugin_object.rf.get(interface.get("@odata.id"))

                    if interface_member.get("error"):
                        plugin_object.add_data_retrieval_error(NetworkPort, interface_member,
                                                               interface.get("@odata.id"))
                        continue

                if interface_member.get("Id"):

                    # get health status
                    status_data = get_status_data(interface_member.get("Status"))

                    addresses = interface_member.get("PermanentMACAddress") or interface_member.get("MACAddress")

                    port_inventory = NetworkPort(
                        id=interface_member.get("Id"),
                        name=interface_member.get("Name"),
                        health_status=status_data.get("Health"),
                        operation_status=status_data.get("State"),
                        link_status=interface_member.get("LinkStatus"),
                        addresses=format_interface_addresses(addresses),
                        current_speed=interface_member.get("SpeedMbps"),
                        system_ids=system_id
                    )

                    if plugin_object.cli_args.verbose:
                        port_inventory.source_data = interface_member

                    # add relations
                    port_inventory.add_relation(plugin_object.rf.get_system_properties(), interface_member.get("Links"))
                    port_inventory.add_relation(plugin_object.rf.get_system_properties(),
                                                interface_member.get("RelatedItem"))

                    plugin_object.inventory.add(port_inventory)

    def add_port_status(port_inventory_item):

        plugin_status = port_status = port_inventory_item.health_status

        if port_status is None:
            port_status = port_inventory_item.operation_status

        if plugin_status is None and port_status == "Enabled":
            plugin_status = "OK"

        if plugin_status is None:
            plugin_status = "OK"

        ip_addresses_string = None
        ip_addresses = [*port_inventory_item.ipv4_addresses, *port_inventory_item.ipv6_addresses]
        if len(ip_addresses) > 0:
            ip_addresses_string = "/".join(ip_addresses)

        duplex = autoneg = None
        if port_inventory_item.full_duplex is not None:
            duplex = "full" if port_inventory_item.full_duplex is True else "half"
        if port_inventory_item.autoneg is not None:
            autoneg = "on" if port_inventory_item.autoneg is True else "off"

        status_text = f"Port {port_inventory_item.id} "

        if port_inventory_item.os_name is not None:
            status_text += f"(OS name: {port_inventory_item.os_name}) "

        if ip_addresses_string is not None:
            status_text += f"(IPs: {ip_addresses_string}) "

        status_text += f"(type: {port_inventory_item.link_type}, " \
                       f"speed: {port_inventory_item.current_speed}, " \
                       f"autoneg: {autoneg}, duplex: {duplex}) "

        if port_status is not None:
            status_text += f"status: {port_status}, "

        status_text += f"link: {port_inventory_item.link_status}"

        plugin_object.add_output_data("CRITICAL" if plugin_status not in ["OK", "WARNING"] else plugin_status,
                                      status_text, location=f"System {system_id}")

    adapter_inventory = plugin_object.inventory.get(NetworkAdapter)
    port_inventory = plugin_object.inventory.get(NetworkPort)

    num_adapters = len(adapter_inventory)
    num_ports = len(port_inventory)

    for network_adapter in adapter_inventory:

        plugin_status = adapter_status = network_adapter.health_status

        if adapter_status is None:
            adapter_status = network_adapter.operation_status

        if plugin_status is None and adapter_status == "Enabled":
            plugin_status = "OK"

        if plugin_status is None:
            plugin_status = "OK"

        adapter_name = network_adapter.model \
            if len(str(network_adapter.model) or '') > len(str(network_adapter.name) or '') else network_adapter.name

        if plugin_object.rf.vendor in ["Huawei", "Cisco", "Dell"] and \
                not all(v is None for v in [network_adapter.model, network_adapter.manufacturer]):
            adapter_name = f"{network_adapter.manufacturer} {network_adapter.model}"

        status_text = f"Adapter {adapter_name} (FW: {network_adapter.firmware}) status: {adapter_status}"

        plugin_object.add_output_data("CRITICAL" if plugin_status not in ["OK", "WARNING"] else plugin_status,
                                      status_text, location=f"System {system_id}")

        for network_port in port_inventory:
            if str(network_port.adapter_id) == str(network_adapter.id):
                add_port_status(network_port)

    for network_port in port_inventory:
        if network_port.adapter_id is None:
            add_port_status(network_port)

    if num_adapters == 0:
        plugin_object.inventory.add_issue(NetworkAdapter, f"No network adapter or interface data "
                                                          f"returned for API URL '{network_adapter_path}'")
    if num_adapters + num_ports > 0:
        plugin_object.add_output_data("OK", f"All network adapter ({num_adapters}) and "
                                            f"ports ({num_ports}) are in good condition",
                                      summary=True, location=f"System {system_id}")

    return
