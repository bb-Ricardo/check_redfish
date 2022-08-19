# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2022 Ricardo Bartels. All rights reserved.
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
import pprint


def get_securityservice_info(plugin_object):

    plugin_object.set_current_command("Security Service")

    managers = plugin_object.rf.get_system_properties("managers")

    if managers is None or len(managers) == 0:
        plugin_object.inventory.add_issue(Manager, "No 'managers' property found in root path '/redfish/v1'")
        return

    for manager in managers:
        if plugin_object.rf.vendor == "HPE":
            get_security_info_hp(plugin_object, manager)

    return


def get_security_info_hp(plugin_object, redfish_url):
    """
    Checks if SecurityState is Production, HighSecurity, ...
    """

    view_response = plugin_object.rf.get_view(f"{redfish_url}{plugin_object.rf.vendor_data.expand_string}")

    if view_response.get("error"):
        plugin_object.add_data_retrieval_error(Manager, view_response, redfish_url)
        return

    # HPE iLO 5 view
    if view_response.get("ILO"):
        manager_response = view_response.get("ILO")[0]
    else:
        return
    manager_id = manager_response.get("Id")
    vendor_data = grab(manager_response, f"Oem.{plugin_object.rf.vendor_dict_key}")
    security_service_link = grab(vendor_data, "Links/SecurityService/@odata.id", separator="/")
    security_service_response = plugin_object.rf.get(security_service_link)
    security_state = security_service_response.get("SecurityState")

    status_text = f"SecurityState is {security_state}"
    plugin_object.add_output_data("WARNING" if security_state in ["Production", "Wipe"] else "OK", status_text,
                                  summary=True, location=f"Manager {manager_id}")

    return

