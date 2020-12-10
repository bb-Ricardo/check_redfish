# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

"""Contains the different vendor definitions"""


class VendorGeneric:

    name = "Generic"
    view_supported = False
    view_select = None

    # only "managers" and "systems" are valid values
    manager_event_log_location = None
    system_event_log_location = None

    manager_event_log_entries_path = None
    system_event_log_entries_path = None

    expand_string = ""


class VendorHPEData(VendorGeneric):

    name = "HPE"

    ilo_version = None
    ilo_firmware_version = None

    expand_string = "?$expand=."

    manager_event_log_location = "managers"
    system_event_log_location = "systems"

    manager_event_log_entries_path = "{system_manager_id}/LogServices/IEL/Entries"
    system_event_log_entries_path = "{system_manager_id}/LogServices/IML/Entries"

    """
        Select and store view (supported from ILO 5)

        ATTENTION: This will only work as long as we are querying servers
        with "1" System, "1" Chassi and "1" Manager

        OK for now but will be changed once we have to query blade centers
    """
    view_supported = False
    view_select = {
        "Select": [
            {
                "From": f"/Systems/1/Memory/{expand_string}",
                "Properties": ["Members AS Memory"]
            },
            {
                "From": f"/Systems/1/Processors/{expand_string}",
                "Properties": ["Members AS Processors"]
            },
            {
                "From": f"/Systems/1/EthernetInterfaces/{expand_string}",
                "Properties": ["Members AS EthernetInterfaces"]
            },
            {
                "From": f"/Systems/1/BaseNetworkAdapters/{expand_string}",
                "Properties": ["Members AS NetworkAdapters"]
            },
            {
                "From": f"/Chassis/1/Power/{expand_string}",
                "Properties": ["PowerSupplies", "Redundancy AS PowerRedundancy"]
            },
            {
                "From": "/Chassis/1/Thermal/",
                "Properties": ["Temperatures", "Fans"]
            },
            {
                "From": f"/Managers/{expand_string}",
                "Properties": ["Members as ILO"]
            },
            {
                "From": f"/Managers/1/EthernetInterfaces/{expand_string}",
                "Properties": ["Members as ILOInterfaces"]
            }
        ]
    }

    view_response = None


class VendorLenovoData(VendorGeneric):

    name = "Lenovo"
    expand_string = "?$expand=*"

    manager_event_log_location = "systems"
    system_event_log_location = "systems"

    manager_event_log_entries_path = "{system_manager_id}/LogServices/StandardLog/Entries/"
    system_event_log_entries_path = "{system_manager_id}/LogServices/ActiveLog/Entries/"


class VendorDellData(VendorGeneric):

    name = "Dell"
    expand_string = "?$expand=*($levels=1)"

    manager_event_log_location = "managers"
    system_event_log_location = "managers"

    # ATTENTION: for Dell we only provide the "base" path.
    #            the Entries path will be discovered in the the according function
    manager_event_log_entries_path = "{system_manager_id}/LogServices/Lclog"
    system_event_log_entries_path = "{system_manager_id}/LogServices/Sel"


class VendorHuaweiData(VendorGeneric):

    name = "Huawei"
    # currently $expand is only support from 5.62 on and newer.
    # using this on older versions will break the plugin
    # expand_string = "?$expand=.%28$levels=1%29"

    manager_event_log_location = "managers"
    system_event_log_location = "systems"

    # defined in dedicated function get_event_log_huawei()
    manager_event_log_entries_path = None
    system_event_log_entries_path = None


class VendorFujitsuData(VendorGeneric):

    name = "Fujitsu"
    expand_string = "?$expand=Members"

    manager_event_log_location = "managers"
    system_event_log_location = "managers"

    manager_event_log_entries_path = "{system_manager_id}/LogServices/InternalEventLog/Entries/"
    system_event_log_entries_path = "{system_manager_id}/LogServices/SystemEventLog/Entries/"


class VendorCiscoData(VendorGeneric):

    name = "Cisco"
    expand_string = ""

    manager_event_log_location = "managers"
    system_event_log_location = "systems"

    manager_event_log_entries_path = "{system_manager_id}/LogServices/CIMC/Entries/"
    system_event_log_entries_path = "{system_manager_id}/LogServices/SEL/Entries/"

# EOF
