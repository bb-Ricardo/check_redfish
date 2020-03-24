


class VendorHPEData():

    ilo_hostname = None
    ilo_version = None
    ilo_firmware_version = None
    ilo_health = None

    expand_string = "?$expand=."

    resource_directory = None

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
                "From": "/Systems/1/Memory/?$expand=.",
                "Properties": [ "Members AS Memory"]
            },
            {
                "From": "/Systems/1/Processors/?$expand=.",
                "Properties": [ "Members AS Processors"]
            },
            {
                "From": "/Systems/1/EthernetInterfaces/?$expand=.",
                "Properties": [ "Members AS EthernetInterfaces"]
            },
            {
                "From": "/Chassis/1/Power/?$expand=.",
                "Properties": ["PowerSupplies", "Redundancy AS PowerRedundancy"]
            },
            {
                "From": "/Chassis/1/Thermal/",
                "Properties": ["Temperatures", "Fans" ]
            },
            {
                "From": "/Managers/?$expand=.",
                "Properties": [ "Members as ILO" ]
            },
            {
                "From": "/Managers/1/EthernetInterfaces/?$expand=.",
                "Properties": [ "Members as ILOInterfaces" ]
            }
        ]
    }

    view_response = None

class VendorLenovoData():

    view_supported = False
    view_select = None

    expand_string = "?$expand=*"

class VendorDellData():

    view_supported = False
    view_select = None

    expand_string = "?$expand=*($levels=1)"

class VendorHuaweiData():

    view_supported = False
    view_select = None

    # currently $expand is not supported
    expand_string = ""

class VendorFujitsuData():

    view_supported = False
    view_select = None

    expand_string = "?$expand=Members"

class VendorCiscoData():

    view_supported = False
    view_select = None

    expand_string = ""

class VendorGeneric():

    view_supported = False
    view_select = None

    expand_string = ""
