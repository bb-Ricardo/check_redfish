

def grab(structure=None, path=None, separator="."):
    """
        get data from a complex object/json structure with a
        "." separated path information. If a part of a path
        is not not present then this function returns "None".

        example structure:
            data_stracture = {
              "rows": [{
                "elements": [{
                  "distance": {
                    "text": "94.6 mi",
                    "value": 152193
                  },
                  "status": "OK"
                }]
              }]
            }

        example path:
            "rows.0.elements.0.distance.value"

        example return value:
            15193


        Parameters
        ----------
        structure: dict, list
            object structure to extract data from
        path: str
            nested path to extract
        separator: str
            path separator to use. Helpful if a path element
            contains the default (.) separator.

        Returns
        -------
        str, dict, list
            the desired path element if found, otherwise None

    """

    max_recursion_level = 100

    current_level = 0
    levels = len(path.split(separator))

    if structure is None or path is None:
        return None

    def traverse(r_structure, r_path):
        nonlocal current_level
        current_level += 1

        if current_level > max_recursion_level:
            logging.debug(f"Max recursion level ({max_recursion_level}) reached. Returning None.")
            return None

        for attribute in r_path.split(separator):
            if isinstance(r_structure, dict):
                r_structure = {k.lower(): v for k, v in r_structure.items()}
            try:
                if isinstance(r_structure, list):
                    data = r_structure[int(attribute)]
                else:
                    data = r_structure.get(attribute.lower())
            except Exception:
                return None

            if current_level == levels:
                return data
            else:
                return traverse(data, separator.join(r_path.split(separator)[1:]))

    return traverse(structure, path)

def get_status_data(status_data=None):
    """
        Some vendors provide incomplete status information
        This function is meant to parse a status structure
        and return a sanitized representation.

        Parameters
        ----------
        status_data: str, dict
            the status structure to parse

        Returns
        -------
        dict
            a unified representation of status data
            as defined in "return_data" var
    """

    return_data = {
        "Health": None,
        "HealthRollup": None,
        "State": None
    }

    """
        If it's just a string then try to check if it's one of the valid
        status types and add it as "Health" otherwise fill State
    """
    if isinstance(status_data, str):
        if status_data.upper() in status_types.keys():
            return_data["Health"] = status_data.upper()
        else:
            return_data["State"] = status_data

    # If status data is a dict then try to match the keys case insensitive.
    elif isinstance(status_data, dict):
        for status_key, status_value in status_data.items():
            for key in return_data.keys():
                if status_key.lower() == key.lower():
                    if status_value is not None and \
                       key.lower().startswith("health") and \
                       status_value.upper() in status_types.keys():
                        status_value = status_value.upper()
                    return_data[key] = status_value

    return return_data

def parse_command_line():
    """parse command line arguments
    Also add current version and version date to description
    """

    # define command line options
    parser = ArgumentParser(
        description=self_description + "\nVersion: " + __version__ + " (" + __version_date__ + ")",
        formatter_class=RawDescriptionHelpFormatter, add_help=False)

    group = parser.add_argument_group(title="mandatory arguments")
    group.add_argument("-H", "--host",
                        help="define the host to request. To change the port just add ':portnumber' to this parameter." )

    group = parser.add_argument_group(title="authentication arguments")
    group.add_argument("-u", "--username", help="the login user name")
    group.add_argument("-p", "--password", help="the login password")
    group.add_argument("-f", "--authfile", help="authentication file with user name and password")
    group.add_argument("--sessionfile", help="define name of session file")
    group.add_argument("--sessionfiledir", help="define directory where the plugin saves session files")

    group = parser.add_argument_group(title="optional arguments")
    group.add_argument("-h", "--help", action='store_true',
                        help="show this help message and exit")
    group.add_argument("-w", "--warning", default="",
                        help="set warning value")
    group.add_argument("-c", "--critical", default="",
                        help="set critical value")
    group.add_argument("-v", "--verbose",  action='store_true',
                        help="this will add all https requests and responses to output, "
                        "also adds inventory source data to all inventory objects")
    group.add_argument("-d", "--detailed",  action='store_true',
                        help="always print detailed result")
    group.add_argument("-m", "--max",  type=int,
                        help="set maximum of returned items for --sel or --mel")
    group.add_argument("-r", "--retries",  type=int, default=default_conn_max_retries,
                        help="set number of maximum retries (default: %d)" % default_conn_max_retries)
    group.add_argument("-t", "--timeout",  type=int, default=default_conn_timeout,
                        help="set number of request timeout per try/retry (default: %d)" % default_conn_timeout)

    # require at least one argument
    group = parser.add_argument_group(title="query status/health information (at least one is required)")
    group.add_argument("--storage", dest="requested_query", action='append_const', const="storage",
                        help="request storage health")
    group.add_argument("--proc", dest="requested_query", action='append_const', const="proc",
                        help="request processor health")
    group.add_argument("--memory", dest="requested_query", action='append_const', const="memory",
                        help="request memory health")
    group.add_argument("--power", dest="requested_query", action='append_const', const="power",
                        help="request power supply health")
    group.add_argument("--temp", dest="requested_query", action='append_const', const="temp",
                        help="request temperature sensors status")
    group.add_argument("--fan", dest="requested_query", action='append_const', const="fan",
                        help="request fan status")
    group.add_argument("--nic", dest="requested_query", action='append_const', const="nic",
                        help="request network interface status")
    group.add_argument("--bmc", dest="requested_query", action='append_const', const="bmc",
                        help="request bmc infos and status")
    group.add_argument("--info", dest="requested_query", action='append_const', const="info",
                        help="request system informations")
    group.add_argument("--firmware", dest="requested_query", action='append_const', const="firmware",
                        help="request firmware informations")
    group.add_argument("--sel", dest="requested_query", action='append_const', const="sel",
                        help="request System Log status")
    group.add_argument("--mel", dest="requested_query", action='append_const', const="mel",
                        help="request Management Processor Log status")
    group.add_argument("--all", dest="requested_query", action='append_const', const="all",
                        help="request all of the above information at once.")

    # inventory
    group = parser.add_argument_group(title="query inventory information (no health check)")
    group.add_argument("-i", "--inventory",  action='store_true',
                        help="return inventory in json format instead of regular plugin output")

    result = parser.parse_args()

    if result.help:
        parser.print_help()
        print("")
        exit(0)

    if result.requested_query is None:
        parser.error("You need to specify at least one query command.")

    # need to check this ourself otherwise it's not
    # possible to put the help command into a arguments group
    if result.host is None:
        parser.error("no remote host defined")

    return result

def get_basic_system_info():

    global plugin

    basic_infos = plugin.rf.connection.root
    vendor_string = ""

    if basic_infos.get("Oem"):

        if len(basic_infos.get("Oem")) > 0:
            vendor_string = list(basic_infos.get("Oem"))[0]

        plugin.rf.vendor_dict_key = vendor_string

        if vendor_string in ["Hpe", "Hp"]:
            plugin.rf.vendor = "HPE"

            plugin.rf.vendor_data = VendorHPEData()

            manager_data = grab(basic_infos, f"Oem.{vendor_string}.Manager.0")

            if manager_data is not None:
                plugin.rf.vendor_data.ilo_hostname = manager_data.get("HostName")
                plugin.rf.vendor_data.ilo_version = manager_data.get("ManagerType")
                plugin.rf.vendor_data.ilo_firmware_version = manager_data.get("ManagerFirmwareVersion")

                if plugin.rf.vendor_data.ilo_version.lower() == "ilo 5":
                    plugin.rf.vendor_data.view_supported = True

        if vendor_string in ["Lenovo"]:
            plugin.rf.vendor = "Lenovo"

            plugin.rf.vendor_data = VendorLenovoData()

        if vendor_string in ["Dell"]:
            plugin.rf.vendor = "Dell"

            plugin.rf.vendor_data = VendorDellData()

        if vendor_string in ["Huawei"]:
            plugin.rf.vendor = "Huawei"

            plugin.rf.vendor_data = VendorHuaweiData()

        if vendor_string in ["ts_fujitsu"]:
            plugin.rf.vendor = "Fujitsu"

            plugin.rf.vendor_data = VendorFujitsuData()

    if "CIMC" in str(plugin.rf.connection.system_properties.get("managers")):
        plugin.rf.vendor = "Cisco"

        plugin.rf.vendor_data = VendorCiscoData()

    if plugin.rf.vendor_data is None:
        if vendor_string is None:
            plugin.rf.vendor = "Generic"
        else:
            plugin.rf.vendor = vendor_string

        plugin.rf.vendor_data = VendorGeneric()

    return

def discover_system_properties():

    global plugin

    if vars(plugin.rf.connection).get("system_properties") is not None:
        return

    system_properties = dict()

    root_objects = [ "Chassis", "Managers", "Systems" ]

    for root_object in root_objects:
        if plugin.rf.connection.root.get(root_object) is None:
            continue

        rf_path = plugin.rf.get(plugin.rf.connection.root.get(root_object).get("@odata.id"))

        if rf_path is None:
            continue

        system_properties[root_object.lower()] = list()
        for entity in rf_path.get("Members"):

            # ToDo:
            #  * This is a DELL workaround
            #  * If RAID chassi is requested the iDRAC will restart
            if root_object == "Chassis" and \
                    ("RAID" in entity.get("@odata.id") or "Enclosure" in entity.get("@odata.id")):
                continue

            system_properties[root_object.lower()].append(entity.get("@odata.id"))

    plugin.rf.connection.system_properties = system_properties
    plugin.rf.save_session_to_file()

    return
