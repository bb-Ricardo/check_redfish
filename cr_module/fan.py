
def get_single_chassi_fan(redfish_url):

    global plugin

    plugin.set_current_command("Fan")

    chassi_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin.rf.get_view(redfish_url)

    default_text = ""
    fan_num = 0
    if "Fans" in thermal_data:
        for fan in thermal_data.get("Fans"):

            status_data = get_status_data(grab(fan,"Status"))

            id = grab(fan, "MemberId")
            name = fan.get("FanName") or fan.get("Name")

            if id is None:
                id = name

            physical_context = fan.get("PhysicalContext")

            oem_data = grab(fan, f"Oem.{plugin.rf.vendor_dict_key}")
            if physical_context is None:
                physical_context = grab(oem_data, "Location") or grab(oem_data, "Position")

            fan_inventory = Fan(
                id = id,
                name = name,
                health_status = status_data.get("Health"),
                operation_status = status_data.get("State"),
                physical_context = physical_context,
                min_reading = fan.get("MinReadingRange"),
                max_reading = fan.get("MaxReadingRange"),
                lower_threshold_non_critical = fan.get("LowerThresholdNonCritical"),
                lower_threshold_critical = fan.get("LowerThresholdCritical"),
                lower_threshold_fatal = fan.get("LowerThresholdFatal"),
                upper_threshold_non_critical = fan.get("UpperThresholdNonCritical"),
                upper_threshold_critical = fan.get("UpperThresholdCritical"),
                upper_threshold_fatal = fan.get("UpperThresholdFatal"),
                location = grab(fan, f"Oem.{plugin.rf.vendor_dict_key}.Location.Info"),
                chassi_ids = chassi_id
            )

            if args.verbose:
                fan_inventory.source_data = fan

            text_speed = ""
            text_units = ""
            fan_status = fan_inventory.health_status

            # add relations
            fan_inventory.add_relation(plugin.rf.connection.system_properties, fan.get("Links"))
            fan_inventory.add_relation(plugin.rf.connection.system_properties, fan.get("RelatedItem"))

            perf_units = ""

            # DELL, Fujitsu, Huawei
            if fan.get("ReadingRPM") is not None or fan.get("ReadingUnits") == "RPM":
                fan_inventory.reading = fan.get("ReadingRPM") or fan.get("Reading")
                fan_inventory.reading_unit = "RPM"

                text_units = " RPM"

            # HP, Lenovo
            else:
                fan_inventory.reading = fan.get("Reading")
                fan_inventory.reading_unit = fan.get("ReadingUnits")

                if fan_inventory.reading_unit == "Percent":

                    text_units = "%"
                    perf_units = "%"

            text_speed = f" ({fan_inventory.reading}{text_units})"

            plugin.inventory.add(fan_inventory)

            if fan_inventory.operation_status == "Absent":
                continue

            if fan_inventory.health_status is None:
                fan_status = "OK" if fan_inventory.operation_status == "Enabled" else fan_inventory.operation_status

            fan_num += 1

            status_text = f"Fan '{fan_inventory.name}'{text_speed} status is: {fan_status}"

            plugin.add_output_data("CRITICAL" if fan_status not in ["OK", "WARNING"] else fan_status, status_text)

            if fan_inventory.reading is not None:
                plugin.add_perf_data(f"Fan_{fan_inventory.name}", int(fan_inventory.reading), perf_uom=perf_units, warning=args.warning, critical=args.critical)

        default_text = f"All fans ({fan_num}) are in good condition"
    else:
        plugin.add_output_data("UNKNOWN", f"No thermal data returned for API URL '{redfish_url}'")

    # get FanRedundancy status
    fan_redundancies = plugin.rf.get_view(redfish_url).get("FanRedundancy")
    if fan_redundancies is None:
        fan_redundancies = plugin.rf.get_view(redfish_url).get("Redundancy")

    if fan_redundancies:
        status_text = ""
        for fan_redundancy in fan_redundancies:

            fr_status = get_status_data(fan_redundancy.get("Status"))

            status = fr_status.get("Health")

            if status is not None:
                status_text = "fan redundancy status is: %s" % fr_status.get("State")

                plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text[0].upper() + status_text[1:])

        if len(status_text) != 0:
            default_text += f" and {status_text}"

    plugin.add_output_data("OK", default_text, summary = True)

    return plugin
