
def get_single_chassi_temp(redfish_url):

    global plugin

    plugin.set_current_command("Temp")

    chassi_id = redfish_url.rstrip("/").split("/")[-1]

    redfish_url = f"{redfish_url}/Thermal"

    thermal_data = plugin.rf.get_view(redfish_url)

    default_text = ""
    temp_num = 0
    if "Temperatures" in thermal_data:

        for temp in thermal_data.get("Temperatures"):

            status_data = get_status_data(grab(temp,"Status"))

            status = status_data.get("Health")
            state = status_data.get("State")

            name = temp.get("Name")
            id = grab(temp, "MemberId")

            if id is None:
                id = name

            temp_inventory = Temperature(
                name = name,
                id = id,
                health_status = status,
                operation_status = state,
                physical_context = temp.get("PhysicalContext"),
                min_reading = temp.get("MinReadingRangeTemp"),
                max_reading = temp.get("MaxReadingRangeTemp"),
                lower_threshold_non_critical = None if temp.get("LowerThresholdNonCritical") == "N/A" else temp.get("LowerThresholdNonCritical"),
                lower_threshold_critical = None if temp.get("LowerThresholdCritical") == "N/A" else temp.get("LowerThresholdCritical"),
                lower_threshold_fatal = None if temp.get("LowerThresholdFatal") == "N/A" else temp.get("LowerThresholdFatal"),
                upper_threshold_non_critical = None if temp.get("UpperThresholdNonCritical") == "N/A" else temp.get("UpperThresholdNonCritical"),
                upper_threshold_critical = None if temp.get("UpperThresholdCritical") == "N/A" else temp.get("UpperThresholdCritical"),
                upper_threshold_fatal = None if temp.get("UpperThresholdFatal") == "N/A" else temp.get("UpperThresholdFatal"),
                chassi_ids = chassi_id
            )

            if args.verbose:
                temp_inventory.source_data = temp

            temp_inventory.reading_unit = "Celsius"
            if temp.get("ReadingCelsius") is not None:
                temp_inventory.reading = temp.get("ReadingCelsius")
            elif temp.get("ReadingFahrenheit") is not None:
                temp_inventory.reading = temp.get("ReadingFahrenheit")
                temp_inventory.reading_unit = "Fahrenheit"
            else:
                temp_inventory.reading = 0

            # add relations
            temp_inventory.add_relation(plugin.rf.connection.system_properties, temp.get("Links"))
            temp_inventory.add_relation(plugin.rf.connection.system_properties, temp.get("RelatedItem"))

            plugin.inventory.add(temp_inventory)

            if state in [ "Absent", "Disabled", "UnavailableOffline" ]:
                continue

            if status is None:
                status = "OK" if state == "Enabled" else state

            current_temp = temp_inventory.reading
            critical_temp = temp_inventory.upper_threshold_critical
            warning_temp = temp_inventory.upper_threshold_non_critical

            temp_num += 1

            if str(warning_temp) in [ "0", "N/A"]:
                warning_temp = None

            if warning_temp is not None and float(current_temp) >= float(warning_temp):
                status = "WARNING"

            if str(critical_temp) in [ "0", "N/A"]:
                critical_temp = None

            if critical_temp is not None and float(current_temp) >= float(critical_temp):
                status = "CRITICAL"

            critical_temp_text = "N/A" if critical_temp is None else "%.1f" % critical_temp

            status_text = f"Temp sensor {temp_inventory.name} status is: {status} (%.1f °C) (max: {critical_temp_text} °C)" % current_temp

            plugin.add_output_data("CRITICAL" if status not in ["OK", "WARNING"] else status, status_text)

            plugin.add_perf_data(f"temp_{temp_inventory.name}", float(current_temp), warning=warning_temp, critical=critical_temp)

        default_text = f"All temp sensors ({temp_num}) are in good condition"
    else:
        plugin.add_output_data("UNKNOWN", f"No thermal data returned for API URL '{redfish_url}'")

    plugin.add_output_data("OK", default_text, summary = True)

    return