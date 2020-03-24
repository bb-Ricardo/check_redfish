
def get_event_log(type):

    global plugin

    if args.inventory is True:
        return

    if type not in ["Manager", "System"]:
        raise Exception("Unknown event log type: %s", type)

    plugin.set_current_command("%s Event Log" % type)

    if type == "System" and plugin.rf.vendor in ["Huawei", "HPE", "Cisco"]:
        property_name = "systems"
    else:
        property_name = "managers"

    if plugin.rf.vendor == "Lenovo":
        property_name = "systems"

    if plugin.rf.connection.system_properties is None:
        discover_system_properties()

    system_manager_ids = plugin.rf.connection.system_properties.get(property_name)

    if system_manager_ids is None or len(system_manager_ids) == 0:
        plugin.add_output_data("UNKNOWN", f"No '{property_name}' property found in root path '/redfish/v1'", summary = not args.detailed)
        return

    for system_manager_id in system_manager_ids:

        if plugin.rf.vendor == "HPE":
            get_event_log_hpe(type, system_manager_id)

        elif plugin.rf.vendor == "Huawei":
            get_event_log_huawei(type, system_manager_id)

        else:
            get_event_log_generic(type, system_manager_id)

    return

def get_event_log_hpe(type, system_manager_id):

    global plugin

    limit_of_returned_itmes = args.max
    forced_limit = False
    data_now = datetime.datetime.now()

    if plugin.rf.vendor_data.ilo_version.lower() != "ilo 5":
        ilo4_limit = 30
        if args.max:
            limit_of_returned_itmes = min(args.max, ilo4_limit)
            if args.max > ilo4_limit:
                forced_limit = True
        else:
            forced_limit = True
            limit_of_returned_itmes = ilo4_limit

    if type == "System":
        redfish_url = f"{system_manager_id}/LogServices/IML/Entries/?$expand=."
    else:
        redfish_url = f"{system_manager_id}/LogServices/IEL/Entries?$expand=."

        if args.warning:
            date_warning = data_now - datetime.timedelta(days=int(args.warning))
        if args.critical:
            date_critical = data_now - datetime.timedelta(days=int(args.critical))

    event_data = plugin.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin.add_output_data("OK", f"No {type} log entries found.", summary = not args.detailed)
        return

    # reverse list from newest to oldest entry
    event_entries = event_data.get("Members")
    event_entries.reverse()

    num_entry = 0
    for event_entry_itme in event_entries:

        if event_entry_itme.get("@odata.context"):
            event_entry = event_entry_itme
        else:
            event_entry = plugin.rf.get(event_entry_itme.get("@odata.id"))

        message = event_entry.get("Message")

        num_entry += 1

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()
        date = event_entry.get("Created")
        repaired = grab(event_entry, f"Oem.{plugin.rf.vendor_dict_key}.Repaired")

        if repaired == None:
            repaired = False

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00Z"

        status = "OK"

        if type == "System":
            if severity == "WARNING" and repaired is False:
                status = "WARNING"
            elif severity != "OK" and repaired is False:
                status = "CRITICAL"
        else:
            entry_data = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")

            if args.critical:
                if entry_data > date_critical and severity != "OK":
                    status = "CRITICAL"
            if args.warning:
                if entry_data > date_warning and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_itmes is not None and num_entry >= limit_of_returned_itmes:
            if forced_limit:
                plugin.add_log_output_data("OK", "This is an %s, limited results to %d entries" %
                    (plugin.rf.vendor_data.ilo_version, limit_of_returned_itmes))
            return

    return

def get_event_log_generic(type, system_manager_id):

    global plugin

    limit_of_returned_itmes = args.max
    forced_limit = False
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    redfish_url = None

    # define locations for known vendors
    if type == "System":
        if plugin.rf.vendor == "Dell":
            log_service_data = plugin.rf.get(f"{system_manager_id}/LogServices/Sel")
            redfish_url = log_service_data.get("Entries").get("@odata.id")
        elif plugin.rf.vendor == "Fujitsu":
            redfish_url = f"{system_manager_id}/LogServices/SystemEventLog/Entries/"
        elif plugin.rf.vendor == "Cisco":
            redfish_url = f"{system_manager_id}/LogServices/SEL/Entries/"
        elif plugin.rf.vendor == "Lenovo":
            redfish_url = f"{system_manager_id}/LogServices/ActiveLog/Entries/"
    else:
        if plugin.rf.vendor == "Dell":
            log_service_data = plugin.rf.get(f"{system_manager_id}/LogServices/Lclog")
            redfish_url = log_service_data.get("Entries").get("@odata.id")
        elif plugin.rf.vendor == "Fujitsu":
            redfish_url = f"{system_manager_id}/LogServices/InternalEventLog/Entries/"
        elif plugin.rf.vendor == "Cisco":
            redfish_url = f"{system_manager_id}/LogServices/CIMC/Entries/"
        elif plugin.rf.vendor == "Lenovo":
            redfish_url = f"{system_manager_id}/LogServices/StandardLog/Entries/"

    # try to discover log service
    if redfish_url is None:
        system_manager_data = plugin.rf.get(system_manager_id)

        log_services = None
        log_services_link = grab(system_manager_data, "LogServices/@odata.id", separator="/")
        if log_services_link is not None:
            log_services = plugin.rf.get(log_services_link)

        if grab(log_services, "Members") is not None and len(log_services.get("Members")) > 0:

            for log_service in log_services.get("Members"):

                log_service_data = plugin.rf.get(log_service.get("@odata.id"))

                # check if "Name" contains "System" or "Manager"
                if log_service_data.get("Name") is not None and type.lower() in log_service_data.get("Name").lower():

                    if log_service_data.get("Entries") is not None:
                        redfish_url = log_service_data.get("Entries").get("@odata.id")
                        break

    if redfish_url is None:
        plugin.add_output_data("UNKNOWN", f"No log services discoverd in {system_manager_id}/LogServices that match {type}")
        return

    if args.warning:
        date_warning = data_now - datetime.timedelta(days=int(args.warning))
    if args.critical:
        date_critical = data_now - datetime.timedelta(days=int(args.critical))

    event_data = plugin.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin.add_output_data("OK", f"No {type} log entries found.", summary = not args.detailed)
        return

    event_entries = event_data.get("Members")

    assoc_id_status = dict()

    # reverse list from newest to oldest entry
    if plugin.rf.vendor == "Lenovo":
        event_entries.reverse()

    num_entry = 0
    for event_entry_item in event_entries:

        if event_entry_item.get("Id"):
            event_entry = event_entry_item
        else:
            event_entry = plugin.rf.get(event_entry_item.get("@odata.id"))

        message = event_entry.get("Message")

        if message is not None:
            message = message.strip().strip("\n").strip()

        num_entry += 1

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()

        # CISCO WHY?
        if severity in  ["NORMAL", "INFORMATIONAL"]:
            severity = "OK"

        date = event_entry.get("Created")

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00-00:00"

        status = "OK"

        # keep track of message IDs
        # newer message can clear a status for older messages
        if type == "System":

            # get log entry id to associate older log entries
            assoc_id = event_entry.get("SensorNumber")

            # found an old message that has been cleared
            if assoc_id is not None and assoc_id_status.get(assoc_id) == "cleared" and severity != "OK":
                message += " (severity '%s' cleared)" % severity
            elif severity is not None:
                if severity == "WARNING":
                    status = severity
                elif severity != "OK":
                    status = "CRITICAL"

            # keep track of messages that clear an older message
            if event_entry.get("SensorNumber") is not None and severity == "OK":
                assoc_id_status[assoc_id] = "cleared"

        if (date_critical is not None or date_warning is not None) and severity is not None:
            # convert time zone offset from valid ISO 8601 format to python implemented datetime TZ offset
            # from:
            #   2019-11-01T15:03:32-05:00
            # to:
            #   2019-11-01T15:03:32-0500

            entry_date = None
            try:
                entry_date = datetime.datetime.strptime(date[::-1].replace(":","",1)[::-1], "%Y-%m-%dT%H:%M:%S%z")
            except Exception:
                pass

            if entry_date is not None and date_critical is not None:
              if entry_date > date_critical.astimezone(entry_date.tzinfo) and severity != "OK":
                    status = "CRITICAL"
            if entry_date is not None and date_warning is not None:
                if entry_date > date_warning.astimezone(entry_date.tzinfo) and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_itmes is not None and num_entry >= limit_of_returned_itmes:
            return
    return

def get_event_log_huawei(type, system_manager_id):

    def collect_log_entries(entry_url):

        collected_log_entries_list = list()

        while True:

            event_data = plugin.rf.get(entry_url)

            collected_log_entries_list.extend(event_data.get("Members"))

            if limit_of_returned_itmes is not None and len(collected_log_entries_list) >= limit_of_returned_itmes:
                break

            if event_data.get("Members@odata.nextLink") is not None and len(collected_log_entries_list) != event_data.get("Members@odata.count"):
                entry_url = event_data.get("Members@odata.nextLink")
            else:
                break

        return collected_log_entries_list

    global plugin

    limit_of_returned_itmes = args.max
    num_entry = 0
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    log_entries = list()

    if type == "System":
        redfish_url = f"{system_manager_id}/LogServices/Log1/Entries/"

        log_entries = collect_log_entries(redfish_url)
    else:

        """
        This is currently only a start of implementation. Will be finished once we
        have an example of how the different LogServices Entries look like.
        """

        # leave here and tell user about missing implementation
        plugin.add_output_data("UNKNOWN", f"Command to check {type} Event Log not implemented for this vendor", summary = not args.detailed)
        return

        # set fix to max 50 (ugly, needs to be re-factored)
        if limit_of_returned_itmes is not None and limit_of_returned_itmes > 50:
            limit_of_returned_itmes = 50
        else:
            limit_of_returned_itmes = 50

        redfish_url = f"{system_manager_id}"

        manager_data = plugin.rf.get(redfish_url)

        if len(manager_data.get("LogServices")) == 0:
            plugin.add_output_data("UNKNOWN", f"No 'LogServices' found for redfish URL '{redfish_url}'", summary = not args.detailed)
            return

        log_services_data = plugin.rf.get(manager_data.get("LogServices").get("@odata.id"))

        while True:

            # this should loop over following LogServices
            # https://device_ip/redfish/v1/Managers/1/LogServices/OperateLog/Entries
            # https://device_ip/redfish/v1/Managers/1/LogServices/RunLog/Entries
            # https://device_ip/redfish/v1/Managers/1/LogServices/SecurityLog/Entries

            for manager_log_service in log_services_data.get("Members"):
                log_entries.extend(manager_log_service.get("@odata.id") + "/Entries")

            if limit_of_returned_itmes is not None and len(log_entries) >= limit_of_returned_itmes:
                break


    if args.warning:
        date_warning = data_now - datetime.timedelta(days=int(args.warning))
    if args.critical:
        date_critical = data_now - datetime.timedelta(days=int(args.critical))

    for log_entry in log_entries:

        event_entry = plugin.rf.get(log_entry.get("@odata.id"))

        num_entry += 1

        """
        It is not really clear what a "Asserted" and a "Deasserted" event looks like.
        We could assume that an "Asserted" event contains a "MessageId" and a
        "Deasserted" event doesn't. And the Only relation between these events is the
        exact same "Message" text. The "EventID" isn't really helpful either.
        And a clearing (Deasserted) of an alarm doesn't seem to work reliably either.
        It is also not possible to mark an event as "repaired" in iBMC.

        Due to all the above stated issues we implement a simple critical and warnings
        days logic as with HP Manager event logs. Otherwise uncleared events will alarm
        forever.
        """

        severity = event_entry.get("Severity").upper()
        message = event_entry.get("Message")
        date = event_entry.get("Created")
        # event_id = event_entry.get("EventId")
        # message_id = event_entry.get("MessageId")

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00-00:00"

        status = "OK"

        # convert time zone offset from valid ISO 8601 format to python implemented datetime TZ offset
        # from:
        #   2019-11-01T15:03:32-05:00
        # to:
        #   2019-11-01T15:03:32-0500

        entry_data = datetime.datetime.strptime(date[::-1].replace(":","",1)[::-1], "%Y-%m-%dT%H:%M:%S%z")

        if date_critical is not None:
          if entry_data > date_critical.astimezone(entry_data.tzinfo) and severity != "OK":
                status = "CRITICAL"
        if date_warning is not None:
            if entry_data > date_warning.astimezone(entry_data.tzinfo) and status != "CRITICAL" and severity != "OK":
                status = "WARNING"

        plugin.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_itmes is not None and num_entry >= limit_of_returned_itmes:
            return

    return
