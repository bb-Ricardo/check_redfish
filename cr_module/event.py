from cr_module.common import grab

import datetime


def get_event_log(plugin_object, event_type):

    if plugin_object.cli_args.inventory is True:
        return

    if event_type not in ["Manager", "System"]:
        raise Exception("Unknown event log type: %s", event_type)

    plugin_object.set_current_command("%s Event Log" % event_type)

    if event_type == "System" and plugin_object.rf.vendor in ["Huawei", "HPE", "Cisco"]:
        property_name = "systems"
    else:
        property_name = "managers"

    if plugin_object.rf.vendor == "Lenovo":
        property_name = "systems"

    if plugin_object.rf.connection.system_properties is None:
        plugin_object.rf.discover_system_properties()

    system_manager_ids = plugin_object.rf.connection.system_properties.get(property_name)

    if system_manager_ids is None or len(system_manager_ids) == 0:
        plugin_object.add_output_data("UNKNOWN", f"No '{property_name}' property found in root path '/redfish/v1'",
                                      summary=not plugin_object.cli_args.detailed)
        return

    for system_manager_id in system_manager_ids:

        if plugin_object.rf.vendor == "HPE":
            get_event_log_hpe(plugin_object, event_type, system_manager_id)

        elif plugin_object.rf.vendor == "Huawei":
            get_event_log_huawei(plugin_object, event_type, system_manager_id)

        else:
            get_event_log_generic(plugin_object, event_type, system_manager_id)

    return


def get_event_log_hpe(plugin_object, event_type, system_manager_id):

    limit_of_returned_items = plugin_object.cli_args.max
    forced_limit = False
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None

    if plugin_object.rf.vendor_data.ilo_version.lower() != "ilo 5":
        ilo4_limit = 30
        if plugin_object.cli_args.max:
            limit_of_returned_items = min(plugin_object.cli_args.max, ilo4_limit)
            if plugin_object.cli_args.max > ilo4_limit:
                forced_limit = True
        else:
            forced_limit = True
            limit_of_returned_items = ilo4_limit

    if event_type == "System":
        redfish_url = f"{system_manager_id}/LogServices/IML/Entries/?$expand=."
    else:
        redfish_url = f"{system_manager_id}/LogServices/IEL/Entries?$expand=."

        if plugin_object.cli_args.warning:
            date_warning = data_now - datetime.timedelta(days=int(plugin_object.cli_args.warning))
        if plugin_object.cli_args.critical:
            date_critical = data_now - datetime.timedelta(days=int(plugin_object.cli_args.critical))

    event_data = plugin_object.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin_object.add_output_data("OK", f"No {event_type} log entries found.",
                                      summary=not plugin_object.cli_args.detailed)
        return

    # reverse list from newest to oldest entry
    event_entries = event_data.get("Members")
    event_entries.reverse()

    num_entry = 0
    for event_entry_item in event_entries:

        if event_entry_item.get("@odata.context"):
            event_entry = event_entry_item
        else:
            event_entry = plugin_object.rf.get(event_entry_item.get("@odata.id"))

        message = event_entry.get("Message")

        num_entry += 1

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()
        date = event_entry.get("Created")
        repaired = grab(event_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.Repaired")

        if repaired is None:
            repaired = False

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00Z"

        status = "OK"

        if event_type == "System":
            if severity == "WARNING" and repaired is False:
                status = "WARNING"
            elif severity != "OK" and repaired is False:
                status = "CRITICAL"
        else:
            entry_data = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")

            if plugin_object.cli_args.critical and date_critical is not None:
                if entry_data > date_critical and severity != "OK":
                    status = "CRITICAL"
            if plugin_object.cli_args.warning and date_warning is not None:
                if entry_data > date_warning and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin_object.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_items is not None and num_entry >= limit_of_returned_items:
            if forced_limit:
                plugin_object.add_log_output_data("OK", "This is an %s, limited results to %d entries" %
                                                  (plugin_object.rf.vendor_data.ilo_version, limit_of_returned_items))
            return

    return


def get_event_log_generic(plugin_object, event_type, system_manager_id):

    limit_of_returned_items = plugin_object.cli_args.max
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    redfish_url = None

    # define locations for known vendors
    if event_type == "System":
        if plugin_object.rf.vendor == "Dell":
            log_service_data = plugin_object.rf.get(f"{system_manager_id}/LogServices/Sel")
            redfish_url = log_service_data.get("Entries").get("@odata.id")
        elif plugin_object.rf.vendor == "Fujitsu":
            redfish_url = f"{system_manager_id}/LogServices/SystemEventLog/Entries/"
        elif plugin_object.rf.vendor == "Cisco":
            redfish_url = f"{system_manager_id}/LogServices/SEL/Entries/"
        elif plugin_object.rf.vendor == "Lenovo":
            redfish_url = f"{system_manager_id}/LogServices/ActiveLog/Entries/"
    else:
        if plugin_object.rf.vendor == "Dell":
            log_service_data = plugin_object.rf.get(f"{system_manager_id}/LogServices/Lclog")
            redfish_url = log_service_data.get("Entries").get("@odata.id")
        elif plugin_object.rf.vendor == "Fujitsu":
            redfish_url = f"{system_manager_id}/LogServices/InternalEventLog/Entries/"
        elif plugin_object.rf.vendor == "Cisco":
            redfish_url = f"{system_manager_id}/LogServices/CIMC/Entries/"
        elif plugin_object.rf.vendor == "Lenovo":
            redfish_url = f"{system_manager_id}/LogServices/StandardLog/Entries/"

    # try to discover log service
    if redfish_url is None:
        system_manager_data = plugin_object.rf.get(system_manager_id)

        log_services = None
        log_services_link = grab(system_manager_data, "LogServices/@odata.id", separator="/")
        if log_services_link is not None:
            log_services = plugin_object.rf.get(log_services_link)

        if grab(log_services, "Members") is not None and len(log_services.get("Members")) > 0:

            for log_service in log_services.get("Members"):

                log_service_data = plugin_object.rf.get(log_service.get("@odata.id"))

                # check if "Name" contains "System" or "Manager"
                if log_service_data.get("Name") is not None and \
                        event_type.lower() in log_service_data.get("Name").lower():

                    if log_service_data.get("Entries") is not None:
                        redfish_url = log_service_data.get("Entries").get("@odata.id")
                        break

    if redfish_url is None:
        plugin_object.add_output_data("UNKNOWN",
                                      f"No log services discovered in "
                                      f"{system_manager_id}/LogServices that match {event_type}")
        return

    if plugin_object.cli_args.warning:
        date_warning = data_now - datetime.timedelta(days=int(plugin_object.cli_args.warning))
    if plugin_object.cli_args.critical:
        date_critical = data_now - datetime.timedelta(days=int(plugin_object.cli_args.critical))

    event_data = plugin_object.rf.get(redfish_url)

    if event_data.get("Members") is None or len(event_data.get("Members")) == 0:
        plugin_object.add_output_data("OK", f"No {event_type} log entries found.",
                                      summary=not plugin_object.cli_args.detailed)
        return

    event_entries = event_data.get("Members")

    assoc_id_status = dict()

    # reverse list from newest to oldest entry
    if plugin_object.rf.vendor == "Lenovo":
        event_entries.reverse()

    num_entry = 0
    for event_entry_item in event_entries:

        if event_entry_item.get("Id"):
            event_entry = event_entry_item
        else:
            event_entry = plugin_object.rf.get(event_entry_item.get("@odata.id"))

        message = event_entry.get("Message")

        if message is not None:
            message = message.strip().strip("\n").strip()

        num_entry += 1

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()

        # CISCO WHY?
        if severity in ["NORMAL", "INFORMATIONAL"]:
            severity = "OK"

        date = event_entry.get("Created")

        # take care of date = None
        if date is None:
            date = "1970-01-01T00:00:00-00:00"

        status = "OK"

        # keep track of message IDs
        # newer message can clear a status for older messages
        if event_type == "System":

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
                entry_date = datetime.datetime.strptime(date[::-1].replace(":", "", 1)[::-1], "%Y-%m-%dT%H:%M:%S%z")
            except Exception:
                pass

            if entry_date is not None and date_critical is not None:
                if entry_date > date_critical.astimezone(entry_date.tzinfo) and severity != "OK":
                    status = "CRITICAL"
            if entry_date is not None and date_warning is not None:
                if entry_date > date_warning.astimezone(
                        entry_date.tzinfo) and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin_object.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_items is not None and num_entry >= limit_of_returned_items:
            return
    return


def get_event_log_huawei(plugin_object, event_type, system_manager_id):

    def collect_log_entries(entry_url):

        collected_log_entries_list = list()

        while True:

            event_data = plugin_object.rf.get(entry_url)

            collected_log_entries_list.extend(event_data.get("Members"))

            if limit_of_returned_items is not None and len(collected_log_entries_list) >= limit_of_returned_items:
                break

            if event_data.get("Members@odata.nextLink") is not None and len(
                    collected_log_entries_list) != event_data.get("Members@odata.count"):
                entry_url = event_data.get("Members@odata.nextLink")
            else:
                break

        return collected_log_entries_list

    limit_of_returned_items = plugin_object.cli_args.max
    num_entry = 0
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    # noinspection PyUnusedLocal
    log_entries = list()

    if event_type == "System":
        redfish_url = f"{system_manager_id}/LogServices/Log1/Entries/"

        log_entries = collect_log_entries(redfish_url)
    else:

        """
        This is currently only a start of implementation. Will be finished once we
        have an example of how the different LogServices Entries look like.
        """

        # leave here and tell user about missing implementation
        plugin_object.add_output_data("UNKNOWN",
                                      f"Command to check {event_type} Event Log not implemented for this vendor",
                                      summary=not plugin_object.cli_args.detailed)
        return

        # noinspection PyUnreachableCode
        """
        # set fix to max 50 (ugly, needs to be re-factored)
        if limit_of_returned_items is not None and limit_of_returned_items > 50:
            limit_of_returned_items = 50
        else:
            limit_of_returned_items = 50

        redfish_url = f"{system_manager_id}"

        manager_data = plugin_object.rf.get(redfish_url)

        if len(manager_data.get("LogServices")) == 0:
            plugin_object.add_output_data("UNKNOWN", f"No 'LogServices' found for redfish URL '{redfish_url}'",
                                          summary=not args.detailed)
            return

        log_services_data = plugin_object.rf.get(manager_data.get("LogServices").get("@odata.id"))

        while True:

            # this should loop over following LogServices
            # https://device_ip/redfish/v1/Managers/1/LogServices/OperateLog/Entries
            # https://device_ip/redfish/v1/Managers/1/LogServices/RunLog/Entries
            # https://device_ip/redfish/v1/Managers/1/LogServices/SecurityLog/Entries

            for manager_log_service in log_services_data.get("Members"):
                log_entries.extend(manager_log_service.get("@odata.id") + "/Entries")

            if limit_of_returned_items is not None and len(log_entries) >= limit_of_returned_items:
                break
        """

    if plugin_object.cli_args.warning:
        date_warning = data_now - datetime.timedelta(days=int(plugin_object.cli_args.warning))
    if plugin_object.cli_args.critical:
        date_critical = data_now - datetime.timedelta(days=int(plugin_object.cli_args.critical))

    for log_entry in log_entries:

        event_entry = plugin_object.rf.get(log_entry.get("@odata.id"))

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

        entry_data = datetime.datetime.strptime(date[::-1].replace(":", "", 1)[::-1], "%Y-%m-%dT%H:%M:%S%z")

        if date_critical is not None:
            if entry_data > date_critical.astimezone(entry_data.tzinfo) and severity != "OK":
                status = "CRITICAL"
        if date_warning is not None:
            if entry_data > date_warning.astimezone(entry_data.tzinfo) and status != "CRITICAL" and severity != "OK":
                status = "WARNING"

        plugin_object.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_items is not None and num_entry >= limit_of_returned_items:
            return

    return
