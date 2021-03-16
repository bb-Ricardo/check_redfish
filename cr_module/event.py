# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.common import grab
from cr_module.classes import plugin_status_types

import datetime


def discover_log_services(plugin_object, event_type, system_manager_id):
    # try to discover log service
    redfish_url = None

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

    return redfish_url


def get_log_entry_time(entry_date=None):

    # set to unix time 0 if no entry was passed on
    if entry_date is None:
        entry_date = "1970-01-01T00:00:00-00:00"

    # convert time zone offset from valid ISO 8601 format to python implemented datetime TZ offset
    # from:
    #   2019-11-01T15:03:32-05:00
    # to:
    #   2019-11-01T15:03:32-0500

    entry_date_object = None
    try:
        entry_date_object = datetime.datetime.strptime(entry_date[::-1].replace(":","",1)[::-1], "%Y-%m-%dT%H:%M:%S%z")
    except Exception:
        pass

    # parse time zone unaware entry dates and add this local time zone
    if entry_date_object is None:

        local_timezone = datetime.datetime.now(datetime.timezone(datetime.timedelta(0))).astimezone().tzinfo

        # HP event log time format
        if "T" in entry_date:
            string_format = "%Y-%m-%dT%H:%M:%SZ"
        else:
            string_format = "%Y-%m-%d %H:%M:%S"

        try:
            entry_date_object = datetime.datetime.strptime(entry_date, string_format)
            entry_date_object = entry_date_object.replace(tzinfo=local_timezone)
        except Exception:
            entry_date_object = get_log_entry_time(None)

    return entry_date_object


def get_event_log(plugin_object, event_type):

    # event logs are not part of the inventory
    if plugin_object.cli_args.inventory is True:
        return

    if event_type not in ["Manager", "System"]:
        raise Exception(f"Unknown event log type: {event_type}")

    plugin_object.set_current_command(f"{event_type} Event Log")

    if event_type == "System":
        property_name = plugin_object.rf.vendor_data.system_event_log_location
        event_entries_redfish_path = plugin_object.rf.vendor_data.system_event_log_entries_path
    else:
        property_name = plugin_object.rf.vendor_data.manager_event_log_location
        event_entries_redfish_path = plugin_object.rf.vendor_data.manager_event_log_entries_path

    # we need to discover the log services if no property_name is set (generic vendor)
    if property_name is None:
        for this_property in ["managers", "systems"]:
            for s_m_id in plugin_object.rf.get_system_properties(this_property) or list():
                event_entries_redfish_path = discover_log_services(plugin_object, event_type, s_m_id)
                if event_entries_redfish_path is not None:
                    event_entries_redfish_path = event_entries_redfish_path.replace(s_m_id, "{system_manager_id}")
                    property_name = this_property
                    break

            if property_name is not None:
                break

        if event_entries_redfish_path is None:
            plugin_object.add_output_data("UNKNOWN",
                                          f"No log services discovered where name matches '{event_type}'")
            return

    if property_name not in ["managers", "systems"]:
        raise Exception(f"Unknown event log location: {property_name}")

    system_manager_ids = plugin_object.rf.get_system_properties(property_name)

    if system_manager_ids is None or len(system_manager_ids) == 0:
        plugin_object.add_output_data("UNKNOWN", f"No '{property_name}' property found in root path '/redfish/v1'",
                                      summary=not plugin_object.cli_args.detailed)
        return

    for system_manager_id in system_manager_ids:

        if event_entries_redfish_path is not None:
            event_entries_redfish_path = event_entries_redfish_path.format(system_manager_id=system_manager_id)

        if plugin_object.rf.vendor == "HPE":
            get_event_log_hpe(plugin_object, event_type, event_entries_redfish_path)

        elif plugin_object.rf.vendor == "Huawei":
            get_event_log_huawei(plugin_object, event_type, system_manager_id)

        else:
            get_event_log_generic(plugin_object, event_type, event_entries_redfish_path)

    return


def get_event_log_hpe(plugin_object, event_type, redfish_path):

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

    if event_type == "Manager":

        if plugin_object.cli_args.warning:
            date_warning = data_now - datetime.timedelta(days=int(plugin_object.cli_args.warning))
        if plugin_object.cli_args.critical:
            date_critical = data_now - datetime.timedelta(days=int(plugin_object.cli_args.critical))

    event_entries = plugin_object.rf.get(redfish_path).get("Members")

    if len(event_entries) == 0:
        plugin_object.add_output_data("OK", f"No {event_type} log entries found.",
                                      summary=not plugin_object.cli_args.detailed)
        return

    # reverse list from newest to oldest entry
    event_entries.reverse()

    num_entry = 0
    for event_entry_item in event_entries:

        if event_entry_item.get("@odata.context"):
            event_entry = event_entry_item
        else:
            event_entry = plugin_object.rf.get(event_entry_item.get("@odata.id"))

        num_entry += 1

        message = event_entry.get("Message")
        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()
        date = event_entry.get("Created") or "1970-01-01T00:00:00Z"
        entry_date = get_log_entry_time(date)
        repaired = grab(event_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.Repaired") or False

        status = "OK"

        if event_type == "System":
            if severity == "WARNING" and repaired is False:
                status = "WARNING"
            elif severity != "OK" and repaired is False:
                status = "CRITICAL"
        else:

            if plugin_object.cli_args.critical and date_critical is not None:
                if entry_date > date_critical.astimezone(entry_date.tzinfo) and severity != "OK":
                    status = "CRITICAL"
            if plugin_object.cli_args.warning and date_warning is not None:
                if entry_date > date_warning.astimezone(entry_date.tzinfo) \
                        and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin_object.add_log_output_data(status, "%s: %s" % (date, message))

        # obey max results returned
        if limit_of_returned_items is not None and num_entry >= limit_of_returned_items:
            if forced_limit:
                plugin_object.add_log_output_data("OK", f"This is an {plugin_object.rf.vendor_data.ilo_version}, "
                                                        f"limited {event_type} log results to "
                                                        f"{limit_of_returned_items} entries")
            return

    return


def get_event_log_generic(plugin_object, event_type, redfish_path):

    num_entry = 0
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    max_entries = None

    # define locations for known vendors
    if plugin_object.rf.vendor == "Dell":
        log_service_data = plugin_object.rf.get(redfish_path)
        if grab(log_service_data, "Entries") is not None:
            redfish_path = log_service_data.get("Entries").get("@odata.id")

    if plugin_object.cli_args.warning:
        date_warning = data_now - datetime.timedelta(days=int(plugin_object.cli_args.warning))
    if plugin_object.cli_args.critical:
        date_critical = data_now - datetime.timedelta(days=int(plugin_object.cli_args.critical))

    # on dell systems max entries need to be limited during request
    if plugin_object.rf.vendor == "Dell":
        max_entries = plugin_object.cli_args.max

    event_entries = plugin_object.rf.get(redfish_path, max_members=max_entries).get("Members")

    if len(event_entries) == 0:
        plugin_object.add_output_data("OK", f"No {event_type} log entries found in '{redfish_path}'.",
                                      summary=not plugin_object.cli_args.detailed)
        return

    assoc_id_status = dict()
    processed_ids = list()

    # reverse list from newest to oldest entry
    if plugin_object.rf.vendor == "Lenovo":
        event_entries.reverse()

    for event_entry_item in event_entries:

        if event_entry_item.get("Id") is not None:
            event_entry = event_entry_item
        else:
            event_entry = plugin_object.rf.get(event_entry_item.get("@odata.id"))

        if event_entry_item.get("Id") in processed_ids:
            continue

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

        date = event_entry.get("Created", "1970-01-01T00:00:00-00:00")

        status = "OK"

        # keep track of message IDs
        # newer message can clear a status for older messages
        if event_type == "System":

            # get log entry id to associate older log entries
            assoc_id = event_entry.get("SensorNumber")

            # found an old message that has been cleared
            if assoc_id is not None and assoc_id_status.get(assoc_id) == "cleared" and severity != "OK":
                message += " (severity '%s' cleared)" % severity
                severity = "OK"
            # Fujitsu uncleared messages
            elif plugin_object.rf.vendor == "Fujitsu" and event_entry.get("MessageId") == "0x180055":
                message += " (severity '%s' (will be) cleared due to lack of clear event)" % severity
            elif severity is not None:
                if severity == "WARNING" and date_warning is None:
                    status = severity
                elif severity != "OK" and date_critical is None:
                    status = "CRITICAL"

            # keep track of messages that clear an older message
            if event_entry.get("SensorNumber") is not None and severity == "OK":
                assoc_id_status[assoc_id] = "cleared"

        if (date_critical is not None or date_warning is not None) and severity is not None:

            entry_date = get_log_entry_time(date)

            if entry_date is not None and date_critical is not None:
                if entry_date > date_critical.astimezone(entry_date.tzinfo) and severity != "OK":
                    status = "CRITICAL"
            if entry_date is not None and date_warning is not None:
                if entry_date > date_warning.astimezone(
                        entry_date.tzinfo) and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin_object.add_log_output_data(status, "%s: %s" % (date, message))

        processed_ids.append(event_entry_item.get("Id"))

        # obey max results returned
        if plugin_object.cli_args.max is not None and num_entry >= plugin_object.cli_args.max:
            return

    return


def get_event_log_huawei(plugin_object, event_type, system_manager_id):

    num_entry = 0
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    log_entries = list()

    if event_type == "System":
        redfish_url = f"{system_manager_id}/LogServices/Log1/Entries"

        log_entries = plugin_object.rf.get(redfish_url).get("Members")
    else:

        manager_data = plugin_object.rf.get(system_manager_id)

        if manager_data.get("LogServices") is None or len(manager_data.get("LogServices")) == 0:
            plugin_object.add_output_data("UNKNOWN", f"No 'LogServices' found for redfish URL '{system_manager_id}'",
                                          summary=not plugin_object.cli_args.detailed)
            return

        log_services_data = plugin_object.rf.get(grab(manager_data, "LogServices/@odata.id", separator="/")) or dict()

        # this should loop over following LogServices
        # https://device_ip/redfish/v1/Managers/1/LogServices/OperateLog/Entries
        # https://device_ip/redfish/v1/Managers/1/LogServices/RunLog/Entries
        # https://device_ip/redfish/v1/Managers/1/LogServices/SecurityLog/Entries

        for manager_log_service in log_services_data.get("Members") or list():
            log_entries.extend(plugin_object.rf.get(manager_log_service.get("@odata.id") + "/Entries").get("Members"))

    if plugin_object.cli_args.warning:
        date_warning = data_now - datetime.timedelta(days=int(plugin_object.cli_args.warning))
    if plugin_object.cli_args.critical:
        date_critical = data_now - datetime.timedelta(days=int(plugin_object.cli_args.critical))

    if event_type == "Manager":
        log_entries = sorted(log_entries, key=lambda i: i['Created'], reverse=True)

    for log_entry in log_entries:

        if log_entry.get("Id") is None:
            event_entry = plugin_object.rf.get(log_entry.get("@odata.id"))
        else:
            event_entry = log_entry

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

        severity = event_entry.get("Severity")
        message = event_entry.get("Message")
        date = event_entry.get("Created")
        entry_date = get_log_entry_time(date)
        log_name = event_entry.get("Name")
        source = ""
        status = "OK"

        if severity is not None:
            severity = severity.upper()
        else:
            severity = "OK"

        # get log source information
        if event_type == "System":
            log_name = "%s/%s" % (event_entry.get("EntryType"), event_entry.get("EventType"))
            source = "[%s]" % grab(event_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.Level")
        elif log_name == "Operate Log":
            oem_data = grab(event_entry, f"Oem.{plugin_object.rf.vendor_dict_key}")
            if oem_data is not None:
                source = "[%s/%s/%s]" % \
                         (oem_data.get("Interface"), oem_data.get("User"), oem_data.get("Address"))

        elif log_name == "Run Log":
            alert_level = grab(event_entry, f"Oem.{plugin_object.rf.vendor_dict_key}.Level")
            source = f"[{alert_level}]"
            if alert_level == "WARN":
                severity = "WARNING"
            if alert_level == "CRIT":
                severity = "CRITICAL"

        elif log_name == "Security Log":
            oem_data = grab(event_entry, f"Oem.{plugin_object.rf.vendor_dict_key}")
            if oem_data is not None:
                source = "%s/%s" % (oem_data.get("Host"), oem_data.get("Interface"))

        # check for WARNING and CRITICAL
        if date_critical is not None:
            if entry_date > date_critical.astimezone(entry_date.tzinfo) and severity != "OK":
                status = "CRITICAL" if severity not in list(plugin_status_types.keys()) else severity
        if date_warning is not None:
            if entry_date > date_warning.astimezone(entry_date.tzinfo) and status != "CRITICAL" and severity != "OK":
                status = "WARNING" if severity not in list(plugin_status_types.keys()) else severity

        plugin_object.add_log_output_data(status, f"{date}: {log_name}: {source}: {message}")

        # obey max results returned
        if plugin_object.cli_args.max is not None and num_entry >= plugin_object.cli_args.max:
            return

    return
