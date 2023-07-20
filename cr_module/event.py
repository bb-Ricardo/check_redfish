# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2023 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.common import grab, quoted_split, get_local_timezone
from cr_module.classes import plugin_status_types
from cr_module.classes.plugin import PluginData

import datetime
import re


def discover_log_services(system_manager_id):

    plugin_object = PluginData()

    # try to discover log service
    log_service_url_list = list()

    system_manager_data = plugin_object.rf.get(system_manager_id)

    log_services = None
    log_services_link = grab(system_manager_data, "LogServices/@odata.id", separator="/")
    if log_services_link is not None:
        log_services = plugin_object.rf.get(log_services_link)

    if isinstance(grab(log_services, "Members"), list):

        for log_service in log_services.get("Members"):

            log_service_url_list.append(log_service.get("@odata.id").rstrip("/"))

    return log_service_url_list


def get_log_entry_time(entry_date=None):

    # set to unix time 0 if no entry was passed on
    if entry_date is None:
        entry_date = "1970-01-01T00:00:00-00:00"

    # convert time zone offset from valid ISO 8601 format to python implemented datetime TZ offset
    # from:
    #   2019-11-01T15:03:32-05:00
    # to:
    #   2019-11-01T15:03:32-0500

    time_regex = "^(\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).*([+-]\d\d):*(\d\d)$"

    entry_date_object = None
    # noinspection PyBroadException
    try:
        entry_date_object = \
            datetime.datetime.strptime("".join(re.search(time_regex, entry_date).groups()), "%Y-%m-%dT%H:%M:%S%z")
    except Exception:
        pass

    # parse time zone unaware entry dates and add this local time zone
    if entry_date_object is None:

        # HP event log time format
        if "T" in entry_date:
            string_format = "%Y-%m-%dT%H:%M:%SZ"
        else:
            string_format = "%Y-%m-%d %H:%M:%S"

        # noinspection PyBroadException
        try:
            entry_date_object = datetime.datetime.strptime(entry_date, string_format)
            entry_date_object = entry_date_object.replace(tzinfo=get_local_timezone())
        except Exception:
            entry_date_object = get_log_entry_time(None)

    return entry_date_object


def log_line_is_excluded(log_message):

    plugin_object = PluginData()

    # match log message against regex expression
    if len(plugin_object.cli_args.log_exclude_list) > 0 and isinstance(log_message, str):

        for log_exclude in plugin_object.cli_args.log_exclude_list:
            if log_exclude.search(log_message):
                return True

    return False


def get_event_log(event_type):

    plugin_object = PluginData()

    # event logs are not part of the inventory
    if plugin_object.cli_args.inventory is True:
        return

    if event_type not in ["Manager", "System"]:
        raise Exception(f"Unknown event log type: {event_type}")

    plugin_object.set_current_command(f"{event_type} Event Log")

    if event_type == "System":
        property_name = plugin_object.rf.vendor_data.system_event_log_location
        event_entries_redfish_path = plugin_object.rf.vendor_data.system_event_log_entries_path or list()
    else:
        property_name = plugin_object.rf.vendor_data.manager_event_log_location
        event_entries_redfish_path = plugin_object.rf.vendor_data.manager_event_log_entries_path or list()

    all_log_services = list()
    for this_property in ["managers", "systems"]:
        for s_m_id in plugin_object.rf.get_system_properties(this_property) or list():
            all_log_services.extend(discover_log_services(s_m_id))

    if property_name is None:
        property_name = event_type.lower() + "s"
        for log_service in all_log_services:
            if event_type.lower() in log_service.lower():
                event_entries_redfish_path.append(log_service)

    system_manager_ids = plugin_object.rf.get_system_properties(property_name)

    if system_manager_ids is None or len(system_manager_ids) == 0:
        plugin_object.add_output_data("UNKNOWN", f"No '{property_name}' property found in root path '/redfish/v1'",
                                      summary=True)
        return

    plugin_object.cli_args.log_exclude_list = list()
    if plugin_object.cli_args.log_exclude is not None and len(plugin_object.cli_args.log_exclude) > 0:

        for log_excluded in quoted_split(plugin_object.cli_args.log_exclude):
            try:
                re_compiled = re.compile(log_excluded)
            except Exception as e:
                plugin_object.add_output_data("UNKNOWN", f"Problem parsing regular expression '{log_excluded}': {e}")
                continue

            plugin_object.cli_args.log_exclude_list.append(re_compiled)

    log_services_parsed = False
    for system_manager_id in system_manager_ids:

        if plugin_object.rf.vendor == "Huawei":
            get_event_log_huawei(event_type, system_manager_id)
        else:

            for single_event_entries_redfish_path in event_entries_redfish_path:
                single_event_entries_redfish_path = \
                    single_event_entries_redfish_path.format(system_manager_id=system_manager_id)

                single_event_entries_redfish_path = single_event_entries_redfish_path.rstrip("/").replace("//", "/")

                # in case the log services couldn't be discovered
                if len(all_log_services) > 0 and single_event_entries_redfish_path not in all_log_services:
                    continue

                log_services_parsed = True

                # get Entries location
                log_service_data_entries = grab(plugin_object.rf.get(single_event_entries_redfish_path),
                                                "Entries/@odata.id", separator="/")
                if log_service_data_entries is not None:
                    if plugin_object.rf.vendor == "HPE":
                        get_event_log_hpe(event_type, log_service_data_entries)
                    else:
                        get_event_log_generic(event_type, log_service_data_entries)

    if plugin_object.rf.vendor != "Huawei" and log_services_parsed is False:
        plugin_object.add_output_data("UNKNOWN", f"No log services discovered where name matches '{event_type}'")

    return


def get_event_log_hpe(event_type, redfish_path):

    plugin_object = PluginData()

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

    # reverse list from newest to oldest entry
    event_entries.reverse()

    num_entry = 0
    num_entry_discarded = 0
    for event_entry_item in event_entries:

        if event_entry_item.get("@odata.context"):
            event_entry = event_entry_item
        else:
            event_entry = plugin_object.rf.get(event_entry_item.get("@odata.id"))

        message = event_entry.get("Message")

        if log_line_is_excluded(message) is True:
            num_entry_discarded += 1
            continue

        num_entry += 1

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

        plugin_object.add_output_data(status, "%s: %s" % (date, message), is_log_entry=True, log_entry_date=entry_date)

        # obey max results returned
        if limit_of_returned_items is not None and num_entry >= limit_of_returned_items:
            if forced_limit:
                # set the timestamp to '1969-12-30 01:00:00+-TIMEZONE'
                # This is an iLO specific case where some log entries return with timestamp '0'
                # To put this message even before (chronological) log entries with timestamp '0'
                # we set it to 2 days before unix time '0'
                message_date = datetime.datetime.fromtimestamp(0-3600*48).replace(tzinfo=get_local_timezone())
                plugin_object.add_output_data("OK", f"This is an {plugin_object.rf.vendor_data.ilo_version}, "
                                                    f"limited {event_type} log results to "
                                                    f"{limit_of_returned_items} entries", is_log_entry=True,
                                                    log_entry_date=message_date)
            return

    # in case all log entries matched teh filter
    if num_entry == 0:
        status_message = f"No {event_type} log entries found."
        if len(plugin_object.cli_args.log_exclude_list) > 0:
            status_message += f" {num_entry_discarded} discarded log entries by log_exclude option."

        plugin_object.add_output_data("OK", status_message, summary=True)

    return


def get_event_log_generic(event_type, redfish_path):

    plugin_object = PluginData()

    # if a log entry has been auto cleared this amount of times within the alert level time range
    # then issue an additional WARNING message
    flapping_threshold_critical = 2
    flapping_threshold_warning = 5

    num_entry = 0
    num_entry_discarded = 0
    data_now = datetime.datetime.now()
    date_warning = None
    date_critical = None
    max_entries = None

    if plugin_object.cli_args.warning:
        date_warning = data_now - datetime.timedelta(days=int(plugin_object.cli_args.warning))
    if plugin_object.cli_args.critical:
        date_critical = data_now - datetime.timedelta(days=int(plugin_object.cli_args.critical))

    # on dell systems max entries need to be limited during request
    if plugin_object.rf.vendor == "Dell":
        max_entries = plugin_object.cli_args.max

    event_entries = plugin_object.rf.get(redfish_path, max_members=max_entries).get("Members")

    if not event_entries or len(event_entries) == 0:
        plugin_object.add_output_data("OK", f"No {event_type} log entries found in '{redfish_path}'.",
                                      summary=True)
        return

    assoc_id_status = dict()
    processed_ids = list()
    cleared_events = dict()

    # reverse list from newest to oldest entry
    if plugin_object.rf.vendor in ["Lenovo", "Supermicro"]:
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

        if log_line_is_excluded(message) is True:
            num_entry_discarded += 1
            continue

        num_entry += 1

        severity = event_entry.get("Severity")
        if severity is not None:
            severity = severity.upper()

        # CISCO WHY?
        if severity in ["NORMAL", "INFORMATIONAL"]:
            severity = "OK"

        date = event_entry.get("Created", "1970-01-01T00:00:00-00:00")
        entry_date = get_log_entry_time(date)

        status = "OK"

        # keep track of message IDs
        # newer message can clear a status for older messages
        if event_type == "System":

            event_cleared = False

            # get log entry id to associate older log entries
            assoc_id = event_entry.get("SensorNumber")

            # found an old message that has been cleared
            if assoc_id is not None and assoc_id_status.get(assoc_id) == "cleared" and severity != "OK":
                message += " (severity '%s' cleared)" % severity
                severity = "OK"
                event_cleared = True
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

            # add cleared event to list
            if event_cleared is True:
                if cleared_events.get(message) is None:
                    cleared_events[message] = list()

                cleared_events[message].append(entry_date)

        if (date_critical is not None or date_warning is not None) and severity is not None:

            if entry_date is not None and date_critical is not None:
                if entry_date > date_critical.astimezone(entry_date.tzinfo) and severity != "OK":
                    status = "CRITICAL"
            if entry_date is not None and date_warning is not None:
                if entry_date > date_warning.astimezone(
                        entry_date.tzinfo) and status != "CRITICAL" and severity != "OK":
                    status = "WARNING"

        plugin_object.add_output_data(status, "%s: %s" % (date, message), is_log_entry=True, log_entry_date=entry_date)

        processed_ids.append(event_entry_item.get("Id"))

        # obey max results returned
        if plugin_object.cli_args.max is not None and num_entry >= plugin_object.cli_args.max:
            return

    def check_flapping(event_message, list_of_dates, threshold_date, flapping_threshold):
        if threshold_date is not None:
            dates_in_flapping_range = [x for x in list_of_dates if x >= threshold_date.astimezone(x.tzinfo)]
            if len(dates_in_flapping_range) >= flapping_threshold:
                last_event_occurred = sorted(dates_in_flapping_range)[-1]
                flap_msg = "Flapping event occurred '{}' time{} since".format(
                    len(dates_in_flapping_range),
                    "s" if len(dates_in_flapping_range) != 1 else ""
                )
                flap_msg = "{}: {} {}: {}".format(
                    last_event_occurred,
                    flap_msg,
                    threshold_date.strftime("%F %T"),
                    event_message
                )
                plugin_object.add_output_data("WARNING", flap_msg, is_log_entry=True,
                                              log_entry_date=last_event_occurred)

                return True

        return False

    # check flapping events
    for event, date_list in cleared_events.items():
        if check_flapping(event, date_list, date_critical, flapping_threshold_critical):
            continue

        check_flapping(event, date_list, date_warning, flapping_threshold_warning)

    # in case all log entries matched the filter
    if num_entry == 0:
        status_message = f"No {event_type} log entries found."
        if len(plugin_object.cli_args.log_exclude_list) > 0:
            status_message += f" {num_entry_discarded} discarded log entries by log_exclude option."

        plugin_object.add_output_data("OK", status_message, summary=True)

    return


def get_event_log_huawei(event_type, system_manager_id):

    plugin_object = PluginData()

    num_entry = 0
    num_entry_discarded = 0
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
                                          summary=True)
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

        if log_line_is_excluded(message) is True:
            num_entry_discarded += 1
            continue

        num_entry += 1

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

        plugin_object.add_output_data(status, f"{date}: {log_name}: {source}: {message}", is_log_entry=True,
                                      log_entry_date=entry_date)

        # obey max results returned
        if plugin_object.cli_args.max is not None and num_entry >= plugin_object.cli_args.max:
            return

    # in case all log entries matched teh filter
    if num_entry == 0:
        status_message = f"No {event_type} log entries found."
        if len(plugin_object.cli_args.log_exclude_list) > 0:
            status_message += f" {num_entry_discarded} discarded log entries by log_exclude option."

        plugin_object.add_output_data("OK", status_message, summary=True)

    return
