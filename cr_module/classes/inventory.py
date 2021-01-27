# -*- coding: utf-8 -*-
#  Copyright (c) 2020 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import datetime
import os
import json
import sys

from cr_module.classes import plugin_status_types
from cr_module.common import grab

# inventory definition
inventory_layout_version_string = "1.2.0"


# noinspection PyBroadException
class InventoryItem(object):
    """

    """
    valid_attributes = None
    inventory_item_name = None
    id = None

    verbose = False

    def __init__(self, **kwargs):

        for attribute in self.valid_attributes:
            value = None
            # references with ids are always lists
            if attribute.endswith("_ids") or attribute in ["licenses", "ipv4_addresses", "ipv6_addresses", "addresses"]:
                value = list()

            super().__setattr__(attribute, value)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def update(self, data_key, data_value, append=False):

        if data_value is None:
            return

        #
        current_data_value = getattr(self, data_key)

        if isinstance(current_data_value, list) and append is True:
            if isinstance(data_value, (str, int, float)):
                if data_value not in current_data_value:
                    current_data_value.append(data_value)
            elif isinstance(data_value, list):
                for this_data_value in data_value:
                    if this_data_value not in current_data_value and this_data_value is not None:
                        current_data_value.append(this_data_value)
            else:
                current_data_value.extend(data_value)
            data_value = current_data_value

        setattr(self, data_key, data_value)

    def add_relation(self, system_properties, relations_data):

        # set inventory attributes for system properties
        relations = {
            "chassis": "chassi_ids",
            "systems": "system_ids",
            "managers": "manager_ids"
        }

        # recursive function to extract all values from nested data structure
        def get_links_recursive(data_structure):

            resource_list = list()

            if isinstance(data_structure, str):
                resource_list.append(data_structure.rstrip("/"))
            elif isinstance(data_structure, list):
                for item in data_structure:
                    resource_list.extend(get_links_recursive(item))
            elif isinstance(data_structure, dict):
                for key, value in data_structure.items():
                    if key == "@odata.id":
                        resource_list.append(value.rstrip("/"))
                    else:
                        resource_list.extend(get_links_recursive(value))

            return resource_list

        if not isinstance(system_properties, dict):
            return

        if relations_data is None:
            return

        # get all values from data structure
        relation_links = get_links_recursive(relations_data)

        # iterate over managers, systems and chassis to check if
        # this inventory item has a relation to it
        for property_name, property_links in system_properties.items():

            for property_link in property_links:
                if property_link.rstrip("/") in relation_links:
                    relations_property_attribute = relations.get(property_name)

                    # add relation if item has attribute
                    if relations_property_attribute is not None and hasattr(self, relations_property_attribute):

                        property_id = property_link.rstrip("/").split("/")[-1]
                        # check if object id is an int
                        try:
                            property_id = int(property_id)
                        except Exception:
                            pass

                        # update attribute
                        self.update(relations_property_attribute, property_id, True)

    def __setattr__(self, key, value):

        # add source data without any formatting
        if key == "source_data":
            super().__setattr__(key, value)
            return

        if key not in self.valid_attributes:
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, key))

        current_value = getattr(self, key)

        if value is None and current_value is None:
            return

        if isinstance(value, str):
            value = value.strip()

            if len(value) == 0:
                value = None

            def is_int(v):
                return v == '0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()

            def is_float(v):
                try:
                    _ = float(v)
                except Exception:
                    return False
                return True

            # skip formatting of certain attributes
            if value is not None and key not in ["id", "name", "firmware", "serial", "version"]:
                if is_int(value):
                    value = int(float(value))

                elif is_float(value):
                    value = float(value)

                elif value.upper() in plugin_status_types.keys():
                    value = value.upper()

        if isinstance(current_value, list):
            if value is None:
                value = list()
            elif isinstance(value, (str, int, float)):
                value = [value]
            elif not isinstance(value, list):
                value = [f"{value}"]
        else:
            if isinstance(value, (list, dict, set, tuple)):
                value = f"{value}"

        super().__setattr__(key, value)


class PhysicalDrive(InventoryItem):
    inventory_item_name = "physical_drive"
    valid_attributes = [
        "bay",
        "encrypted",
        "failure_predicted",
        "firmware",
        "health_status",
        "id",
        "interface_speed",
        "interface_type",
        "location",
        "logical_drive_ids",
        "manufacturer",
        "model",
        "name",
        "operation_status",
        "part_number",
        "power_on_hours",
        "predicted_media_life_left_percent",
        "serial",
        "size_in_byte",
        "speed_in_rpm",
        "storage_controller_ids",
        "storage_enclosure_ids",
        "storage_port",
        "system_ids",
        "temperature",
        "type"
    ]


class LogicalDrive(InventoryItem):
    inventory_item_name = "logical_drive"
    valid_attributes = [
       "encrypted",
       "health_status",
       "id",
       "name",
       "operation_status",
       "physical_drive_ids",
       "raid_type",
       "size_in_byte",
       "storage_controller_ids",
       "system_ids",
       "type"
    ]


class StorageController(InventoryItem):
    inventory_item_name = "storage_controller"
    valid_attributes = [
       "backup_power_health",
       "backup_power_present",
       "cache_size_in_mb",
       "firmware",
       "health_status",
       "id",
       "location",
       "logical_drive_ids",
       "manufacturer",
       "model",
       "name",
       "operation_status",
       "physical_drive_ids",
       "serial",
       "storage_enclosure_ids",
       "system_ids"
    ]


class StorageEnclosure(InventoryItem):
    inventory_item_name = "storage_enclosure"
    valid_attributes = [
       "firmware",
       "health_status",
       "id",
       "location",
       "manufacturer",
       "model",
       "name",
       "num_bays",
       "operation_status",
       "physical_drive_ids",
       "serial",
       "storage_controller_ids",
       "storage_port",
       "system_ids"
    ]


class Processor(InventoryItem):
    inventory_item_name = "processor"
    valid_attributes = [
       "L1_cache_kib",
       "L2_cache_kib",
       "L3_cache_kib",
       "architecture",
       "cores",
       "current_speed",
       "health_status",
       "id",
       "instruction_set",
       "manufacturer",
       "max_speed",
       "model",
       "name",
       "operation_status",
       "serial",
       "socket",
       "system_ids",
       "threads"
    ]


class Memory(InventoryItem):
    inventory_item_name = "memory"
    valid_attributes = [
        "base_type",
        "channel",
        "health_status",
        "id",
        "manufacturer",
        "name",
        "operation_status",
        "part_number",
        "serial",
        "size_in_mb",
        "slot",
        "socket",
        "speed",
        "system_ids",
        "type"
    ]


class PowerSupply(InventoryItem):
    inventory_item_name = "power_supply"
    valid_attributes = [
        "bay",
        "capacity_in_watt",
        "chassi_ids",
        "firmware",
        "health_status",
        "id",
        "input_voltage",
        "last_power_output",
        "model",
        "model",
        "name",
        "operation_status",
        "part_number",
        "serial",
        "type",
        "vendor"
    ]


class Temperature(InventoryItem):
    inventory_item_name = "temperature"
    valid_attributes = [
        "chassi_ids",
        "health_status",
        "id",
        "location",
        "lower_threshold_critical",
        "lower_threshold_fatal",
        "lower_threshold_non_critical",
        "max_reading",
        "min_reading",
        "name",
        "operation_status",
        "physical_context",
        "reading",
        "reading_unit",
        "upper_threshold_critical",
        "upper_threshold_fatal",
        "upper_threshold_non_critical"
    ]


class Fan(InventoryItem):
    inventory_item_name = "fan"
    valid_attributes = [
        "chassi_ids",
        "health_status",
        "id",
        "location",
        "lower_threshold_critical",
        "lower_threshold_fatal",
        "lower_threshold_non_critical",
        "max_reading",
        "min_reading",
        "name",
        "operation_status",
        "physical_context",
        "reading",
        "reading_unit",
        "upper_threshold_critical",
        "upper_threshold_fatal",
        "upper_threshold_non_critical"
    ]


class NetworkAdapter(InventoryItem):
    inventory_item_name = "network_adapter"
    valid_attributes = [
        "chassi_ids",
        "firmware",
        "health_status",
        "id",
        "manager_ids",
        "manufacturer",
        "model",
        "name",
        "num_ports",
        "operation_status",
        "part_number",
        "port_ids",
        "serial",
        "system_ids"
    ]


class NetworkPort(InventoryItem):
    inventory_item_name = "network_port"
    valid_attributes = [
        "adapter_id",
        "addresses",
        "autoneg",
        "capable_speed",
        "chassi_ids",
        "current_speed",
        "full_duplex",
        "health_status",
        "hostname",
        "id",
        "ipv4_addresses",
        "ipv6_addresses",
        "link_status",
        "link_type",
        "manager_ids",
        "name",
        "operation_status",
        "os_name",
        "port_name",
        "system_ids",
        "vlan_enabled",
        "vlan_id"
    ]


class System(InventoryItem):
    inventory_item_name = "system"
    valid_attributes = [
        "bios_version",
        "chassi_ids",
        "cpu_num",
        "health_status",
        "host_name",
        "id",
        "indicator_led",
        "manager_ids",
        "manufacturer",
        "mem_size",
        "model",
        "name",
        "operation_status",
        "part_number",
        "power_state",
        "serial",
        "type"
    ]


class Firmware(InventoryItem):
    inventory_item_name = "firmware"
    valid_attributes = [
        "health_status",
        "id",
        "location",
        "name",
        "operation_status",
        "updateable",
        "version"
    ]


class Manager(InventoryItem):
    inventory_item_name = "manager"
    valid_attributes = [
        "chassi_ids",
        "firmware",
        "health_status",
        "id",
        "licenses",
        "model",
        "name",
        "operation_status",
        "system_ids",
        "type"
    ]


class Chassi(InventoryItem):
    inventory_item_name = "chassi"
    valid_attributes = [
        "health_status",
        "id",
        "indicator_led",
        "manager_ids",
        "manufacturer",
        "model",
        "name",
        "operation_status",
        "serial",
        "sku",
        "system_ids",
        "type"
    ]


class Inventory(object):
    """

    """
    base_structure = dict()
    inventory_start = None
    data_retrieval_issues = dict()
    plugin_version = None
    inventory_id = None

    def __init__(self, plugin_version, inventory_id):
        for inventory_sub_class in InventoryItem.__subclasses__():
            if inventory_sub_class.inventory_item_name is None:
                raise AttributeError("The 'inventory_item_name' attribute for class '%s' is undefined." %
                                     inventory_sub_class.__name__)

            self.base_structure[inventory_sub_class.inventory_item_name] = list()

        # set metadata
        self.inventory_start = datetime.datetime.utcnow()
        self.plugin_version = plugin_version
        self.inventory_id = inventory_id

    def add(self, object_type):

        if not isinstance(object_type, InventoryItem):
            raise AttributeError("'%s' object not allowed to add to a '%s' class item." %
                                 (object_type.__class__.__name__, InventoryItem.__name__))

        # check if ID is already used and add issue
        for inv_item in self.base_structure[object_type.inventory_item_name]:
            if inv_item.id == object_type.id:

                print(f"Object id '{object_type.id}' for '{object_type.__class__.__name__}' already used",
                      file=sys.stderr)

        self.base_structure[object_type.inventory_item_name].append(object_type)

    def update(self, class_name, component_id, data_key, data_value, append=False):

        if class_name not in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        # find inventory item to update
        for inventory_item in self.base_structure[class_name.inventory_item_name]:
            if inventory_item.id == component_id:

                inventory_item.update(data_key, data_value, append)

    def append(self, class_name, component_id, data_key, data_value):

        self.update(class_name, component_id, data_key, data_value, True)

    def add_issue(self, class_name, issue=None):

        if issue is None:
            return

        if class_name not in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        current_issues = self.data_retrieval_issues.get(class_name.inventory_item_name, list())
        current_issues.append(f"{issue}")
        self.data_retrieval_issues[class_name.inventory_item_name] = current_issues

    def get_issues(self, class_name=None):

        if class_name is not None:
            if class_name not in InventoryItem.__subclasses__():
                raise AttributeError("'%s' object must be a sub class of '%s'." %
                                     (class_name.__name__, InventoryItem.__name__))

            return self.data_retrieval_issues.get(class_name.inventory_item_name, list())
        else:
            return self.data_retrieval_issues

    def get(self, class_name):

        if isinstance(class_name, str):
            if class_name not in [x.inventory_item_name for x in InventoryItem.__subclasses__()]:
                raise AttributeError(f"'{class_name}' must be a sub class of {InventoryItem.__name__}")

            inventory_key = class_name

        else:
            if class_name not in InventoryItem.__subclasses__():
                raise AttributeError("'%s' object must be a sub class of '%s'." %
                                     (class_name.__name__, InventoryItem.__name__))
            else:
                inventory_key = class_name.inventory_item_name

        return self.base_structure.get(inventory_key, list())

    def unset(self, class_name=None):

        if class_name not in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        self.base_structure[class_name.inventory_item_name] = list()

    def to_json(self):
        inventory_content = self.base_structure

        start_date = self.inventory_start.replace(
            tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat()

        # add metadata
        meta_data = {
            "start_of_data_collection": start_date,
            "duration_of_data_collection_in_seconds": (datetime.datetime.utcnow()-self.inventory_start).total_seconds(),
            "inventory_layout_version": inventory_layout_version_string,
            "data_retrieval_issues": self.data_retrieval_issues,
            "host_that_collected_inventory": os.uname()[1],
            "script_version": self.plugin_version,
            "inventory_id": self.inventory_id
        }

        output = {"inventory": inventory_content, "meta": meta_data}

        return json.dumps(output, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)
