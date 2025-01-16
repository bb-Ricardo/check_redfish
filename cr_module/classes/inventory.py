# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2024 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import datetime
import json
import sys

from cr_module.classes import plugin_status_types

from socket import gethostname


# inventory definition
inventory_layout_version_string = "1.10.0"


# noinspection PyBroadException
class InventoryItem(object):
    """

    """
    valid_attributes = None
    inventory_item_name = None
    id = None

    verbose = False

    def __init__(self, **kwargs):

        for attribute, attribute_type in self.valid_attributes.items():
            super().__setattr__(attribute, list() if attribute_type == list else None)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def update(self, data_key, data_value, append=False):

        if data_value is None:
            return

        current_data_value = getattr(self, data_key)
        attribute_type = self.valid_attributes.get(data_key)

        if attribute_type == list and append is True:
            if isinstance(data_value, list):
                for this_data_value in [f"{x}".strip() for x in data_value if x is not None]:
                    if this_data_value not in current_data_value:
                        current_data_value.append(this_data_value)

            elif f"{data_value}".strip() not in current_data_value:
                    current_data_value.append(f"{data_value}".strip())

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
                    if key == "@odata.id" and isinstance(value, str):
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

                        # update attribute
                        self.update(relations_property_attribute, property_id, True)

    def __setattr__(self, key, value):

        # add source data without any formatting
        if key == "source_data":
            super().__setattr__(key, value)
            return

        if key not in self.valid_attributes.keys():
            raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, key))

        value_type = self.valid_attributes.get(key)

        if value is None and getattr(self, key) is None:
            return

        def is_int(v):
            return v == '0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()

        def is_float(v):
            try:
                _ = float(v)
            except Exception:
                return False
            return True

        if value_type == str:
            value = f"{value}".strip()

            if value.upper() in plugin_status_types.keys():
                value = value.upper()

            if len(value) == 0:
                value = None

        elif value_type == list:
            if not isinstance(value, value_type):
                value = [f"{value}".strip()]

        elif value_type in [int, float]:
            if not isinstance(value, value_type):
                if is_float(f"{value}".strip()):
                    value = value_type(float(f"{value}".strip()))
                if is_int(f"{value}".strip()):
                    value = value_type(f"{value}".strip())

        elif value_type == bool:
            if not isinstance(value, value_type):
                if f"{value}".strip().lower() == "true":
                    value = True
                elif f"{value}".strip().lower() == "false":
                    value = False

        else:
            value = f"{value}".strip()

        super().__setattr__(key, value)


class PhysicalDrive(InventoryItem):
    inventory_item_name = "physical_drive"
    valid_attributes = {
        "bay": str,
        "encrypted": bool,
        "failure_predicted": bool,
        "firmware": str,
        "health_status": str,
        "id": str,
        "interface_speed": int,
        "interface_type": str,
        "location": str,
        "logical_drive_ids": list,
        "manufacturer": str,
        "model": str,
        "name": str,
        "operation_status": str,
        "part_number": str,
        "power_on_hours": int,
        "predicted_media_life_left_percent": int,
        "serial": str,
        "size_in_byte": int,
        "speed_in_rpm": int,
        "storage_controller_ids": list,
        "storage_enclosure_ids": list,
        "storage_port": str,
        "system_ids": list,
        "temperature": int,
        "type": str
    }


class LogicalDrive(InventoryItem):
    inventory_item_name = "logical_drive"
    valid_attributes = {
       "encrypted": bool,
       "health_status": str,
       "id": str,
       "name": str,
       "operation_status": str,
       "physical_drive_ids": list,
       "raid_type": str,
       "size_in_byte": int,
       "storage_controller_ids": list,
       "system_ids": list,
       "type": str
    }


class StorageController(InventoryItem):
    inventory_item_name = "storage_controller"
    valid_attributes = {
       "backup_power_health": str,
       "backup_power_present": bool,
       "cache_size_in_mb": int,
       "firmware": str,
       "health_status": str,
       "id": str,
       "location": str,
       "logical_drive_ids": list,
       "manufacturer": str,
       "model": str,
       "name": str,
       "operation_status": str,
       "physical_drive_ids": list,
       "serial": str,
       "storage_enclosure_ids": list,
       "system_ids": list
    }


class StorageEnclosure(InventoryItem):
    inventory_item_name = "storage_enclosure"
    valid_attributes = {
       "firmware": str,
       "health_status": str,
       "id": str,
       "location": str,
       "manufacturer": str,
       "model": str,
       "name": str,
       "num_bays": int,
       "operation_status": str,
       "physical_drive_ids": list,
       "serial": str,
       "storage_controller_ids": list,
       "storage_port": str,
       "system_ids": list
    }


class Processor(InventoryItem):
    inventory_item_name = "processor"
    valid_attributes = {
       "L1_cache_kib": int,
       "L2_cache_kib": int,
       "L3_cache_kib": int,
       "architecture": str,
       "cores": int,
       "current_speed": int,
       "health_status": str,
       "id": str,
       "instruction_set": str,
       "manufacturer": str,
       "max_speed": int,
       "model": str,
       "name": int,
       "operation_status": int,
       "serial": str,
       "socket": int,
       "system_ids": list,
       "threads": int,
       "type": int
    }


class Memory(InventoryItem):
    inventory_item_name = "memory"
    valid_attributes = {
        "base_type": str,
        "channel": int,
        "health_status": str,
        "id": str,
        "manufacturer": str,
        "name": str,
        "operation_status": str,
        "part_number": str,
        "serial": str,
        "size_in_mb": int,
        "slot": int,
        "socket": int,
        "speed": int,
        "system_ids": list,
        "type": str
    }


class PowerSupply(InventoryItem):
    inventory_item_name = "power_supply"
    valid_attributes = {
        "bay": str,
        "capacity_in_watt": int,
        "chassi_ids": list,
        "firmware": str,
        "health_status": str,
        "id": str,
        "input_voltage": int,
        "last_power_output": int,
        "model": str,
        "name": str,
        "operation_status": str,
        "part_number": str,
        "serial": str,
        "type": str,
        "vendor": str
    }


class Temperature(InventoryItem):
    inventory_item_name = "temperature"
    valid_attributes = {
        "chassi_ids": list,
        "health_status": str,
        "id": str,
        "location": str,
        "lower_threshold_critical": int,
        "lower_threshold_fatal": int,
        "lower_threshold_non_critical": int,
        "max_reading": int,
        "min_reading": int,
        "name": str,
        "operation_status": str,
        "physical_context": str,
        "reading": int,
        "reading_unit": str,
        "upper_threshold_critical": int,
        "upper_threshold_fatal": int,
        "upper_threshold_non_critical": int
    }

class Fan(InventoryItem):
    inventory_item_name = "fan"
    valid_attributes = Temperature.valid_attributes


class NetworkAdapter(InventoryItem):
    inventory_item_name = "network_adapter"
    valid_attributes = {
        "chassi_ids": list,
        "firmware": str,
        "health_status": str,
        "id": str,
        "manager_ids": list,
        "manufacturer": str,
        "model": str,
        "name": str,
        "num_ports": int,
        "operation_status": str,
        "part_number": str,
        "port_ids": list,
        "system_ids": list,
        "serial": str
    }


class NetworkPort(InventoryItem):
    inventory_item_name = "network_port"
    valid_attributes = {
        "adapter_id": str,
        "addresses": list,
        "autoneg": bool,
        "capable_speed": int,
        "chassi_ids": list,
        "current_speed": int,
        "full_duplex": bool,
        "health_status": str,
        "hostname": str,
        "id": str,
        "ipv4_addresses": list,
        "ipv6_addresses": list,
        "link_status": str,
        "link_type": str,
        "manager_ids": list,
        "name": str,
        "operation_status": str,
        "os_name": str,
        "port_name": str,
        "system_ids": list,
        "vlan_enabled": bool,
        "vlan_id": int
    }


class System(InventoryItem):
    inventory_item_name = "system"
    valid_attributes = {
        "bios_version": str,
        "chassi_ids": list,
        "cpu_num": int,
        "health_status": str,
        "host_name": str,
        "id": str,
        "indicator_led": bool,
        "manager_ids": list,
        "manufacturer": str,
        "mem_size": int,
        "model": str,
        "name": str,
        "operation_status": str,
        "part_number": str,
        "power_state": str,
        "serial": str,
        "type": str
    }


class Firmware(InventoryItem):
    inventory_item_name = "firmware"
    valid_attributes = {
        "health_status": str,
        "id": str,
        "location": str,
        "name": str,
        "operation_status": str,
        "updateable": bool,
        "version": str
    }


class Manager(InventoryItem):
    inventory_item_name = "manager"
    valid_attributes = {
        "chassi_ids": list,
        "firmware": str,
        "health_status": str,
        "id": str,
        "licenses": list,
        "model": str,
        "name": str,
        "operation_status": str,
        "system_ids": list,
        "type": str
    }


class Chassi(InventoryItem):
    inventory_item_name = "chassi"
    valid_attributes = {
        "health_status": str,
        "id": str,
        "indicator_led": bool,
        "manager_ids": list,
        "manufacturer": str,
        "model": str,
        "name": str,
        "operation_status": str,
        "serial": str,
        "sku": str,
        "system_ids": list,
        "type": str
    }


class Inventory(object):
    """

    """
    base_structure = dict()
    inventory_start = None
    data_retrieval_issues = dict()
    plugin_version = None
    inventory_id = None
    inventory_name = None

    def __init__(self, plugin_version, inventory_id, inventory_name):
        for inventory_sub_class in InventoryItem.__subclasses__():
            if inventory_sub_class.inventory_item_name is None:
                raise AttributeError("The 'inventory_item_name' attribute for class '%s' is undefined." %
                                     inventory_sub_class.__name__)

            self.base_structure[inventory_sub_class.inventory_item_name] = list()

        # set metadata
        self.inventory_start = datetime.datetime.utcnow()
        self.plugin_version = plugin_version
        self.inventory_id = inventory_id
        self.inventory_name = inventory_name

    def add(self, object_type):

        if not isinstance(object_type, InventoryItem):
            raise AttributeError("'%s' object not allowed to add to a '%s' class item." %
                                 (object_type.__class__.__name__, InventoryItem.__name__))

        # check if ID is already used and add issue
        for inv_item in self.base_structure[object_type.inventory_item_name]:
            if inv_item.id == object_type.id:

                print(f"Object id '{object_type.id}' for '{object_type.__class__.__name__}' ({inv_item.name}) already used",
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
            "host_that_collected_inventory": gethostname(),
            "script_version": self.plugin_version,
            "inventory_id": self.inventory_id,
            "inventory_name": self.inventory_name,
        }

        output = {"inventory": inventory_content, "meta": meta_data}

        return json.dumps(output, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)
