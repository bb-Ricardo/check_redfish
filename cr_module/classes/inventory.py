

# inventory definition
inventory_layout_version_string = "0.1"
physical_drive_attributes = [ "id", "name", "serial", "type", "speed_in_rpm", "health_status", "operation_status", "bay",
                              "size_in_byte", "firmware", "model", "power_on_hours", "interface_type", "interface_speed",
                              "encrypted", "manufacturer", "temperature", "location", "storage_port", "system_ids",
                              "storage_controller_ids", "storage_enclosure_ids", "logical_drive_ids", "failure_predicted",
                              "predicted_media_life_left_percent", "part_number"]
logical_drive_attributes = ["id", "name", "type", "health_status", "operation_status", "size_in_byte", "raid_type",
                            "encrypted", "storage_controller_ids", "physical_drive_ids", "system_ids"]
storage_controller_attributes = ["id", "name", "serial", "model", "location", "firmware", "health_status", "operation_status",
                                 "backup_power_present", "cache_size_in_mb", "system_ids", "manufacturer",
                                 "storage_enclosure_ids", "logical_drive_ids", "physical_drive_ids"]
storage_enclosure_attributes = ["id", "name", "serial", "model", "location", "firmware", "health_status", "operation_status",
                                "num_bays", "storage_controller_ids", "physical_drive_ids", "storage_port", "system_ids",
                                "manufacturer"]
processor_attributes = [ "id", "name", "serial", "model", "socket", "health_status", "operation_status", "cores",
                         "threads", "current_speed", "max_speed", "manufacturer", "instruction_set", "architecture",
                         "system_ids", "L1_cache_kib", "L2_cache_kib", "L3_cache_kib"]
memory_attributes = [ "id", "name", "serial", "socket", "slot", "channel", "health_status", "operation_status",
                      "speed", "part_number", "manufacturer", "type", "size_in_mb", "base_type", "system_ids"]
ps_attributes = [ "id", "name", "last_power_output", "part_number", "model", "health_status", "operation_status",
                  "bay", "model", "vendor", "serial", "firmware", "type", "capacity_in_watt", "input_voltage", "chassi_ids" ]
temp_fan_common_attributes = [ "id", "name", "physical_context", "health_status", "operation_status", "reading",
                   "min_reading", "max_reading", "lower_threshold_non_critical", "lower_threshold_critical",
                   "lower_threshold_fatal", "upper_threshold_non_critical", "upper_threshold_critical",
                   "upper_threshold_fatal", "reading_unit", "location", "chassi_ids"]
nic_attributes = [ "id", "name", "current_speed", "capable_speed", "health_status", "operation_status", "link_status",
                   "full_duplex", "autoneg", "ipv4_addresses", "ipv6_addresses", "mac_address", "link_type", "port_name",
                   "system_ids", "hostname", "manager_ids", "chassi_ids"]
system_attributes = [ "id", "name", "serial", "model", "manufacturer", "chassi_ids", "bios_version", "host_name", "power_state",
                      "cpu_num", "mem_size", "health_status", "operation_status", "part_number", "type", "indicator_led",
                      "manager_ids"]
firmware_attributes = [ "id", "name", "version", "location", "updateable", "health_status", "operation_status" ]
manager_attributes = [ "id", "name", "firmware", "model", "type", "system_ids", "chassi_ids", "licenses", "health_status",
                       "operation_status" ]
chassi_attributes = [ "id", "name", "model", "type", "manufacturer", "system_ids", "health_status", "operation_status",
                      "indicator_led", "serial", "sku", "manager_ids" ]




class InventoryItem(object):
    """

    """
    valid_attributes = None
    inventory_item_name = None

    def __init__(self, **kwargs):

        if args.verbose:
            self.valid_attributes.append("source_data")

        for attribute in self.valid_attributes:
            value = None
            # references with ids are always lists
            if attribute.endswith("_ids") or attribute in ["licenses", "ipv4_addresses", "ipv6_addresses"]:
                value = list()

            super().__setattr__(attribute, value)

        for k,v in kwargs.items():
            setattr(self, k, v)

    def update(self, data_key, data_value, append=False):

        #
        current_data_value = getattr(self, data_key)

        if isinstance(current_data_value, list) and append is True:
            if isinstance(data_value, (str, int, float)):
                if data_value not in current_data_value:
                    current_data_value.append(data_value)
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
        for property, property_links in system_properties.items():

            for property_link in property_links:
                if property_link.rstrip("/") in relation_links:
                    relations_property_attribute = relations.get(property)

                    # add relation if item has attribute
                    if relations_property_attribute is not None and hasattr(self, relations_property_attribute):

                        id = property_link.rstrip("/").split("/")[-1]
                        # check if object id is an int
                        try:
                            id = int(id)
                        except:
                            pass

                        # update attribute
                        self.update(relations_property_attribute, id, True)

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
                return v=='0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()

            def is_float(v):
                try:     i = float(v)
                except:  return False
                return True

            # skip formating of certain attributes
            if value is not None and key not in [ "id", "name", "firmware", "serial", "version" ]:
                if is_int(value):
                    value = int(float(value))

                elif is_float(value):
                    value = float(value)

                elif value.upper() in status_types.keys():
                    value = value.upper()

        if isinstance(current_value, list):
            if value is None:
                value = list()
            elif isinstance(value, (str, int, float)):
                value = [ value ]
            elif not isinstance(value, list):
                value = [ f"{value}" ]
        else:
            if isinstance(value, (list, dict, set, tuple)):
                value = f"{value}"

        super().__setattr__(key, value)

class PhysicalDrive(InventoryItem):
    inventory_item_name = "physical_drives"
    valid_attributes = physical_drive_attributes

class LogicalDrive(InventoryItem):
    inventory_item_name = "logical_drives"
    valid_attributes = logical_drive_attributes

class StorageController(InventoryItem):
    inventory_item_name = "storage_controllers"
    valid_attributes = storage_controller_attributes

class StorageEnclosure(InventoryItem):
    inventory_item_name = "storage_enclosures"
    valid_attributes = storage_enclosure_attributes

class Processor(InventoryItem):
    inventory_item_name = "processors"
    valid_attributes = processor_attributes

class Memory(InventoryItem):
    inventory_item_name = "memories"
    valid_attributes = memory_attributes

class PowerSupply(InventoryItem):
    inventory_item_name = "power_supplies"
    valid_attributes = ps_attributes

class Temperature(InventoryItem):
    inventory_item_name = "temperatures"
    valid_attributes = temp_fan_common_attributes

class Fan(InventoryItem):
    inventory_item_name = "fans"
    valid_attributes = temp_fan_common_attributes

class NIC(InventoryItem):
    inventory_item_name = "nics"
    valid_attributes = nic_attributes

class System(InventoryItem):
    inventory_item_name = "systems"
    valid_attributes = system_attributes

class Firmware(InventoryItem):
    inventory_item_name = "firmware"
    valid_attributes = firmware_attributes

class Manager(InventoryItem):
    inventory_item_name = "managers"
    valid_attributes = manager_attributes

class Chassi(InventoryItem):
    inventory_item_name = "chassis"
    valid_attributes = chassi_attributes

class Inventory(object):
    """

    """
    base_structure = dict()
    inventory_start = None
    data_retrieval_issues = list()


    def __init__(self):
        for inventory_sub_class in InventoryItem.__subclasses__():
            if inventory_sub_class.inventory_item_name is None:
                raise AttributeError("The 'inventory_item_name' attribute for class '%s' is undefined." %
                                 inventory_sub_class.__name__)

            self.base_structure[inventory_sub_class.inventory_item_name] = list()

        # set metadata
        self.inventory_start = datetime.datetime.utcnow()

    def add(self, object):

        if not isinstance(object, InventoryItem):
            raise AttributeError("'%s' object not allowed to add to a '%s' class item." %
                                 (object.__class__.__name__, InventoryItem.__name__))

        # check if ID is already used and add issue
        for inv_item in self.base_structure[object.inventory_item_name]:
            if inv_item.id == object.id:
                #raise AttributeError(f"Object id '{object.id}' already used")
                print(f"Object id '{object.id}' already used", file=sys.stderr)

        self.base_structure[object.inventory_item_name].append(object)

    def update(self, class_name, component_id, data_key, data_value, append=False):

        if not class_name in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        # find inventory item to update
        for inventory_item in self.base_structure[class_name.inventory_item_name]:
            if inventory_item.id == component_id:

                inventory_item.update(data_key, data_value, append)

    def append(self, class_name, component_id, data_key, data_value):

        self.update(class_name, component_id, data_key, data_value, True)

    def add_issue(self, class_name, issue = None):

        if issue is None:
            return

        if not class_name in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        self.data_retrieval_issues.append(f"{class_name.inventory_item_name}: {issue}")

    def get(self, class_name):

        if not class_name in InventoryItem.__subclasses__():
            raise AttributeError("'%s' object must be a sub class of '%s'." %
                                 (class_name.__name__, InventoryItem.__name__))

        if self.base_structure[class_name.inventory_item_name] is None:
            return list()

        return self.base_structure[class_name.inventory_item_name]

    def to_json(self):
        inventory_content = self.base_structure

        # add metadata
        inventory_content["meta"] = {
            "WARNING": "THIS is a alpha version of this implementation and possible changes might occur without notice",
            "start_of_data_collection": self.inventory_start.replace(tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat(),
            "duration_of_data_colection_in_seconds": (datetime.datetime.utcnow() - self.inventory_start).total_seconds(),
            "inventory_layout_version": inventory_layout_version_string,
            "data_retrieval_issues": self.data_retrieval_issues,
            "host_that_collected_inventory": os.uname()[1],
            "script_version": __version__
        }

        output = { "inventory": inventory_content }

        return json.dumps(output, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)
