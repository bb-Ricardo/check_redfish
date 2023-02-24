# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2022 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.classes.inventory import PhysicalDrive

known_firmware_issues = {

    # this is currently only implemented for physical drives
    # if different components have known issues then the logic needs be added there as well

    PhysicalDrive: {

        # https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-a00092491en_us
        "VO0480JFDGT": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO0960JFDGU": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO1920JFDGV": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO3840JFDHA": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "MO0400JFFCF": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "MO0800JFFCH": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "MO1600JFFCK": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "MO3200JFFCL": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO000480JWDAR": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO000960JWDAT": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO001920JWDAU": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO003840JWDAV": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO007680JWCNK": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO015300JWCNL": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VK000960JWSSQ": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VK001920JWSSR": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VK003840JWSST": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VK007680JWSSU": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],
        "VO015300JWSSV": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6", "HDP7"],

        # https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=a00097382en_us
        "EK0800JVYPN": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"],
        "EO1600JVYPP": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"],
        "MK0800JVYPQ": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"],
        "MO1600JVYPR": ["HDP1", "HDP2", "HDP3", "HDP4", "HDP5", "HDP6"],

        # https://sp.ts.fujitsu.com/dmsp/Publications/public/SB-PRI-21010.pdf
        "PX02SMF020": ["5202", "5203", "5204"],
        "PX02SMF040": ["5202", "5203", "5204"],
        "PX02SMF080": ["5202", "5203", "5204"],
        "PX02SMB160": ["5202", "5203", "5204"],
    }
}


def component_has_firmware_issues(inventory_type, model, firmware_version):
    """
        Returns bool if firmware for a specific component has known issues

        Parameters
        ----------
        inventory_type: PowerSupply
            check_redfish inventory item class
        model: str
            name of the component model
        firmware_version: str
            firmware version to check for known issues

        Returns
        -------
        bool
            True if affect, False otherwise
    """

    if model is None or firmware_version is None:
        return False

    item_firmware_data = known_firmware_issues.get(inventory_type)

    if item_firmware_data is None:
        return False

    item_model_data = item_firmware_data.get(model)
    if item_model_data is None:
        return False

    if isinstance(item_model_data, str):
        if firmware_version == item_model_data:
            return True
        else:
            return False
    elif isinstance(item_model_data, list):
        if firmware_version in item_model_data:
            return True
        else:
            return False
    else:
        raise ValueError(f"Item data in wrong format: check {inventory_type.inventory_item_name} model {model} ")
