# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2022 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import logging
from cr_module.classes import plugin_status_types


def grab(structure=None, path=None, separator="."):
    """
        get data from a complex object/json structure with a
        "." separated path information. If a part of a path
        is not not present then this function returns "None".

        example structure:
            data_structure = {
              "rows": [{
                "elements": [{
                  "distance": {
                    "text": "94.6 mi",
                    "value": 152193
                  },
                  "status": "OK"
                }]
              }]
            }

        example path:
            "rows.0.elements.0.distance.value"

        example return value:
            15193


        Parameters
        ----------
        structure: dict, list
            object structure to extract data from
        path: str
            nested path to extract
        separator: str
            path separator to use. Helpful if a path element
            contains the default (.) separator.

        Returns
        -------
        str, dict, list
            the desired path element if found, otherwise None

    """

    max_recursion_level = 100

    current_level = 0
    levels = len(path.split(separator))

    if structure is None or path is None:
        return None

    # noinspection PyBroadException
    def traverse(r_structure, r_path):
        nonlocal current_level
        current_level += 1

        if current_level > max_recursion_level:
            logging.debug(f"Max recursion level ({max_recursion_level}) reached. Returning None.")
            return None

        for attribute in r_path.split(separator):
            if isinstance(r_structure, dict):
                r_structure = {k.lower(): v for k, v in r_structure.items()}
            try:
                if isinstance(r_structure, list):
                    data = r_structure[int(attribute)]
                else:
                    data = r_structure.get(attribute.lower())
            except Exception:
                return None

            if current_level == levels:
                return data
            else:
                return traverse(data, separator.join(r_path.split(separator)[1:]))

    return traverse(structure, path)


def get_status_data(status_data=None):
    """
        Some vendors provide incomplete status information
        This function is meant to parse a status structure
        and return a sanitized representation.

        Parameters
        ----------
        status_data: str, dict
            the status structure to parse

        Returns
        -------
        dict
            a unified representation of status data
            as defined in "return_data" var
    """

    return_data = {
        "Health": None,
        "HealthRollup": None,
        "State": None
    }

    """
        If it's just a string then try to check if it's one of the valid
        status types and add it as "Health" otherwise fill State
    """
    if isinstance(status_data, str):
        if status_data.upper() in plugin_status_types.keys():
            return_data["Health"] = status_data.upper()
        else:
            return_data["State"] = status_data

    # If status data is a dict then try to match the keys case insensitive.
    elif isinstance(status_data, dict):
        for status_key, status_value in status_data.items():
            for key in return_data.keys():
                if status_key.lower() == key.lower():
                    if status_value is not None and \
                            key.lower().startswith("health") and \
                            status_value.upper() in plugin_status_types.keys():
                        status_value = status_value.upper()
                    return_data[key] = status_value

    return return_data

# EOF
