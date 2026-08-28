#!/usr/bin/env bash

###############
#
#   Script to clean up mockup data

PROPERTIES_TO_SANITIZE=(
"SerialNumber" "PCASerialNumber"
"PartNumber" "SparePartNumber" "ProductPartNumber" "PCAPartNumber" "ConnectorPartNumber"
"HostName" "CommonName"
"UserName"
"Version" "FirmwareVersion" "VersionString" "FWVersion" "Revision" "FirmwareRevision"
"LicenseKey"
# Fujitsu properties
"FirmwarePackageVersion" "BiosVersion" "OpromVersion" "SDRRVersion" "OperatingSystemVersion" "AgentVersion" "BooterVersion" "DriverVersion" "UefiDriverversion" "AssetTag"
# Lenovo
"PrimaryFirmwareVersion"
"SecondaryFirmwareVersion"
# SuperMicro
"BoardSerialNumber"
# Huawei
"OSVersion" "APPVersion" "DataVersion" "ConfigurationVersion"
# Dell
"SystemMeVersion" "SmuVersion" "ServerOS.1.OSVersion" "EFIVersion" "DxioVersion" "ControllerBIOSVersion" "AgesaVersion" "UefiComplianceVersion"
# SNMP
"CommunityName" "SNMP.1.AgentCommunity" "IPMILan.1.CommunityName" "TrapCommunityName" "ReadOnlyCommunity" "ReadWriteCommunity" "ROCommunity" "RWCommunity"
)

MOCKUP_SERIAL="MOCKUPSERIAL-42"
MOCKUP_PARTNUMBER="MOCKUPPN-0815"
MOCKUP_FIRMWARE="MOCKUPFW-23"
MOCKUP_HOSTNAME="MOCKUPHOST.localdomain"
MOCKUP_USERNAME="MOCKUPUSER-1337"
MOCKUP_COMMUNITY="MOCKUPCOMMUNITY"
MOCKUP_ASSET="MOCKUPASSET"

MOCKUP="$1"

if [[ -z "$MOCKUP" ]]; then
    echo "no mockup path defined. run $0 mockup-dir"
    exit
fi

if [[ ! -d "$MOCKUP" ]]; then
    echo "mockup '${MOCKUP}' is not a directory"
    exit
fi


echo "cleaning: $(basename "$MOCKUP")"
find "$MOCKUP" -iname "*schema*" -type d -exec rm -rf {} \; 2>/dev/null
rm -f "$MOCKUP/README" >/dev/null 2>&1

for PROPERTY in "${PROPERTIES_TO_SANITIZE[@]}"; do
    VALUES=$(grep -ir "${PROPERTY}" "${MOCKUP}" | sed 's/^\(.*"'"${PROPERTY}"'"[[:space:]]*:[[:space:]]*"\)\(.*\)\("[[:space:]]*,*[[:space:]]*$\)/\2/g' | grep -v "MOCKUP\|${MOCKUP}\|${PROPERTY}\|^SERIAL$\|^0.0.0.0$\|^NA$\|^N/A$\|^$" | sort -u)

    MOCKUP_PREFIX=$MOCKUP_FIRMWARE
    [[ "$PROPERTY" =~ Serial ]] && MOCKUP_PREFIX=$MOCKUP_SERIAL
    [[ "$PROPERTY" =~ PartNumber ]] && MOCKUP_PREFIX=$MOCKUP_PARTNUMBER
    [[ "$PROPERTY" =~ HostName|CommonName ]] && MOCKUP_PREFIX=$MOCKUP_HOSTNAME
    [[ "$PROPERTY" =~ UserName ]] && MOCKUP_PREFIX=$MOCKUP_USERNAME
    [[ "$PROPERTY" =~ Community ]] && MOCKUP_PREFIX=$MOCKUP_COMMUNITY
    [[ "$PROPERTY" =~ AssetTag ]] && MOCKUP_PREFIX=$MOCKUP_ASSET

    # sort by length
    VALUES=$(echo "$VALUES" | awk '{ print length($0) " " $0; }' | sort -r -n | cut -d ' ' -f 2- | sed 's|\\n||g')

    IFS=$'\n'
    for VALUE in $VALUES; do
        # remove leading whitespace characters
        VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
        # remove trailing whitespace characters
        VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"

        # skip default users and roles
        [[ "$PROPERTY" =~ UserName && "$VALUE" =~ Administrator|Admin|admin ]] && continue

        # skip default Host names
        [[ "$PROPERTY" =~ HostName|CommonName && "$VALUE" =~ iRMC ]] && continue

        # skip default SNMP communities
        [[ "$PROPERTY" =~ Community && "$VALUE" =~ public|privat ]] && continue

        # skip trivial numbers
        [[ $VALUE =~ ^[0-9]{1,2}$ ]] && continue

        echo -e "\tcleaning $PROPERTY: $VALUE"

        RN=$(od -A n -t d -N 3 /dev/urandom)
        # simple values (1.2, 34.2) need to match property as well
        if [[ "${VALUE}" =~ ^[0-9]{1,}\.[0-9]{1,}$ ]]; then
            grep -lir "${PROPERTY}.*${VALUE}" "${MOCKUP}" | xargs sed -i 's/'"${VALUE}"'/'"${MOCKUP_PREFIX}-${RN##*' '}"'/g' 2>/dev/null
        else
            # more complex values will be changed throughout the whole mockup
            grep -lr "${VALUE}" "${MOCKUP}" | xargs sed -i 's|'"${VALUE}"'|'"${MOCKUP_PREFIX}-${RN##*' '}"'|g' 2>/dev/null
            grep -lr "${VALUE}" "${MOCKUP}" | xargs sed -i 's/'"${VALUE}"'/'"${MOCKUP_PREFIX}-${RN##*' '}"'/g' 2>/dev/null
        fi

        # CISCO specific
        if [[ ${#VALUE} -ge 5 ]]; then
            find "$MOCKUP" -type d -name "${VALUE}" -exec sh -c 'x="{}"; mv "$x" "$(dirname ${x})/'${MOCKUP_PREFIX}-${RN##*' '}'"' \; 2>/dev/null
        fi

        if [[ ! "${VALUE}" =~ ^[0-9]{1,}\.[0-9]{1,}$ ]]; then
            grep -F -r "$VALUE" "${MOCKUP}"
        fi
    done

done

MAC_PREFIX="AA:BB:CC:23:42"
WW_PREFIX="${MAC_PREFIX}:DD:EE"
#grep -rE "([[:xdigit:]]{1,2}:){7}[[:xdigit:]]{1,2}" $MOCKUP
# FC WWNN and WWPN addresses
WW_ADDRESSES=$(grep -hEr "([[:xdigit:]]{1,2}:){7}[[:xdigit:]]{1,2}" "$MOCKUP" | grep -iv "fingerprint\|00:00:00:00:00:00:00:00" | grep -oE "([[:xdigit:]]{1,2}:){7}[[:xdigit:]]{1,2}" | grep -v "^${MAC_PREFIX}" | sort -u )
for WW_ADDRESS in $WW_ADDRESSES; do
    echo -e "\tcleaning WW_ADDRESS: $WW_ADDRESS"
    grep -lEr "$WW_ADDRESS" "$MOCKUP" | xargs sed -i 's/'"${WW_ADDRESS}"'/'${WW_PREFIX}':'"${WW_ADDRESS##*:}"'/g' 2>/dev/null
done

# MAC addresses
MAC_ADDRESSES=$(grep -hEr "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}" "$MOCKUP" | grep -v "fingerprint\|00:00:00:00:00:00" | grep -oE "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}" | grep -v "^${MAC_PREFIX}" | sort -u)
for MAC_ADDRESS in $MAC_ADDRESSES; do
    echo -e "\tcleaning MAC_ADDRESS: $MAC_ADDRESS"
    grep -lEr "$MAC_ADDRESS" "$MOCKUP" | xargs sed -i 's/'"${MAC_ADDRESS}"'/'${MAC_PREFIX}':'"${MAC_ADDRESS##*:}"'/g' 2>/dev/null
done

# Lenovo MAC addresses
LENOVO_MAC_PREFIX="AABBCC2342"
MAC_ADDRESSES=$(grep -hiEr "mac.*\"[[:xdigit:]]{12}\"" "$MOCKUP" | grep -v "00:00:00:00:00:00" | grep -oE "[[:xdigit:]]{12}" | grep -v "^${LENOVO_MAC_PREFIX}" | sort -u)
for MAC_ADDRESS in $MAC_ADDRESSES; do
    echo -e "\tcleaning MAC_ADDRESS: $MAC_ADDRESS"
    grep -lEr "$MAC_ADDRESS" "$MOCKUP" | xargs sed -i 's/'"${MAC_ADDRESS}"'/'"${LENOVO_MAC_PREFIX}${MAC_ADDRESS: -2}"'/g' 2>/dev/null
done

# get list of IPv4 addresses
IPv4_ADDRESSES=$(grep -ohEr "([0-9]{1,3}\.){3}[0-9]{1,3}" "$MOCKUP"  | sort -u | grep -v '0\.\0\.0\.0\|127\.0\|255\.255')

for IPv4_ADDRESS in $IPv4_ADDRESSES; do
    echo -e "\tcleaning IPv4_ADDRESS: $IPv4_ADDRESS"
    grep -lEr "$IPv4_ADDRESS" "$MOCKUP" | xargs sed -i 's/'"${IPv4_ADDRESS}"'/127.0.1.'"${IPv4_ADDRESS##*.}"'/g' 2>/dev/null
done

IPv6_PREFIX="fe80::23:42"
IPv6_SEARCH_STRING='(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
IPv6_ADDRESSES=$(grep -rE "$IPv6_SEARCH_STRING" "$MOCKUP" | grep -vi "fingerprint" | grep -oE "$IPv6_SEARCH_STRING" | grep -v "^::$\|^[0:]*$\|^${MAC_PREFIX}\|^$IPv6_PREFIX" | sort -u)
for IPv6_ADDRESS in $IPv6_ADDRESSES; do
    echo -e "\tcleaning IPv6_ADDRESS: $IPv6_ADDRESS"
    grep -lEr "$IPv6_ADDRESS" "$MOCKUP" | xargs sed -i 's/'"${IPv6_ADDRESS}"'/'${IPv6_PREFIX}':'"${IPv6_ADDRESS##*:}"'/g' 2>/dev/null

    #   grep -ir ${IPv6_ADDRESS%%:*} $MOCKUP
done

# try cleaning leftover usernames from log
# admindcn
LOG_USER_NAMES=$(grep -R "logged in using \|Session open (user:\|Unable to log in for\|Invalid user " "$MOCKUP" | sed 's/.*logged in using \(.*\), .*/\1/g' | sed 's/.*Session open .user:\(.*\), ip.*/\1/g' | sed 's/.*\(Unable to log in for\|Invalid user\) \(.*\) from .*/\2/g' | sort -u | grep -v "^MOCKUP\|%1\|Description")
for LOG_USER in $LOG_USER_NAMES; do
    [[ "$LOG_USER" =~ Administrator|Admin|admin ]] && continue
    echo -e "\tcleaning LOG User: $LOG_USER"
    grep -lr "${LOG_USER}" "$MOCKUP" | xargs sed -i 's/'"${LOG_USER}"'/'${MOCKUP_USERNAME}'/g' 2>/dev/null
    grep -lr "\"${LOG_USER}\"," "$MOCKUP" | xargs sed -i 's/"'"${LOG_USER}"'",/"'"${MOCKUP_USERNAME}"'",/g' 2>/dev/null
done


echo "Leftovers $MOCKUP SORT:"
{
for PROPERTY in "${PROPERTIES_TO_SANITIZE[@]}"; do
    grep -ihr "${PROPERTY}\":" "${MOCKUP}" | grep -v "MOCKUP\|{$\|egistry\|OData-Version\|odata.context\|null\,*$\|: \"\"\,*$\|: \"N/*A\",*$\|RedfishVersion";
done;
} | sed 's/^[[:space:]]*//g' | sort -u | grep --color "$(printf -- '%s\n' "${PROPERTIES_TO_SANITIZE[@]} ipv6 Serial")"

# EOF
