#!/usr/bin/env python3
"""
Dell Unity / Unisphere REST API mock server for Aria Management Pack Builder testing.

Version: v2-https - MPB source-update auth compatibility fix with HTTPS/self-signed TLS support.

Purpose
-------
This is a local mock/emulator for validating MPB source connections, collection
queries, field selection, object relationships, pagination, action POST flows,
error handling, uploads/downloads, and metric query handling when a licensed
UnityVSA is not available.

It is not a Dell product, it does not implement storage behaviour, and it should
not be used to validate destructive operations or production automation logic.

Run HTTPS with an automatically generated self-signed certificate:
    python unity_mpb_mock_api_https.py --host 0.0.0.0 --port 8443

Run HTTPS with a provided certificate/key:
    python unity_mpb_mock_api_https.py --host 0.0.0.0 --port 8443 --ssl-cert unity.crt --ssl-key unity.key

Run plain HTTP only, for legacy local testing:
    python unity_mpb_mock_api_https.py --http --host 0.0.0.0 --port 8080

Example:
    curl -k -u admin:Password123! -H "X-EMC-REST-CLIENT: true" \
      "https://127.0.0.1:8443/api/types/system/instances?fields=id,name,model,serialNumber,softwareVersion,health&compact=true"
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

# --------------------------------------------------------------------------------------
# Mock data helpers
# --------------------------------------------------------------------------------------

SYSTEM_UUID = "9ED00875-29E3-B680-985F-5E31C5932C27"
CSRF_TOKEN = "unity-mock-csrf-token"
SESSION_COOKIE = "mod_sec_emc=unity-mock-session; Path=/; HttpOnly"
TGC_COOKIE = "TGC=unity-mock-tgc; Path=/; HttpOnly"
API_VERSION = "5.5"
EARLIEST_API_VERSION = "4.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_past(minutes: int = 0, days: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes, days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ref(resource_type: str, resource_id: str, name: Optional[str] = None) -> Dict[str, Any]:
    value: Dict[str, Any] = {"id": resource_id}
    if name is not None:
        value["name"] = name
    value["resource"] = resource_type
    return value


def health(value: int = 5, text: str = "The component is operating normally.") -> Dict[str, Any]:
    severity = {
        0: "UNKNOWN",
        5: "OK",
        7: "OK_BUT",
        10: "DEGRADED",
        15: "MINOR",
        20: "MAJOR",
        25: "CRITICAL",
        30: "NON_RECOVERABLE",
    }.get(value, "OK")
    return {
        "value": value,
        "description": severity,
        "descriptions": [text],
        "resolution": "No action is required." if value <= 7 else "Review component health and related alerts.",
    }


def mib(value: int) -> int:
    return value * 1024 * 1024


def gib(value: int) -> int:
    return value * 1024 * 1024 * 1024


def tib(value: int) -> int:
    return value * 1024 * 1024 * 1024 * 1024


# Resource name aliases seen in examples, scripts, and older collections.
RESOURCE_ALIASES = {
    "ethPort": "ethernetPort",
    "ethport": "ethernetPort",
    "ethernetport": "ethernetPort",
    "storageinstance": "storageResource",
    "storageinstances": "storageResource",
    "filesystem": "filesystem",
    "fileSystem": "filesystem",
    "lun": "lun",
}

# Actions that usually return data rather than 204 No Content.
ACTION_OUTPUTS = {
    "ping",
    "traceroute",
    "recommendforinterface",
    "recommendforaggregation",
    "verify",
    "verifyconnection",
    "retrievenonce",
    "getaces",
    "listavailabledisks",
    "listavailabledisks",
    "getdefaultstorageresourceoptions",
    "validate",
    "test",
}

# Broad resource catalogue. It is not intended to be exhaustive schema validation; it is used
# to make /api/types browse-style responses useful and to seed generic objects for MPB tests.
RESOURCE_CATEGORIES: Dict[str, List[str]] = {
    "network": [
        "cifsServer", "dnsServer", "fileDNSServer", "fileInterface", "fileKerberosServer",
        "fileLDAPServer", "fileNDMPServer", "fileNISServer", "fsnPort", "ftpServer", "ipInterface",
        "ipPort", "iscsiNode", "iscsiPortal", "iscsiSettings", "linkAggregation", "mgmtInterface",
        "mgmtInterfaceSettings", "nasServer", "nfsServer", "preferredInterfaceSettings", "route",
        "smtpServer", "tenant", "urServer", "virusChecker", "vlanInfo", "vmwareNasPEServer",
    ],
    "events_alerts": ["alert", "alertConfig", "alertConfigSNMPTarget", "alertEmailConfig", "event"],
    "jobs": ["job"],
    "storage": [
        "capabilityProfile", "cifsShare", "consistencyGroup", "disk", "diskGroup", "filesystem",
        "host", "hostGroup", "hostInitiator", "hostIPPort", "hostLUN", "lun", "nasServer",
        "nfsShare", "pool", "poolUnit", "snap", "snapshotSchedule", "storageResource",
        "storageTier", "vmwareDatastore", "vmwareNasPEServer", "vvolDatastore", "vvol",
    ],
    "environment": [
        "battery", "dae", "dpe", "enclosure", "ethernetPort", "fan", "fcPort", "ioModule",
        "powerSupply", "sasPort", "ssd", "storageProcessor", "uncPort",
    ],
    "system": [
        "basicSystemInfo", "certificate", "dnsServer", "encryption", "feature", "installedSoftwareVersion",
        "license", "loginSessionInfo", "ntpServer", "remoteSyslog", "securitySettings", "serviceContract",
        "supportProxy", "supportService", "system", "systemLimit", "time", "upgradeSession",
    ],
    "metrics": [
        "metric", "metricCollection", "metricHistoricalQuery", "metricQueryResult", "metricRealTimeQuery",
        "metricService", "metricValue",
    ],
    "remote_protection": [
        "importSession", "moveSession", "remoteSystem", "replicationSession", "snap", "snapshotSchedule",
        "syncReplicationManagementPort", "thinClone",
    ],
    "users_security": ["ldapServer", "role", "roleMapping", "user", "x509Certificate"],
}

ALL_KNOWN_RESOURCES = sorted({r for values in RESOURCE_CATEGORIES.values() for r in values})

# Operations metadata. In lenient mode it is informational; in strict-operations mode it is enforced.
DEFAULT_OPERATIONS = {"collection", "instance", "create", "delete", "modify", "action"}
READONLY_RESOURCES = {
    "basicSystemInfo", "disk", "dae", "dpe", "enclosure", "ethernetPort", "fcPort", "fan",
    "ioModule", "powerSupply", "sasPort", "ssd", "storageProcessor", "vlanInfo", "metric",
    "metricCollection", "metricQueryResult", "metricValue", "event", "systemLimit",
}


# --------------------------------------------------------------------------------------
# Seed database
# --------------------------------------------------------------------------------------


def seed_database() -> Dict[str, List[Dict[str, Any]]]:
    db: Dict[str, List[Dict[str, Any]]] = {}

    db["basicSystemInfo"] = [{
        "id": "0",
        "name": "unityvsa-mock-01",
        "model": "UnityVSA",
        "softwareVersion": "5.1.2.0.5.007",
        "apiVersion": API_VERSION,
        "earliestAPIVersion": EARLIEST_API_VERSION,
    }]

    db["loginSessionInfo"] = [{
        "id": "admin",
        "user": ref("user", "user_admin", "admin"),
        "roles": [ref("role", "administrator", "Administrator")],
        "idleTimeout": 3600,
        "isPasswordChangeRequired": False,
    }]

    db["role"] = [
        {"id": "administrator", "name": "Administrator", "description": "Full administrative access."},
        {"id": "storageadmin", "name": "Storage Administrator", "description": "Storage administration access."},
        {"id": "operator", "name": "Operator", "description": "Read-only/operator access."},
    ]

    db["user"] = [
        {"id": "user_admin", "name": "admin", "role": ref("role", "administrator", "Administrator"), "isDefault": True},
        {"id": "user_mpb", "name": "mpbsvc", "role": ref("role", "operator", "Operator"), "isDefault": False},
    ]

    db["system"] = [{
        "id": "0",
        "name": "unityvsa-mock-01",
        "model": "UnityVSA",
        "serialNumber": SYSTEM_UUID,
        "uuid": SYSTEM_UUID,
        "uuidBase": 42,
        "softwareVersion": "5.1.2.0.5.007",
        "internalModel": "UnityVSA 2Core",
        "platform": "UnityVSA",
        "isAllFlash": True,
        "macAddress": "00:50:56:9e:dc:01",
        "isEULAAccepted": True,
        "isUpgradeComplete": True,
        "isAutoFailbackEnabled": True,
        "isRemoteSysInterfaceAutoPair": True,
        "currentPower": 280,
        "avgPower": 250,
        "health": health(),
        "supportedUpgradeModels": [9, 10],
    }]

    db["installedSoftwareVersion"] = [{
        "id": "Unity OE 5.1.2",
        "version": "5.1.2.0.5.007",
        "releaseDate": "2022-11-01T00:00:00.000Z",
        "isActive": True,
    }]

    db["license"] = [{
        "id": "lic_unityvsa_ce",
        "name": "UnityVSA Community Edition 4TB",
        "productLine": 1,
        "licenseType": "Community",
        "capacity": 4,
        "unitOfMeasure": 4,
        "isInstalled": True,
        "expirationTime": None,
    }]

    db["feature"] = [
        {"id": "feature_unityvsa", "name": "UnityVSA", "state": 2, "reason": None},
        {"id": "feature_replication", "name": "Replication", "state": 2, "reason": None},
        {"id": "feature_compression", "name": "Compression", "state": 2, "reason": None},
    ]

    db["storageProcessor"] = [
        {"id": "spa", "name": "SP A", "model": 9, "slotNumber": 0, "health": health(), "operationalStatus": [2], "parentDpe": ref("dpe", "dpe", "DPE")},
        {"id": "spb", "name": "SP B", "model": 9, "slotNumber": 1, "health": health(), "operationalStatus": [2], "parentDpe": ref("dpe", "dpe", "DPE")},
    ]

    db["dpe"] = [{"id": "dpe", "name": "Disk Processor Enclosure", "health": health(), "model": 100, "slotNumber": 0}]
    db["dae"] = [{"id": "dae_0", "name": "Virtual DAE 0", "health": health(), "model": 100, "slotNumber": 0}]
    db["enclosure"] = [db["dpe"][0], db["dae"][0]]

    db["pool"] = [
        {
            "id": "pool_1", "name": "Pool_01", "description": "Primary dynamic all-flash pool", "type": 2,
            "poolType": 10, "raidType": 1, "state": 2, "health": health(),
            "sizeTotal": tib(4), "sizeUsed": gib(1260), "sizeFree": tib(4) - gib(1260),
            "sizeSubscribed": tib(6), "sizePreallocated": gib(256), "percentFullThreshold": 85,
            "tiers": [{"name": "Extreme Performance", "type": 10, "sizeTotal": tib(4), "sizeUsed": gib(1260)}],
            "isFASTCacheEnabled": False, "fastVPStatus": 1,
        },
        {
            "id": "pool_2", "name": "Pool_Archive", "description": "Secondary mock pool", "type": 2,
            "poolType": 100, "raidType": 10, "state": 2, "health": health(7, "Pool has a minor mock warning."),
            "sizeTotal": tib(8), "sizeUsed": tib(2), "sizeFree": tib(6), "sizeSubscribed": tib(9),
            "tiers": [{"name": "Capacity", "type": 30, "sizeTotal": tib(8), "sizeUsed": tib(2)}],
        },
    ]

    db["storageTier"] = [
        {"id": "tier_extreme", "name": "Extreme Performance", "tierType": 10, "diskTechnology": 8, "raidType": 1},
        {"id": "tier_capacity", "name": "Capacity", "tierType": 30, "diskTechnology": 2, "raidType": 10},
    ]

    disks: List[Dict[str, Any]] = []
    for i in range(12):
        pool_id = "pool_1" if i < 8 else "pool_2"
        disks.append({
            "id": f"dpe_disk_{i}", "name": f"DPE Disk {i}", "slotNumber": i, "size": gib(512),
            "rawSize": gib(512), "rpm": 0, "diskTechnology": 99 if i < 8 else 2,
            "diskType": 9 if i < 8 else 10, "tierType": 10 if i < 8 else 30,
            "pool": ref("pool", pool_id, "Pool_01" if pool_id == "pool_1" else "Pool_Archive"),
            "parentDpe": ref("dpe", "dpe", "DPE"), "health": health(), "isSED": False,
            "operationalStatus": [2],
        })
    db["disk"] = disks

    db["poolUnit"] = [
        {"id": "poolUnit_1", "name": "Virtual Disk Group 1", "pool": ref("pool", "pool_1", "Pool_01"), "type": 2, "health": health(), "sizeTotal": tib(4)},
        {"id": "poolUnit_2", "name": "Virtual Disk Group 2", "pool": ref("pool", "pool_2", "Pool_Archive"), "type": 2, "health": health(), "sizeTotal": tib(8)},
    ]

    db["storageResource"] = [
        {
            "id": "sv_1", "name": "LUN_App_01", "type": 8, "description": "Application LUN", "health": health(),
            "pool": ref("pool", "pool_1", "Pool_01"), "sizeTotal": gib(500), "sizeUsed": gib(220),
            "sizeAllocated": gib(230), "thinStatus": 1, "compressionStatus": 1, "dedupStatus": 1,
            "dataReductionStatus": 1, "dataReductionSizeSaved": gib(80), "dataReductionPercent": 26,
            "dataReductionRatio": 1.35, "hostAccess": [{"host": ref("host", "host_1", "esxi-01.lab.local"), "access": 3}],
            "snapCount": 1, "replicationType": 0,
        },
        {
            "id": "sv_2", "name": "LUN_DB_01", "type": 8, "description": "Database LUN", "health": health(),
            "pool": ref("pool", "pool_1", "Pool_01"), "sizeTotal": gib(1024), "sizeUsed": gib(640),
            "sizeAllocated": gib(650), "thinStatus": 1, "compressionStatus": 1, "dedupStatus": 0,
            "dataReductionStatus": 1, "dataReductionSizeSaved": gib(120), "dataReductionPercent": 15,
            "dataReductionRatio": 1.17, "hostAccess": [{"host": ref("host", "host_2", "esxi-02.lab.local"), "access": 3}],
            "snapCount": 0, "replicationType": 0,
        },
        {
            "id": "res_1", "name": "FS_Profiles_01", "type": 1, "description": "User profiles file system", "health": health(),
            "pool": ref("pool", "pool_1", "Pool_01"), "sizeTotal": gib(1024), "sizeUsed": gib(410),
            "sizeAllocated": gib(420), "thinStatus": 1, "filesystem": ref("filesystem", "fs_1", "FS_Profiles_01"),
            "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "snapCount": 2, "replicationType": 0,
        },
        {
            "id": "vmfs_1", "name": "VMFS_Datastore_01", "type": 4, "description": "VMware VMFS LUN", "health": health(),
            "pool": ref("pool", "pool_1", "Pool_01"), "sizeTotal": gib(2048), "sizeUsed": gib(900),
            "sizeAllocated": gib(920), "thinStatus": 1, "lun": ref("lun", "lun_vmfs_1", "VMFS_Datastore_01"),
        },
    ]

    db["lun"] = [
        {"id": "sv_1", "name": "LUN_App_01", "storageResource": ref("storageResource", "sv_1", "LUN_App_01"), "type": 2, "sizeTotal": gib(500), "wwn": "60:06:01:60:AA:BB:00:01", "defaultNode": 0, "currentNode": 0, "health": health()},
        {"id": "sv_2", "name": "LUN_DB_01", "storageResource": ref("storageResource", "sv_2", "LUN_DB_01"), "type": 2, "sizeTotal": gib(1024), "wwn": "60:06:01:60:AA:BB:00:02", "defaultNode": 1, "currentNode": 1, "health": health()},
        {"id": "lun_vmfs_1", "name": "VMFS_Datastore_01", "storageResource": ref("storageResource", "vmfs_1", "VMFS_Datastore_01"), "type": 3, "sizeTotal": gib(2048), "wwn": "60:06:01:60:AA:BB:00:03", "defaultNode": 0, "currentNode": 0, "health": health()},
    ]

    db["filesystem"] = [
        {"id": "fs_1", "name": "FS_Profiles_01", "storageResource": ref("storageResource", "res_1", "FS_Profiles_01"), "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "pool": ref("pool", "pool_1", "Pool_01"), "type": 1, "supportedProtocols": 2, "sizeTotal": gib(1024), "sizeUsed": gib(410), "isThinEnabled": True, "health": health()},
        {"id": "fs_2", "name": "FS_Engineering_01", "storageResource": ref("storageResource", "res_2", "FS_Engineering_01"), "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "pool": ref("pool", "pool_1", "Pool_01"), "type": 1, "supportedProtocols": 2, "sizeTotal": gib(512), "sizeUsed": gib(120), "isThinEnabled": True, "health": health()},
    ]

    db["consistencyGroup"] = [{
        "id": "cg_1", "name": "CG_App_01", "storageResources": [ref("storageResource", "sv_1", "LUN_App_01"), ref("storageResource", "sv_2", "LUN_DB_01")],
        "pool": ref("pool", "pool_1", "Pool_01"), "health": health(), "sizeTotal": gib(1524), "thinStatus": 65535,
    }]

    db["host"] = [
        {"id": "host_1", "name": "esxi-01.lab.local", "description": "Mock ESXi host", "type": 5, "osType": "VMware ESXi", "hostUUID": str(uuid.uuid4()), "health": health(), "operationalStatus": [2], "tenant": None, "fcHostInitiators": [], "iscsiHostInitiators": [ref("hostInitiator", "init_1", "iqn.1998-01.com.vmware:esxi-01")]},
        {"id": "host_2", "name": "esxi-02.lab.local", "description": "Mock ESXi host", "type": 5, "osType": "VMware ESXi", "hostUUID": str(uuid.uuid4()), "health": health(), "operationalStatus": [2], "tenant": None, "fcHostInitiators": [], "iscsiHostInitiators": [ref("hostInitiator", "init_2", "iqn.1998-01.com.vmware:esxi-02")]},
    ]
    db["hostGroup"] = [{"id": "hostGroup_1", "name": "ESXi_Cluster_01", "type": 1, "hosts": [ref("host", "host_1", "esxi-01.lab.local"), ref("host", "host_2", "esxi-02.lab.local")], "health": health()}]
    db["hostInitiator"] = [
        {"id": "init_1", "name": "iqn.1998-01.com.vmware:esxi-01", "type": 2, "host": ref("host", "host_1", "esxi-01.lab.local"), "paths": [{"target": ref("iscsiPortal", "if_iscsi_1"), "state": 1}], "isIgnored": False},
        {"id": "init_2", "name": "iqn.1998-01.com.vmware:esxi-02", "type": 2, "host": ref("host", "host_2", "esxi-02.lab.local"), "paths": [{"target": ref("iscsiPortal", "if_iscsi_2"), "state": 1}], "isIgnored": False},
    ]
    db["hostLUN"] = [
        {"id": "hl_1", "host": ref("host", "host_1", "esxi-01.lab.local"), "lun": ref("lun", "sv_1", "LUN_App_01"), "hlu": 1, "access": 3, "type": 1},
        {"id": "hl_2", "host": ref("host", "host_2", "esxi-02.lab.local"), "lun": ref("lun", "sv_2", "LUN_DB_01"), "hlu": 2, "access": 3, "type": 1},
    ]
    db["hostIPPort"] = [
        {"id": "host_ip_1", "host": ref("host", "host_1", "esxi-01.lab.local"), "address": "192.168.20.11", "type": 0},
        {"id": "host_ip_2", "host": ref("host", "host_2", "esxi-02.lab.local"), "address": "192.168.20.12", "type": 0},
    ]

    # Network / port data.
    ethernet_ports = []
    ip_ports = []
    for sp in ("spa", "spb"):
        sp_name = "SP A" if sp == "spa" else "SP B"
        for i in range(4):
            eid = f"{sp}_eth{i}"
            item = {
                "id": eid, "name": f"{sp_name} Ethernet Port {i}", "shortName": f"eth{i}",
                "storageProcessor": ref("storageProcessor", sp, sp_name), "macAddress": f"00:50:56:{'aa' if sp == 'spa' else 'bb'}:00:{i:02x}",
                "connectorType": 2, "currentSpeed": 10000, "requestedSpeed": 0, "supportedSpeeds": [1000, 10000],
                "mtuSize": 1500, "minMtuSize": 1280, "maxMtuSize": 9216, "isLinkUp": True,
                "isAggregated": False, "isIncludedInFSN": False, "health": health(), "operationalStatus": [32784],
            }
            ethernet_ports.append(item)
            ip_ports.append({k: item[k] for k in ("id", "name", "shortName", "macAddress", "isLinkUp", "isAggregated", "storageProcessor")})
            ip_ports[-1]["isEnslaved"] = False
    db["ethernetPort"] = ethernet_ports
    db["ethPort"] = ethernet_ports
    db["ipPort"] = ip_ports
    db["linkAggregation"] = [{
        "id": "la_spa_0", "name": "SP A Link Aggregation 0", "shortName": "LA 0",
        "primaryPort": ref("ethernetPort", "spa_eth2", "SP A Ethernet Port 2"),
        "ports": [ref("ethernetPort", "spa_eth2", "SP A Ethernet Port 2"), ref("ethernetPort", "spa_eth3", "SP A Ethernet Port 3")],
        "mtuSize": 9000, "macAddress": "00:50:56:aa:00:99", "isLinkUp": True,
        "isIncludedInFSN": False, "storageProcessor": ref("storageProcessor", "spa", "SP A"), "health": health(),
    }]
    db["fsnPort"] = [{
        "id": "fsn_spa_0", "name": "SP A FSN Port 0", "shortName": "FSN 0",
        "primaryPort": ref("ethernetPort", "spa_eth0", "SP A Ethernet Port 0"),
        "secondaryPorts": [ref("ethernetPort", "spa_eth1", "SP A Ethernet Port 1")],
        "activePort": ref("ethernetPort", "spa_eth0", "SP A Ethernet Port 0"),
        "mtuSize": 1500, "macAddress": "00:50:56:aa:00:fe", "isLinkUp": True,
        "storageProcessor": ref("storageProcessor", "spa", "SP A"), "health": health(),
    }]

    db["mgmtInterface"] = [{
        "id": "mgmt_1", "configMode": 1, "ethernetPort": ref("ethernetPort", "spa_eth0", "SP A Ethernet Port 0"),
        "protocolVersion": 4, "ipAddress": "192.168.10.50", "netmask": "255.255.255.0", "gateway": "192.168.10.1", "v6PrefixLength": None,
    }]
    db["mgmtInterfaceSettings"] = [{"id": "0", "v4ConfigMode": 1, "v6ConfigMode": 0}]
    db["ipInterface"] = [
        {"id": "if_mgmt_1", "ipPort": ref("ipPort", "spa_eth0", "SP A Ethernet Port 0"), "ipProtocolVersion": 4, "ipAddress": "192.168.10.50", "netmask": "255.255.255.0", "gateway": "192.168.10.1", "vlanId": 10, "type": 1},
        {"id": "if_iscsi_1", "ipPort": ref("ipPort", "spa_eth1", "SP A Ethernet Port 1"), "ipProtocolVersion": 4, "ipAddress": "192.168.30.101", "netmask": "255.255.255.0", "gateway": "192.168.30.1", "vlanId": 30, "type": 2},
        {"id": "if_file_1", "ipPort": ref("ipPort", "spa_eth2", "SP A Ethernet Port 2"), "ipProtocolVersion": 4, "ipAddress": "192.168.40.101", "netmask": "255.255.255.0", "gateway": "192.168.40.1", "vlanId": 40, "type": 3},
        {"id": "if_repl_1", "ipPort": ref("ipPort", "spa_eth3", "SP A Ethernet Port 3"), "ipProtocolVersion": 4, "ipAddress": "192.168.50.101", "netmask": "255.255.255.0", "gateway": "192.168.50.1", "vlanId": 50, "type": 4},
    ]
    db["route"] = [
        {"id": "route_1", "ipInterface": ref("ipInterface", "if_file_1"), "destination": "0.0.0.0", "netmask": "0.0.0.0", "gateway": "192.168.40.1", "health": health(), "isRouteToExternalServices": True},
        {"id": "route_2", "ipInterface": ref("ipInterface", "if_iscsi_1"), "destination": "192.168.30.0", "netmask": "255.255.255.0", "gateway": "192.168.30.1", "health": health(), "isRouteToExternalServices": False},
    ]
    db["vlanInfo"] = [
        {"id": "vlan_10", "vlanId": 10, "interfaces": [ref("ipInterface", "if_mgmt_1")], "tenant": None},
        {"id": "vlan_30", "vlanId": 30, "interfaces": [ref("ipInterface", "if_iscsi_1")], "tenant": None},
        {"id": "vlan_40", "vlanId": 40, "interfaces": [ref("ipInterface", "if_file_1")], "tenant": None},
    ]
    db["tenant"] = [{"id": "tenant_1", "name": "Tenant_A", "uuid": str(uuid.uuid4()), "vlans": [40, 41], "hosts": [ref("host", "host_1", "esxi-01.lab.local")]}]

    db["iscsiNode"] = [
        {"id": "iqn_spa_eth1", "name": "iqn.1992-04.com.emc:unityvsa.spa.eth1", "ethernetPort": ref("ethernetPort", "spa_eth1"), "alias": "SPA iSCSI Node 1"},
        {"id": "iqn_spb_eth1", "name": "iqn.1992-04.com.emc:unityvsa.spb.eth1", "ethernetPort": ref("ethernetPort", "spb_eth1"), "alias": "SPB iSCSI Node 1"},
    ]
    db["iscsiPortal"] = [
        {"id": "iscsiPortal_1", "ethernetPort": ref("ethernetPort", "spa_eth1"), "iscsiNode": ref("iscsiNode", "iqn_spa_eth1"), "ipAddress": "192.168.30.101", "netmask": "255.255.255.0", "gateway": "192.168.30.1", "vlanId": 30, "ipProtocolVersion": 4},
        {"id": "iscsiPortal_2", "ethernetPort": ref("ethernetPort", "spb_eth1"), "iscsiNode": ref("iscsiNode", "iqn_spb_eth1"), "ipAddress": "192.168.30.102", "netmask": "255.255.255.0", "gateway": "192.168.30.1", "vlanId": 30, "ipProtocolVersion": 4},
    ]
    db["iscsiSettings"] = [{"id": "0", "isForwardCHAPRequired": False, "reverseCHAPUserName": "", "forwardGlobalCHAPUserName": "", "iSNSServer": ""}]

    # NAS / file services.
    db["nasServer"] = [{
        "id": "nas_1", "name": "NAS_Prod_01", "health": health(), "homeSP": ref("storageProcessor", "spa", "SP A"),
        "currentSP": ref("storageProcessor", "spa", "SP A"), "pool": ref("pool", "pool_1", "Pool_01"),
        "sizeAllocated": gib(4), "tenant": None, "isReplicationEnabled": False, "isReplicationDestination": False,
        "isBackupOnly": False, "isMigrationDestination": False, "replicationType": 0, "syncReplicationType": 0,
        "currentUnixDirectoryService": 1, "isMultiProtocolEnabled": True, "allowUnmappedUser": True,
        "defaultUnixUser": "nobody", "defaultWindowsUser": "UNITY\\nobody", "isPacketReflectEnabled": True,
        "fileSpaceUsed": gib(530), "dataReductionSizeSaved": gib(75), "dataReductionPercent": 12, "dataReductionRatio": 1.14,
        "fileInterface": [ref("fileInterface", "fi_1", "NAS_Prod_01_if_1")],
        "filesystems": [ref("filesystem", "fs_1", "FS_Profiles_01"), ref("filesystem", "fs_2", "FS_Engineering_01")],
    }]
    db["fileInterface"] = [{
        "id": "fi_1", "name": "NAS_Prod_01_if_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"),
        "ipPort": ref("ipPort", "spa_eth2", "SP A Ethernet Port 2"), "health": health(), "ipAddress": "192.168.40.101",
        "ipProtocolVersion": 4, "netmask": "255.255.255.0", "gateway": "192.168.40.1", "vlanId": 40,
        "macAddress": "00:50:56:aa:40:01", "role": 0, "isPreferred": True, "replicationPolicy": 0, "isDisabled": False,
    }]
    db["fileDNSServer"] = [{"id": "filedns_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "addresses": ["192.168.10.10", "192.168.10.11"], "domain": "lab.local", "replicationPolicy": 0}]
    db["fileLDAPServer"] = [{"id": "fileldap_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "authority": "dc=lab,dc=local", "serverAddresses": ["192.168.10.20"], "portNumber": 636, "authenticationType": 1, "protocol": 1, "verifyServerCertificate": False, "bindDN": "cn=unity,ou=svc,dc=lab,dc=local", "schemeType": 2}]
    db["fileNISServer"] = [{"id": "filenis_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "addresses": ["192.168.10.21"], "domain": "lab.local", "replicationPolicy": 0}]
    db["fileNDMPServer"] = [{"id": "filendmp_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "username": "ndmp"}]
    db["fileKerberosServer"] = [{"id": "filekrb_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "realm": "LAB.LOCAL", "addresses": ["dc01.lab.local"], "portNumber": 88}]
    db["cifsServer"] = [{"id": "cifs_1", "name": "CIFS_PROD_01", "description": "Mock SMB server", "netbiosName": "CIFS-PROD-01", "domain": "LAB.LOCAL", "workgroup": "WORKGROUP", "isStandalone": False, "health": health(), "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "fileInterfaces": [ref("fileInterface", "fi_1", "NAS_Prod_01_if_1")], "smbcaSupported": True, "smbMultiChannelSupported": True, "smbProtocolVersions": ["2.1", "3.0", "3.1.1"]}]
    db["nfsServer"] = [{"id": "nfs_1", "hostName": "nas-prod-01.lab.local", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "fileInterfaces": [ref("fileInterface", "fi_1")], "nfsv3Enabled": True, "nfsv4Enabled": True, "isSecureEnabled": False, "kdcType": 1, "servicePrincipalName": "nfs/nas-prod-01.lab.local@LAB.LOCAL", "isExtendedCredentialsEnabled": True, "credentialsCacheTTL": "0:15:00.000"}]
    db["ftpServer"] = [{"id": "ftp_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "isFtpEnabled": False, "isSftpEnabled": True, "isCifsUserEnabled": True, "isUnixUserEnabled": True, "isAnonymousUserEnabled": False, "isHomedirLimitEnabled": True, "defaultHomedir": "/home", "welcomeMsg": "Unity mock FTP", "motd": "Mock server", "isAuditEnabled": False, "hostsList": [], "usersList": [], "groupsList": [], "isAllowHost": True, "isAllowUser": True, "isAllowGroup": True}]
    db["virusChecker"] = [{"id": "vc_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "isEnabled": False}]
    db["preferredInterfaceSettings"] = [{"id": "pis_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "productionIpV4": ref("fileInterface", "fi_1", "NAS_Prod_01_if_1"), "productionIpV6": None, "backupIpV4": None, "backupIpV6": None, "replicationPolicy": 0}]
    db["cifsShare"] = [{"id": "cifsShare_1", "name": "profiles$", "type": 1, "filesystem": ref("filesystem", "fs_1", "FS_Profiles_01"), "snap": None, "isReadOnly": False, "path": "/", "exportPaths": ["\\\\CIFS-PROD-01\\profiles$"], "description": "Profiles share", "creationTime": utc_past(days=10), "modifiedTime": utc_past(days=1), "isContinuousAvailabilityEnabled": True, "isEncryptionEnabled": False, "isACEEnabled": True, "isABEEnabled": True, "isBranchCacheEnabled": False, "isDFSEnabled": False, "offlineAvailability": 3, "defaultAccess": 2}]
    db["nfsShare"] = [{"id": "nfsShare_1", "name": "profiles_nfs", "type": 1, "filesystem": ref("filesystem", "fs_1", "FS_Profiles_01"), "path": "/", "exportPaths": ["192.168.40.101:/FS_Profiles_01"], "defaultAccess": 2, "minSecurity": 0, "noAccessHosts": [], "readOnlyHosts": [], "readWriteHosts": [ref("host", "host_1", "esxi-01.lab.local")], "rootAccessHosts": []}]
    db["vmwareNasPEServer"] = [{"id": "vmnpe_1", "nasServer": ref("nasServer", "nas_1", "NAS_Prod_01"), "fileInterfaces": [ref("fileInterface", "fi_1")], "boundVVolCount": 0}]

    db["dnsServer"] = [{"id": "0", "domain": "lab.local", "addresses": ["192.168.10.10", "192.168.10.11"], "origin": 1}]
    db["ntpServer"] = [{"id": "0", "addresses": ["192.168.10.12", "192.168.10.13"], "isNTPEnabled": True, "rebootPrivilege": 0}]
    db["smtpServer"] = [{"id": "smtp_1", "address": "smtp.lab.local:25", "username": "unity", "authType": 0, "sslMethod": 0, "isBypassProxyEnabled": False, "type": 0}]
    db["remoteSyslog"] = [{"id": "rsyslog_1", "address": "192.168.10.30:514", "protocol": 0, "facility": 1, "category": 0, "enabled": True, "severity": 5}]
    db["urServer"] = [{"id": "0", "address": "unisphere-central.lab.local"}]
    db["securitySettings"] = [{"id": "0", "tlsMode": 2, "sslStrength": 3}]
    db["supportProxy"] = [{"id": "0", "isEnabled": False, "protocol": 0, "address": "", "port": 8080, "username": ""}]
    db["supportService"] = [{"id": "0", "status": 0, "credentialStatus": 2, "remoteServiceType": 1, "isCloudManagementEnabled": False}]
    db["esrsParam"] = [{"id": "0", "status": 0, "level": 0, "configStatus": 1, "proxyStatus": 0}]
    db["encryption"] = [{"id": "0", "encryptionMode": 16, "encryptionStatus": 1, "encryptionPercentage": 0, "keyManagerBackupKeyStatus": 0, "kmipStatus": 0}]
    db["systemLimit"] = [{"id": "system_limits", "name": "UnityVSA mock limits", "maxPools": 16, "maxLuns": 1000, "maxHosts": 1024, "maxNasServers": 64, "maxFileSystems": 500}]
    db["time"] = [{"id": "0", "time": utc_now(), "timezone": "UTCp0000DublinLisbonLondon", "isNTPEnabled": True}]
    db["serviceContract"] = [{"id": "contract_1", "status": 0, "startDate": utc_past(days=180), "endDate": utc_past(days=-180), "serviceLevel": "Community"}]

    db["alert"] = [
        {"id": "alert_1", "timestamp": utc_past(minutes=45), "severity": 4, "component": {"id": "pool_2", "resource": "pool", "name": "Pool_Archive"}, "messageId": "14:604",
         "message": "Mock warning: pool usage is above the configured warning threshold.", "descriptionId": "desc_pool_warning", "description": "The pool has crossed a mock threshold.", "resolutionId": "res_pool_warning", "resolution": "Review capacity and thresholds.", "isAcknowledged": False, "duplicateCount": 0, "state": 1},
        {"id": "alert_2", "timestamp": utc_past(minutes=5), "severity": 6, "component": {"id": "spa_eth0", "resource": "ethernetPort", "name": "SP A Ethernet Port 0"}, "messageId": "14:200",
         "message": "Mock info: Ethernet port link is up.", "description": "The component is operating normally.", "resolution": "No action required.", "isAcknowledged": True, "duplicateCount": 0, "state": 2},
    ]
    db["alertConfig"] = [{"id": "0", "locale": 0, "isThresholdAlertsEnabled": True, "emailFromAddress": "unityvsa@lab.local", "minSNMPTrapNotificationSeverity": 4, "callHomeSuppressionStartTime": None, "callHomeSuppressionEndTime": None}]
    db["alertEmailConfig"] = [{"id": "email_1", "emailAddress": "storage-alerts@lab.local", "minNotificationSeverity": 4}]
    db["alertConfigSNMPTarget"] = [{"id": "snmp_1", "address": "192.168.10.31:162", "version": 2, "community": "public", "username": "", "authProto": 0, "privacyProto": 0}]
    db["event"] = [
        {"id": "event_1", "node": 0, "creationTime": utc_past(minutes=60), "severity": 5, "messageId": "13:100", "arguments": [], "message": "Mock event: user admin logged in.", "username": "admin", "category": 1, "source": "Management"},
        {"id": "event_2", "node": 1, "creationTime": utc_past(minutes=15), "severity": 6, "messageId": "13:101", "arguments": ["Pool_01"], "message": "Mock event: pool statistics collected.", "username": "N/A", "category": 0, "source": "Stats"},
    ]

    db["remoteSystem"] = [{"id": "remote_1", "name": "unity-remote-01", "address": "192.168.60.50", "type": 99, "connectionType": 1, "capabilities": [1], "health": health()}]
    db["replicationSession"] = [{"id": "repl_1", "name": "Repl_FS_Profiles", "source": ref("storageResource", "res_1", "FS_Profiles_01"), "destination": ref("storageResource", "remote_res_1", "FS_Profiles_01_DR"), "remoteSystem": ref("remoteSystem", "remote_1", "unity-remote-01"), "role": 0, "status": 2, "syncState": 2, "networkStatus": 2, "rpo": "1:00:00.000", "health": health()}]
    db["snap"] = [{"id": "snap_1", "name": "snap_LUN_App_01_daily", "storageResource": ref("storageResource", "sv_1", "LUN_App_01"), "creatorType": 1, "state": 2, "creationTime": utc_past(days=1), "expirationTime": utc_past(days=-6), "isReadOnly": True, "size": gib(20), "health": health()}]
    db["snapshotSchedule"] = [{"id": "sched_1", "name": "Daily", "type": 3, "rules": [{"daysOfWeek": [2,3,4,5,6], "hours": [22], "minutes": 0}], "isPaused": False}]
    db["importSession"] = [{"id": "import_1", "name": "Mock import session", "state": 50008, "stage": 2, "progressPct": 100, "health": health()}]
    db["moveSession"] = [{"id": "move_1", "name": "Mock move session", "state": 6, "status": 0, "priority": 3, "progressPct": 100, "source": ref("storageResource", "sv_1"), "destinationPool": ref("pool", "pool_2", "Pool_Archive")}]

    # Capacity/performance metrics.
    db["metric"] = [
        {"id": "metric_1", "path": "sp.*.cpu.summary.busyTicks", "type": 4, "description": "SP CPU busy ticks", "isHistoricalAvailable": True, "isRealtimeAvailable": True, "unitDisplayString": "ticks/sec"},
        {"id": "metric_2", "path": "sp.*.physical.disk.*.responseTime", "type": 4, "description": "Disk response time", "isHistoricalAvailable": True, "isRealtimeAvailable": True, "unitDisplayString": "ms"},
        {"id": "metric_3", "path": "sp.*.net.*.bytesIn", "type": 4, "description": "Network bytes in", "isHistoricalAvailable": True, "isRealtimeAvailable": True, "unitDisplayString": "B/s"},
        {"id": "metric_4", "path": "block.lun.*.totalIops", "type": 4, "description": "LUN total IOPS", "isHistoricalAvailable": True, "isRealtimeAvailable": True, "unitDisplayString": "IOPS"},
        {"id": "metric_5", "path": "pool.*.sizeUsed", "type": 5, "description": "Pool used capacity", "isHistoricalAvailable": True, "isRealtimeAvailable": False, "unitDisplayString": "bytes"},
    ]
    db["metricCollection"] = [{"id": "default", "interval": 60, "oldest": utc_past(days=7), "retention": 7}]
    db["metricService"] = [{"id": "0", "isHistoricalEnabled": True}]
    db["metricRealTimeQuery"] = []
    db["metricHistoricalQuery"] = []
    db["metricQueryResult"] = []
    db["metricValue"] = [
        {"id": "metricValue_1", "path": "block.lun.*.totalIops", "timestamp": utc_past(minutes=1), "values": {"sv_1": 120.4, "sv_2": 86.2}},
        {"id": "metricValue_2", "path": "sp.*.physical.disk.*.responseTime", "timestamp": utc_past(minutes=1), "values": {"dpe_disk_0": 0.8, "dpe_disk_1": 0.7}},
    ]

    db["job"] = [{"id": "N-1", "name": "Mock completed job", "description": "Seed job", "state": 4, "stateChangeTime": utc_past(minutes=10), "submitTime": utc_past(minutes=11), "startTime": utc_past(minutes=11), "endTime": utc_past(minutes=10), "elapsedTime": "0:01:00.000", "progressPct": 100, "tasks": [{"name": "Mock task", "state": 2}], "isJobCancelable": False, "isJobCancelled": False, "affectedResource": {"resource": "system", "id": "0", "name": "unityvsa-mock-01"}}]

    db["capabilityProfile"] = [{"id": "cp_1", "name": "Gold Thin", "serviceLevel": 3, "spaceEfficiencies": [1], "usageTags": ["Production"], "pool": ref("pool", "pool_1", "Pool_01")}]
    db["vmwareDatastore"] = [{"id": "vmds_1", "name": "VMFS_Datastore_01", "type": 1, "storageResource": ref("storageResource", "vmfs_1", "VMFS_Datastore_01"), "hostAccess": [ref("host", "host_1", "esxi-01.lab.local")], "health": health()}]
    db["vvolDatastore"] = [{"id": "vvolds_1", "name": "VVol_Datastore_01", "type": 0, "boundVVolCount": 0, "health": health()}]
    db["vvol"] = [{"id": "vvol_1", "name": "mock-config-vvol", "type": 0, "datastore": ref("vvolDatastore", "vvolds_1", "VVol_Datastore_01"), "sizeTotal": gib(1), "policyComplianceStatus": 0}]

    # Environment components.
    db["battery"] = [{"id": "bat_1", "name": "SPS 1", "health": health(), "operationalStatus": [2]}]
    db["fan"] = [{"id": "fan_1", "name": "Fan 1", "health": health(), "speed": 4800, "operationalStatus": [2]}]
    db["powerSupply"] = [{"id": "ps_1", "name": "Power Supply 1", "health": health(), "inputType": 1, "operationalStatus": [2]}]
    db["ioModule"] = [{"id": "iom_1", "name": "I/O Module 1", "storageProcessor": ref("storageProcessor", "spa", "SP A"), "health": health(), "operationalStatus": [2]}]
    db["fcPort"] = [{"id": "spa_fc0", "name": "SP A FC Port 0", "storageProcessor": ref("storageProcessor", "spa", "SP A"), "currentSpeed": 16000, "requestedSpeed": 0, "health": health(), "operationalStatus": [32784]}]
    db["sasPort"] = [{"id": "spa_sas0", "name": "SP A SAS Port 0", "storageProcessor": ref("storageProcessor", "spa", "SP A"), "currentSpeed": 12000, "health": health(), "operationalStatus": [32784]}]
    db["ssd"] = [{"id": "spa_ssd", "name": "SP A Internal SSD", "storageProcessor": ref("storageProcessor", "spa", "SP A"), "size": gib(128), "health": health()}]
    db["uncPort"] = [{"id": "unc_1", "name": "Uncommitted Port 1", "health": health(), "operationalStatus": [2]}]

    # Ensure all known resources are present, with generic seed objects for browseability.
    for resource in ALL_KNOWN_RESOURCES:
        db.setdefault(resource, [generic_object(resource, f"{resource}_1")])

    return db


# --------------------------------------------------------------------------------------
# Generic field/schema helpers
# --------------------------------------------------------------------------------------


def canonical_resource(resource: str) -> str:
    if not resource:
        return resource
    return RESOURCE_ALIASES.get(resource, RESOURCE_ALIASES.get(resource.lower(), resource))


def generic_object(resource: str, rid: Optional[str] = None) -> Dict[str, Any]:
    rid = rid or f"{resource}_{random.randint(1, 999)}"
    obj: Dict[str, Any] = {
        "id": rid,
        "name": rid.replace("_", " ").title(),
        "description": f"Synthetic {resource} object generated by the Unity mock API.",
        "health": health(),
        "creationTime": utc_past(days=1),
        "modifiedTime": utc_now(),
    }
    if "pool" in resource.lower():
        obj.update({"sizeTotal": tib(1), "sizeUsed": gib(128), "sizeFree": tib(1) - gib(128), "state": 2, "type": 2})
    if "port" in resource.lower() or "interface" in resource.lower():
        obj.update({"ipAddress": "192.168.100.10", "isLinkUp": True, "macAddress": "00:50:56:00:aa:bb", "mtuSize": 1500})
    if "metric" in resource.lower():
        obj.update({"path": f"mock.{resource}.*.value", "type": 4, "isHistoricalAvailable": True, "isRealtimeAvailable": True, "unitDisplayString": "count"})
    return obj


def synthetic_value(field_name: str, obj: Dict[str, Any], resource: str) -> Any:
    name = field_name.split(".")[-1]
    lower = name.lower()
    if lower == "id":
        return obj.get("id", f"{resource}_1")
    if lower == "name":
        return obj.get("name", f"{resource}_mock")
    if lower == "health":
        return health()
    if lower.startswith("is") or lower.startswith("has") or lower.endswith("enabled") or lower.endswith("supported"):
        return True
    if "time" in lower or "date" in lower:
        return utc_now()
    if "size" in lower or "capacity" in lower or "bytes" in lower:
        return gib(128)
    if "percent" in lower or lower.endswith("pct"):
        return 42
    if "ratio" in lower:
        return 1.25
    if "count" in lower or "number" in lower or "interval" in lower or "retention" in lower or "status" in lower or "state" in lower or "type" in lower or "severity" in lower:
        return 1
    if "address" in lower or lower.startswith("ip") or "gateway" in lower or "netmask" in lower:
        return "192.168.100.10" if "netmask" not in lower else "255.255.255.0"
    if lower.endswith("sp") or lower in {"pool", "nasserver", "host", "filesystem", "lun", "storageprocessor"}:
        return ref(lower, f"{lower}_1")
    if lower.endswith("s") and lower not in {"status"}:
        return []
    return f"mock-{name}"


def get_path(obj: Any, dotted: str) -> Any:
    if obj is None:
        return None
    current = obj
    for part in dotted.split("."):
        if isinstance(current, list):
            collected = []
            for item in current:
                val = get_path(item, part)
                if isinstance(val, list):
                    collected.extend(val)
                else:
                    collected.append(val)
            current = collected
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def set_nested(out: Dict[str, Any], dotted: str, value: Any, source_obj: Dict[str, Any]) -> None:
    parts = dotted.split(".")
    cursor = out
    for part in parts[:-1]:
        if part not in cursor or not isinstance(cursor[part], dict):
            # Preserve ref ids if present on the original object.
            original = source_obj.get(part)
            cursor[part] = {"id": original.get("id")} if isinstance(original, dict) and "id" in original else {}
        cursor = cursor[part]
    cursor[parts[-1]] = value


def split_csv_respecting_parens(value: str) -> List[str]:
    if not value:
        return []
    result, buf, depth, in_quote, quote_char = [], [], 0, False, ""
    for ch in value:
        if ch in {'"', "'"}:
            if not in_quote:
                in_quote, quote_char = True, ch
            elif quote_char == ch:
                in_quote = False
        elif not in_quote and ch == "(":
            depth += 1
        elif not in_quote and ch == ")" and depth > 0:
            depth -= 1
        if ch == "," and not in_quote and depth == 0:
            result.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        result.append("".join(buf).strip())
    return [x for x in result if x]


def parse_literal(value: str) -> Any:
    raw = value.strip()
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    low = raw.lower()
    # Prefer numeric 1/0 as integers for filter comparisons such as queryId eq 1;
    # true/false and yes/no forms are still accepted for Boolean-style inputs.
    if low in {"true", "t", "yes", "y"}:
        return True
    if low in {"false", "f", "no", "n"}:
        return False
    if low in {"null", "none"}:
        return None
    try:
        if "." in raw:
            return float(raw)
        return int(raw, 0)
    except ValueError:
        return raw


def safe_number(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except Exception:
        return 0.0


def eval_expression(expr: str, obj: Dict[str, Any]) -> Any:
    expr = expr.strip()

    # Conditional expression: attr eq value ? true_expr : false_expr
    if "?" in expr and ":" in expr:
        condition, rest = expr.split("?", 1)
        true_expr, false_expr = rest.split(":", 1)
        return eval_expression(true_expr, obj) if eval_filter(condition.strip(), obj) else eval_expression(false_expr, obj)

    m = re.match(r"@count\(([^)]+)\)", expr, re.I)
    if m:
        val = get_path(obj, m.group(1).strip())
        return len(val) if isinstance(val, list) else (1 if val is not None else 0)

    m = re.match(r"@sum\(([^)]+)\)", expr, re.I)
    if m:
        val = get_path(obj, m.group(1).strip())
        if isinstance(val, list):
            return sum(safe_number(x) for x in val)
        return safe_number(val)

    m = re.match(r"@concat\((.*)\)", expr, re.I)
    if m:
        parts = split_csv_respecting_parens(m.group(1))
        return "".join(str(get_path(obj, p) if re.match(r"^[A-Za-z_]", p) else parse_literal(p)) for p in parts)

    m = re.match(r"@concatList\((.*)\)", expr, re.I)
    if m:
        args = split_csv_respecting_parens(m.group(1))
        path = args[0] if args else ""
        sep = ","
        for a in args[1:]:
            if a.strip().lower().startswith("separator="):
                sep = str(parse_literal(a.split("=", 1)[1]))
        val = get_path(obj, path)
        if not isinstance(val, list):
            val = [] if val is None else [val]
        return sep.join(str(x) for x in val)

    m = re.match(r"@enum(?:String)?\(([^)]+)\)", expr, re.I)
    if m:
        val = get_path(obj, m.group(1).strip())
        enum_map = {5: "OK", 4: "WARNING", 3: "ERROR", 2: "CRITICAL", 1: "ALERT", 0: "UNKNOWN", 8: "OK"}
        if isinstance(val, list):
            return [enum_map.get(v, str(v)) for v in val]
        return enum_map.get(val, str(val))

    # Simple arithmetic using known object attributes only.
    if any(op in expr for op in ["+", "-", "*", "/"]):
        def repl(match: re.Match[str]) -> str:
            token = match.group(0)
            if token.lower() in {"and", "or", "eq", "ne", "gt", "ge", "lt", "le"}:
                return token
            val = get_path(obj, token)
            return str(safe_number(val))
        safe = re.sub(r"\b[A-Za-z_][A-Za-z0-9_.]*\b", repl, expr)
        if re.fullmatch(r"[0-9.\s+\-*/()]+", safe):
            try:
                return eval(safe, {"__builtins__": {}}, {})
            except Exception:
                return None

    if re.match(r"^[A-Za-z_]", expr):
        return get_path(obj, expr)
    return parse_literal(expr)


def eval_filter(expr: str, obj: Dict[str, Any]) -> bool:
    expr = unquote(expr).strip()
    if not expr:
        return True

    # Basic support for OR / AND with left-to-right evaluation.
    or_parts = re.split(r"\s+or\s+", expr, flags=re.I)
    if len(or_parts) > 1:
        return any(eval_filter(part, obj) for part in or_parts)
    and_parts = re.split(r"\s+and\s+", expr, flags=re.I)
    if len(and_parts) > 1:
        return all(eval_filter(part, obj) for part in and_parts)

    # IN expression.
    m = re.match(r"([A-Za-z_][\w.]*)\s+in\s*\((.*)\)", expr, re.I)
    if m:
        lhs = get_path(obj, m.group(1))
        values = [parse_literal(v) for v in split_csv_respecting_parens(m.group(2))]
        return str(lhs).lower() in {str(v).lower() for v in values}

    m = re.match(r"([A-Za-z_][\w.]*)\s+(eq|ne|gt|ge|lt|le|lk|=|!=|>|>=|<|<=)\s+(.+)", expr, re.I)
    if not m:
        # Treat a bare attribute name as truthiness.
        return bool(get_path(obj, expr))

    lhs_name, op, rhs_raw = m.groups()
    lhs = get_path(obj, lhs_name)
    rhs = parse_literal(rhs_raw)
    op = op.lower()

    if op in {"lk"}:
        pattern = str(rhs)
        pattern = pattern.replace("%25", "%")
        regex = re.escape(pattern).replace(r"\%", ".*").replace(r"\*", ".*").replace(r"\_", ".")
        return re.search(regex, str(lhs or ""), re.I) is not None

    if op in {"eq", "="}:
        return str(lhs).lower() == str(rhs).lower()
    if op in {"ne", "!="}:
        return str(lhs).lower() != str(rhs).lower()

    left_num = safe_number(lhs)
    right_num = safe_number(rhs)
    if op in {"gt", ">"}:
        return left_num > right_num
    if op in {"ge", ">="}:
        return left_num >= right_num
    if op in {"lt", "<"}:
        return left_num < right_num
    if op in {"le", "<="}:
        return left_num <= right_num
    return False


# --------------------------------------------------------------------------------------
# REST handler
# --------------------------------------------------------------------------------------


class UnityMockHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4 UnityMock"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "quiet", False):
            return
        super().log_message(fmt, *args)

    # ---------- low-level response helpers ----------
    @property
    def db(self) -> Dict[str, List[Dict[str, Any]]]:
        return self.server.db  # type: ignore[attr-defined]

    @property
    def args(self) -> argparse.Namespace:
        return self.server.args  # type: ignore[attr-defined]

    def _headers_common(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-cache, nostore, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Connection", "close")
        self.send_header("Content-Language", self._language())
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("EMC-CSRF-TOKEN", CSRF_TOKEN)
        self.send_header("Set-Cookie", SESSION_COOKIE)
        self.send_header("Set-Cookie", TGC_COOKIE)

    def _send_json(self, body: Any, status: int = 200) -> None:
        payload = json.dumps(body, indent=2, sort_keys=False).encode("utf-8")
        self._headers_common(status, f"application/json;version={API_VERSION};charset=UTF-8", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def _send_no_content(self, status: int = 204) -> None:
        self._headers_common(status, f"application/json;version={API_VERSION};charset=UTF-8", 0)
        self.end_headers()

    def _send_bytes(self, payload: bytes, content_type: str, filename: str = "unity-mock.bin", status: int = 200) -> None:
        self._headers_common(status, content_type, len(payload))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, message: str, error_code: int = 131149829) -> None:
        self._send_json({
            "error": {
                "errorCode": error_code,
                "httpStatusCode": status,
                "messages": [{self._language(): f"{message} (Mock Error Code:0x{error_code:x})"}],
                "created": utc_now(),
            }
        }, status=status)

    def _read_body(self) -> Any:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return {}
        return {"_rawLength": length, "_contentType": ctype}

    def _language(self) -> str:
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query)
        lang = q.get("language", [self.headers.get("Accept-Language", "en-US")])[0]
        return lang.replace("_", "-").split(",")[0] or "en-US"

    def _base_url(self) -> str:
        proto = "https" if getattr(self.server, "using_ssl", False) else "http"  # type: ignore[attr-defined]
        host = self.headers.get("Host", f"{self.args.host}:{self.args.port}")
        return f"{proto}://{host}"

    # ---------- auth ----------
    def _is_auth_exempt(self) -> bool:
        path = urlparse(self.path).path
        return path in {"/", "/api", "/api/types/basicSystemInfo/instances", "/apidocs/index.html"}

    def _check_auth(self) -> bool:
        if self.args.no_auth or self._is_auth_exempt():
            return True

        if self.headers.get("X-EMC-REST-CLIENT", "").lower() != "true":
            self._error(302, "X-EMC-REST-CLIENT header is missing or not set to true")
            return False

        client_ip = self.client_address[0] if self.client_address else "unknown"
        auth = self.headers.get("Authorization", "")
        cookie = self.headers.get("Cookie", "")

        # Unity returns session cookies after a successful authenticated GET. MPB sometimes
        # validates credentials on one request and then performs follow-up source-update
        # queries without replaying Basic auth or cookies. For mock/testing purposes, allow
        # follow-up GET requests from a client IP that has already authenticated once.
        # Use --strict-auth to force every non-exempt request to carry Basic auth or a
        # Unity mock session cookie.
        authenticated_clients = getattr(self.server, "authenticated_clients", set())
        has_mock_cookie = "mod_sec_emc=unity-mock-session" in cookie or "TGC=unity-mock-tgc" in cookie
        if not auth.startswith("Basic "):
            if not self.args.strict_auth and self.command == "GET" and client_ip in authenticated_clients:
                return True
            if has_mock_cookie:
                return True
            self._error(401, "Basic authentication header is required")
            return False

        try:
            user_pass = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            username, password = user_pass.split(":", 1)
        except Exception:
            self._error(401, "Invalid Basic authentication header")
            return False

        if username != self.args.username or password != self.args.password:
            self._error(403, "Invalid username or password")
            return False

        authenticated_clients.add(client_ip)
        self.server.authenticated_clients = authenticated_clients  # type: ignore[attr-defined]

        if self.command in {"POST", "DELETE"} and self.args.require_csrf:
            if self.headers.get("EMC-CSRF-TOKEN") != CSRF_TOKEN:
                self._error(403, "EMC-CSRF-TOKEN header is required for POST and DELETE")
                return False
        return True

    # ---------- request dispatch ----------
    def do_GET(self) -> None:
        if not self._check_auth():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        parts = [unquote(p) for p in path.strip("/").split("/") if p]

        if path == "/":
            self._send_json({"message": "Unity mock API", "api": "/api", "apidocs": "/apidocs/index.html"})
            return
        if path == "/apidocs/index.html":
            html = b"<html><body><h1>Unity Mock API</h1><p>Mock apidocs endpoint. Use /api/types/&lt;resource&gt;/instances.</p></body></html>"
            self._send_bytes(html, "text/html;charset=UTF-8", "index.html")
            return
        if path == "/api":
            self._send_json({
                "@base": self._base_url() + "/api",
                "updated": utc_now(),
                "links": [
                    {"rel": "self", "href": "/"},
                    {"rel": "types", "href": "/types"},
                    {"rel": "basicSystemInfo", "href": "/types/basicSystemInfo/instances"},
                ],
            })
            return
        if path == "/api/types":
            self._send_json(self._types_catalog())
            return
        if parts and parts[0] == "download":
            self._handle_download(parts)
            return
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "types" and parts[3] == "instances":
            self._collection_get(canonical_resource(parts[2]), parsed.query)
            return
        if len(parts) >= 4 and parts[0] == "api" and parts[1] == "instances":
            self._instance_get(canonical_resource(parts[2]), "/".join(parts[3:]), parsed.query)
            return
        self._error(404, f"No mock GET route for {path}")

    def do_POST(self) -> None:
        if not self._check_auth():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        parts = [unquote(p) for p in path.strip("/").split("/") if p]
        body = self._read_body()

        if parts and parts[0] == "upload" or path.startswith("/api/upload"):
            self._handle_upload(parts, body)
            return

        if path == "/api/types/loginSessionInfo/action/logout":
            self._send_no_content(204)
            return

        # POST /api/types/<resource>/instances
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "types" and parts[3] == "instances":
            self._collection_create(canonical_resource(parts[2]), body, parsed.query)
            return

        # POST /api/types/<resource>/action/<action>
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "types" and parts[3] == "action":
            self._class_action(canonical_resource(parts[2]), parts[4], body, parsed.query)
            return

        # POST /api/instances/<resource>/<id>/action/<action>
        if len(parts) >= 6 and parts[0] == "api" and parts[1] == "instances" and "action" in parts:
            resource = canonical_resource(parts[2])
            action_idx = parts.index("action")
            instance_id = "/".join(parts[3:action_idx])
            action = parts[action_idx + 1] if len(parts) > action_idx + 1 else ""
            self._instance_action(resource, instance_id, action, body, parsed.query)
            return

        self._error(404, f"No mock POST route for {path}")

    def do_DELETE(self) -> None:
        if not self._check_auth():
            return
        parsed = urlparse(self.path)
        parts = [unquote(p) for p in parsed.path.strip("/").split("/") if p]
        if len(parts) >= 4 and parts[0] == "api" and parts[1] == "instances":
            self._instance_delete(canonical_resource(parts[2]), "/".join(parts[3:]), parsed.query)
            return
        self._error(404, f"No mock DELETE route for {parsed.path}")

    # ---------- API implementations ----------
    def _types_catalog(self) -> Dict[str, Any]:
        entries = []
        for category, resources in RESOURCE_CATEGORIES.items():
            for r in resources:
                entries.append({
                    "content": {
                        "id": r,
                        "name": r,
                        "category": category,
                        "instancesUri": f"/api/types/{r}/instances",
                        "operations": sorted(list(DEFAULT_OPERATIONS - ({"create", "delete", "modify"} if r in READONLY_RESOURCES else set()))),
                    }
                })
        return {"@base": self._base_url() + "/api/types", "updated": utc_now(), "links": [{"rel": "self", "href": "/"}], "entryCount": len(entries), "entries": entries}

    def _query_params(self, query: str) -> Dict[str, str]:
        raw = parse_qs(query, keep_blank_values=True)
        return {k: v[-1] if v else "" for k, v in raw.items()}

    def _collection_get(self, resource: str, query: str) -> None:
        params = self._query_params(query)
        objects = deepcopy(self.db.get(resource, [generic_object(resource, f"{resource}_1")]))

        if "filter" in params and params["filter"]:
            objects = [o for o in objects if eval_filter(params["filter"], o)]

        if "groupby" in params and params["groupby"]:
            grouped = self._apply_groupby(resource, objects, params)
            self._send_json(grouped)
            return

        if "orderby" in params and params["orderby"]:
            objects = self._apply_orderby(objects, params["orderby"])

        total = len(objects)
        per_page = self._per_page(resource, params)
        page = max(1, int(params.get("page", "1") or "1"))
        start, end = (page - 1) * per_page, page * per_page
        paged = objects[start:end]

        fields = params.get("fields")
        compact = self._is_true(params.get("compact"))
        entries = []
        for obj in paged:
            try:
                content = self._select_fields(resource, obj, fields, collection=True)
            except KeyError as e:
                self._error(422, f"The attribute {e.args[0]} is not defined on resource type {resource}")
                return
            entry = {"content": content}
            if not compact:
                entry = {"@base": f"{self._base_url()}/api/instances/{resource}", "updated": utc_now(), "links": [{"rel": "self", "href": f"/{obj.get('id')}"}], **entry}
            entries.append(entry)

        response = {
            "@base": f"{self._base_url()}/api/types/{resource}/instances" + (f"?{query}" if query else ""),
            "updated": utc_now(),
            "links": self._paging_links(page, per_page, total, self._is_true(params.get("with_entrycount"))),
            "entries": entries,
        }
        if self._is_true(params.get("with_entrycount")):
            response["entryCount"] = total
        self._send_json(response)

    def _instance_get(self, resource: str, ident: str, query: str) -> None:
        params = self._query_params(query)
        obj = self._find_instance(resource, ident)
        if obj is None:
            self._error(404, f"The requested {resource} instance does not exist: {ident}")
            return
        fields = params.get("fields")
        try:
            content = self._select_fields(resource, obj, fields, collection=False)
        except KeyError as e:
            self._error(422, f"The attribute {e.args[0]} is not defined on resource type {resource}")
            return
        compact = self._is_true(params.get("compact"))
        if compact:
            self._send_json({"content": content})
            return
        self._send_json({
            "@base": f"{self._base_url()}/api/instances/{resource}",
            "updated": utc_now(),
            "links": [{"rel": "self", "href": f"/{obj.get('id')}"}],
            "content": content,
        })

    def _collection_create(self, resource: str, body: Any, query: str) -> None:
        if self.args.strict_operations and resource in READONLY_RESOURCES:
            self._error(405, f"Resource type {resource} does not support create")
            return
        params = self._query_params(query)
        if "timeout" in params:
            self._send_json(self._make_job(f"{resource}.create", body, resource), 202)
            return
        if resource == "metricRealTimeQuery":
            created = self._create_metric_query(body)
        elif resource == "metricHistoricalQuery":
            created = self._create_metric_query(body, historical=True)
        elif resource == "job":
            created = self._make_job("batch", body, "job")
        else:
            created_id = body.get("id") if isinstance(body, dict) else None
            created = deepcopy(body) if isinstance(body, dict) else {}
            created["id"] = created_id or self._next_id(resource)
            created.setdefault("name", created["id"])
            created.setdefault("health", health())
            self.db.setdefault(resource, []).append(created)
        self._send_json({
            "@base": f"{self._base_url()}/api/instances/{resource}",
            "updated": utc_now(),
            "links": [{"rel": "self", "href": f"/{created.get('id')}"}],
            "content": {"id": created.get("id")},
        }, 201)

    def _instance_delete(self, resource: str, ident: str, query: str) -> None:
        if self.args.strict_operations and resource in READONLY_RESOURCES:
            self._error(405, f"Resource type {resource} does not support delete")
            return
        params = self._query_params(query)
        obj = self._find_instance(resource, ident)
        if obj is None:
            self._error(404, f"The requested {resource} instance does not exist: {ident}")
            return
        if "timeout" in params:
            self._send_json(self._make_job(f"{resource}.delete", {}, resource, obj.get("id")), 202)
            return
        self.db[resource] = [x for x in self.db.get(resource, []) if x.get("id") != obj.get("id")]
        self._send_no_content(204)

    def _class_action(self, resource: str, action: str, body: Any, query: str) -> None:
        action_l = action.lower()
        params = self._query_params(query)
        if "timeout" in params:
            self._send_json(self._make_job(f"{resource}.{action}", body, resource), 202)
            return
        if resource == "metricService" and action_l == "modify":
            for obj in self.db.get("metricService", []):
                if isinstance(body, dict):
                    obj.update(body)
            self._send_no_content(204)
            return
        if action_l in ACTION_OUTPUTS:
            self._send_json(self._action_output(resource, action, body))
            return
        self._send_no_content(204)

    def _instance_action(self, resource: str, ident: str, action: str, body: Any, query: str) -> None:
        action_l = action.lower()
        params = self._query_params(query)
        obj = self._find_instance(resource, ident)
        if obj is None and not ident.startswith("name:"):
            self._error(404, f"The requested {resource} instance does not exist: {ident}")
            return
        if "timeout" in params:
            self._send_json(self._make_job(f"{resource}.{action}", body, resource, obj.get("id") if obj else None), 202)
            return
        if action_l == "modify":
            if obj is not None and isinstance(body, dict):
                obj.update({k: v for k, v in body.items() if not k.startswith("_")})
            self._send_no_content(204)
            return
        if action_l in {"cancel", "testucalert", "testemailalert", "testuialert", "testsnmpalert", "generateusermappingsreport", "updateusermappings", "refreshconfiguration", "failback", "pause", "resume", "sync", "verifycredentials"}:
            self._send_no_content(204)
            return
        if action_l in ACTION_OUTPUTS:
            self._send_json(self._action_output(resource, action, body, obj))
            return
        self._send_no_content(204)

    # ---------- action helpers ----------
    def _action_output(self, resource: str, action: str, body: Any, obj: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        action_l = action.lower()
        content: Dict[str, Any]
        if action_l == "ping":
            destination = body.get("destination", "127.0.0.1") if isinstance(body, dict) else "127.0.0.1"
            content = {"result": {"destination": destination, "status": 0, "packetTransmitted": 4, "packetReceived": 4, "packetLoss": 0, "roundTripTime": 2}}
        elif action_l == "traceroute":
            destination = body.get("destination", "127.0.0.1") if isinstance(body, dict) else "127.0.0.1"
            content = {"result": [{"hop": 1, "address": "192.168.10.1", "time": 1}, {"hop": 2, "address": destination, "time": 2}]}
        elif action_l == "recommendforinterface":
            ports = [ref("ipPort", p["id"], p.get("name")) for p in self.db.get("ipPort", [])[:3]]
            content = {"recommendedPorts": ports, "recommendations": ports}
        elif action_l == "recommendforaggregation":
            ports = [ref("ethernetPort", p["id"], p.get("name")) for p in self.db.get("ethernetPort", [])[:2]]
            content = {"recommendedPorts": ports, "recommendations": ports}
        elif action_l in {"verify", "verifyconnection", "validate", "test"}:
            content = {"isValid": True, "result": {"status": 0, "message": f"Mock {action} succeeded for {resource}."}}
        elif action_l == "retrievenonce":
            content = {"nonce": random.randint(100000, 999999)}
        elif action_l == "getaces":
            content = {"aces": [{"sid": "S-1-5-32-544", "name": "BUILTIN\\Administrators", "accessLevel": 4, "accessType": 1}]}
        elif action_l in {"listavailabledisks", "listavailabledisks"}:
            content = {"disks": [ref("disk", d["id"], d.get("name")) for d in self.db.get("disk", [])]}
        else:
            content = {"result": {"status": 0, "message": f"Mock output for {resource}.{action}"}}
        return {"@base": f"{self._base_url()}/api/types/{resource}/action/{action}", "updated": utc_now(), "links": [{"rel": "self", "href": "/"}], "content": content}

    # ---------- uploads/downloads ----------
    def _handle_download(self, parts: List[str]) -> None:
        path = "/".join(parts)
        if "x509Certificate" in path:
            payload = b"-----BEGIN CERTIFICATE-----\nMIIDUNITYMOCKCERTIFICATE==\n-----END CERTIFICATE-----\n"
            self._send_bytes(payload, "application/x-pem-file", "unity-mock-cert.pem")
        elif "encryption" in path or "serviceInfo" in path or "configCapture" in path:
            self._send_bytes(b"PK\x03\x04UNITY-MOCK-ZIP", "application/zip", "unity-mock.zip")
        else:
            self._send_bytes(b"# Unity mock NAS/server configuration file\n", "text/plain", "unity-mock.txt")

    def _handle_upload(self, parts: List[str], body: Any) -> None:
        upload_id = self._next_id("upload")
        self._send_json({"@base": self._base_url() + "/api/upload", "updated": utc_now(), "links": [{"rel": "self", "href": f"/{upload_id}"}], "content": {"id": upload_id, "status": "uploaded", "bytesReceived": body.get("_rawLength", 0) if isinstance(body, dict) else 0}}, 201)

    # ---------- data selection / query helpers ----------
    def _select_fields(self, resource: str, obj: Dict[str, Any], fields: Optional[str], collection: bool) -> Dict[str, Any]:
        if not fields:
            return {"id": obj.get("id")} if collection else deepcopy(obj)
        output: Dict[str, Any] = {}
        requested = split_csv_respecting_parens(fields)
        if "id" not in [f.split("::", 1)[0].strip() for f in requested]:
            requested.append("id")
        for item in requested:
            if "::" in item:
                name, expr = item.split("::", 1)
                output[name.strip()] = eval_expression(expr, obj)
                continue
            field = item.strip()
            if not field:
                continue
            value = get_path(obj, field)
            if value is None and field not in obj and self.args.strict_fields:
                raise KeyError(field)
            if value is None and not self.args.strict_fields:
                value = synthetic_value(field, obj, resource)
            set_nested(output, field, deepcopy(value), obj)
        return output

    def _find_instance(self, resource: str, ident: str) -> Optional[Dict[str, Any]]:
        ident = unquote(ident)
        if resource not in self.db:
            self.db[resource] = [generic_object(resource, ident.replace("name:", ""))]
        objects = self.db.get(resource, [])
        if ident.startswith("name:"):
            target = ident.split(":", 1)[1]
            for obj in objects:
                if str(obj.get("name", "")).lower() == target.lower():
                    return obj
            return None
        for obj in objects:
            if str(obj.get("id")) == ident:
                return obj
        return None

    def _next_id(self, resource: str) -> str:
        return f"{resource}_{len(self.db.get(resource, [])) + 1}"

    def _is_true(self, value: Optional[str]) -> bool:
        if value is None:
            return False
        return value == "" or str(value).lower() in {"true", "t", "yes", "y", "1"}

    def _per_page(self, resource: str, params: Dict[str, str]) -> int:
        default = 100 if resource == "event" else 5 if resource == "metricValue" else 2000
        try:
            per_page = int(params.get("per_page", default) or default)
        except ValueError:
            per_page = default
        upper = 250 if resource == "event" else 5 if resource == "metricValue" else 2000
        return max(1, min(per_page, upper))

    def _paging_links(self, page: int, per_page: int, total: int, with_last: bool) -> List[Dict[str, str]]:
        last_page = max(1, math.ceil(total / per_page))
        links = [{"rel": "self", "href": f"&page={page}"}]
        if page > 1:
            links.append({"rel": "first", "href": "&page=1"})
            links.append({"rel": "prev", "href": f"&page={page - 1}"})
        if page < last_page:
            links.append({"rel": "next", "href": f"&page={page + 1}"})
        if with_last:
            links.append({"rel": "last", "href": f"&page={last_page}"})
        return links

    def _apply_orderby(self, objects: List[Dict[str, Any]], orderby: str) -> List[Dict[str, Any]]:
        terms = split_csv_respecting_parens(orderby)
        result = objects
        for term in reversed(terms):
            bits = term.strip().split()
            field = bits[0]
            reverse = len(bits) > 1 and bits[1].lower() == "desc"
            result = sorted(result, key=lambda o: str(get_path(o, field) or ""), reverse=reverse)
        return result

    def _apply_groupby(self, resource: str, objects: List[Dict[str, Any]], params: Dict[str, str]) -> Dict[str, Any]:
        group_fields = split_csv_respecting_parens(params.get("groupby", ""))
        field_specs = split_csv_respecting_parens(params.get("fields", ""))
        groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
        for obj in objects:
            key = tuple(get_path(obj, f) for f in group_fields)
            groups.setdefault(key, []).append(obj)
        entries = []
        for key, members in groups.items():
            content: Dict[str, Any] = {}
            for idx, gf in enumerate(group_fields):
                content[gf] = key[idx]
            for spec in field_specs:
                if "::" in spec:
                    name, expr = spec.split("::", 1)
                    m = re.match(r"@sum\(([^)]+)\)", expr.strip(), re.I)
                    if m:
                        content[name.strip()] = sum(safe_number(get_path(x, m.group(1).strip())) for x in members)
            entries.append({"content": content})
        return {"@base": f"{self._base_url()}/api/types/{resource}/instances", "updated": utc_now(), "links": [{"rel": "self", "href": "&page=1"}], "entryCount": len(entries), "entries": entries}

    def _make_job(self, method: str, body: Any, resource: str, rid: Optional[str] = None) -> Dict[str, Any]:
        job_id = self._next_id("job").replace("job_", "N-")
        job = {
            "id": job_id,
            "name": "Common UIS job",
            "description": f"Mock async job for {method}",
            "state": 2,
            "stateChangeTime": utc_now(),
            "submitTime": utc_now(),
            "startTime": utc_now(),
            "estRemainTime": "00:01:00.000",
            "progressPct": 0,
            "methodName": method,
            "tasks": [{"name": "Mock task", "description": method, "state": 0, "parametersIn": json.dumps(body)}],
            "isJobCancelable": True,
            "isJobCancelled": False,
            "affectedResource": {"resource": resource, "id": rid or resource, "name": rid or resource},
        }
        self.db.setdefault("job", []).append(job)
        return job

    def _create_metric_query(self, body: Any, historical: bool = False) -> Dict[str, Any]:
        paths = body.get("paths", []) if isinstance(body, dict) else []
        interval = body.get("interval", 60) if isinstance(body, dict) else 60
        resource = "metricHistoricalQuery" if historical else "metricRealTimeQuery"
        query_id = str(len(self.db.get(resource, [])) + 1)
        obj = {"id": query_id, "paths": paths, "interval": interval, "expiration": utc_past(days=-1)}
        self.db.setdefault(resource, []).append(obj)
        # Create metricQueryResult rows.
        for path in paths or ["sp.*.cpu.summary.busyTicks"]:
            self.db.setdefault("metricQueryResult", []).append({
                "id": query_id,
                "queryId": query_id,
                "path": path,
                "timestamp": utc_now(),
                "values": {"spa": round(random.uniform(10, 50), 2), "spb": round(random.uniform(10, 50), 2)},
            })
        return obj


class UnityMockServer(ThreadingHTTPServer):
    daemon_threads = True


# --------------------------------------------------------------------------------------
# HTTPS / certificate helpers
# --------------------------------------------------------------------------------------


def _dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _split_cert_san_arg(values: Optional[List[str]]) -> Tuple[List[str], List[str]]:
    """Return (dns_names, ip_addresses) from repeated/comma-separated SAN args."""
    dns_names: List[str] = []
    ip_addresses: List[str] = []
    for raw in values or []:
        for item in str(raw).split(","):
            item = item.strip()
            if not item:
                continue
            lowered = item.lower()
            if lowered.startswith("dns:"):
                dns_names.append(item[4:].strip())
            elif lowered.startswith("ip:"):
                ip_addresses.append(item[3:].strip())
            elif _is_ip_address(item):
                ip_addresses.append(item)
            else:
                dns_names.append(item)
    return dns_names, ip_addresses


def _discover_default_alt_names(host: str, extra_sans: Optional[List[str]]) -> Tuple[List[str], List[str]]:
    dns_names = ["localhost"]
    ip_addresses = ["127.0.0.1", "::1"]

    host = (host or "").strip()
    if host and host not in {"0.0.0.0", "::", "[::]", "*"}:
        host = host.strip("[]")
        if _is_ip_address(host):
            ip_addresses.append(host)
        else:
            dns_names.append(host)

    for name in [socket.gethostname(), socket.getfqdn()]:
        if name and name.lower() not in {"localhost", "localhost.localdomain"}:
            dns_names.append(name)

    # Try to discover the primary outbound IP. This does not send traffic; it only asks
    # the OS which local source address it would use.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            if local_ip and _is_ip_address(local_ip):
                ip_addresses.append(local_ip)
    except Exception:
        pass

    extra_dns, extra_ips = _split_cert_san_arg(extra_sans)
    dns_names.extend(extra_dns)
    ip_addresses.extend(extra_ips)

    # Keep only valid IP SANs; OpenSSL fails hard on invalid IP entries.
    valid_ips = [ip for ip in ip_addresses if _is_ip_address(ip)]
    return _dedupe_preserve_order(dns_names), _dedupe_preserve_order(valid_ips)


def _openssl_config_text(common_name: str, dns_names: List[str], ip_addresses: List[str]) -> str:
    safe_cn = re.sub(r"[^A-Za-z0-9_. -]", "_", common_name or "unity-mock.local")[:64]
    lines = [
        "[req]",
        "distinguished_name = dn",
        "x509_extensions = v3_req",
        "prompt = no",
        "",
        "[dn]",
        f"CN = {safe_cn}",
        "",
        "[v3_req]",
        "basicConstraints = critical, CA:FALSE",
        "keyUsage = critical, digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth",
        "subjectAltName = @alt_names",
        "",
        "[alt_names]",
    ]
    for idx, name in enumerate(dns_names, start=1):
        lines.append(f"DNS.{idx} = {name}")
    for idx, ip_addr in enumerate(ip_addresses, start=1):
        lines.append(f"IP.{idx} = {ip_addr}")
    lines.append("")
    return "\n".join(lines)


def _generate_self_signed_with_openssl(
    cert_path: Path,
    key_path: Path,
    common_name: str,
    dns_names: List[str],
    ip_addresses: List[str],
    valid_days: int,
) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl executable was not found")

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    config_text = _openssl_config_text(common_name, dns_names, ip_addresses)
    with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as cfg:
        cfg.write(config_text)
        cfg_path = cfg.name

    try:
        cmd = [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            str(max(int(valid_days), 1)),
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-config",
            cfg_path,
            "-extensions",
            "v3_req",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "openssl certificate generation failed")
    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass


def _generate_self_signed_with_cryptography(
    cert_path: Path,
    key_path: Path,
    common_name: str,
    dns_names: List[str],
    ip_addresses: List[str],
    valid_days: int,
) -> None:
    # Optional fallback for environments without the openssl executable but with
    # the cryptography package installed.
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # type: ignore

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name or "unity-mock.local"),
    ])

    san_values: List[Any] = [x509.DNSName(name) for name in dns_names]
    san_values.extend(x509.IPAddress(ipaddress.ip_address(ip_addr)) for ip_addr in ip_addresses)

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=max(int(valid_days), 1)))
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass


def ensure_tls_certificate(args: argparse.Namespace) -> Tuple[str, str, bool, List[str], List[str]]:
    """
    Return (cert_path, key_path, generated_or_regenerated, dns_sans, ip_sans).

    If --ssl-cert/--ssl-key are provided, they are used as-is. Otherwise, a
    self-signed cert/key are generated or reused under --cert-dir.
    """
    if args.ssl_cert or args.ssl_key:
        if not (args.ssl_cert and args.ssl_key):
            raise SystemExit("--ssl-cert and --ssl-key must be supplied together")
        cert_path = Path(args.ssl_cert).expanduser()
        key_path = Path(args.ssl_key).expanduser()
        if not cert_path.exists():
            raise SystemExit(f"TLS certificate does not exist: {cert_path}")
        if not key_path.exists():
            raise SystemExit(f"TLS private key does not exist: {key_path}")
        dns_names, ip_addresses = _discover_default_alt_names(args.host, args.cert_san)
        return str(cert_path), str(key_path), False, dns_names, ip_addresses

    if args.no_generate_cert:
        raise SystemExit("HTTPS is enabled but no --ssl-cert/--ssl-key were supplied and --no-generate-cert was set")

    cert_dir = Path(args.cert_dir).expanduser()
    cert_path = cert_dir / "unity_mock_tls.crt"
    key_path = cert_dir / "unity_mock_tls.key"
    dns_names, ip_addresses = _discover_default_alt_names(args.host, args.cert_san)
    should_generate = args.regenerate_cert or not (cert_path.exists() and key_path.exists())
    if not should_generate:
        return str(cert_path), str(key_path), False, dns_names, ip_addresses

    try:
        _generate_self_signed_with_openssl(
            cert_path,
            key_path,
            args.cert_cn,
            dns_names,
            ip_addresses,
            args.cert_valid_days,
        )
    except Exception as openssl_error:
        try:
            _generate_self_signed_with_cryptography(
                cert_path,
                key_path,
                args.cert_cn,
                dns_names,
                ip_addresses,
                args.cert_valid_days,
            )
        except Exception as cryptography_error:
            raise SystemExit(
                "Could not generate a self-signed TLS certificate. Install openssl, "
                "install the Python cryptography package, or pass --ssl-cert/--ssl-key. "
                f"openssl error: {openssl_error}; cryptography error: {cryptography_error}"
            ) from cryptography_error

    return str(cert_path), str(key_path), True, dns_names, ip_addresses


def certificate_sha256_fingerprint(cert_path: str) -> str:
    try:
        pem = Path(cert_path).read_text(encoding="utf-8")
        der = ssl.PEM_cert_to_DER_cert(pem)
        digest = hashlib.sha256(der).hexdigest().upper()
        return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    except Exception:
        return "unavailable"


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dell Unity / Unisphere REST API mock for MPB testing")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=8080, help="Listen port. Use 443 or 8443 for Unity-like HTTPS testing.")
    parser.add_argument("--username", default="admin", help="Basic auth username")
    parser.add_argument("--password", default="Password123!", help="Basic auth password")
    parser.add_argument("--no-auth", action="store_true", help="Disable Basic/X-EMC-REST-CLIENT auth checks")
    parser.add_argument("--strict-auth", action="store_true", help="Require Basic auth or mock session cookies on every non-exempt request")
    parser.add_argument("--require-csrf", action="store_true", help="Require EMC-CSRF-TOKEN on POST and DELETE")
    parser.add_argument("--strict-fields", action="store_true", help="Return 422 for fields not present in mock object data")
    parser.add_argument("--strict-operations", action="store_true", help="Return 405 for create/delete/modify on read-only resources")
    parser.add_argument("--quiet", action="store_true", help="Suppress request logging")

    tls = parser.add_argument_group("HTTPS / TLS")
    tls.add_argument("--http", action="store_true", help="Run plain HTTP instead of HTTPS. HTTPS is the default.")
    tls.add_argument("--ssl-cert", help="PEM certificate for HTTPS. If omitted, a self-signed cert is generated/reused.")
    tls.add_argument("--ssl-key", help="PEM private key for HTTPS. Must be supplied with --ssl-cert.")
    tls.add_argument("--cert-dir", default="./unity_mock_certs", help="Directory for auto-generated TLS cert/key")
    tls.add_argument("--cert-cn", default="unity-mock.local", help="Common Name for auto-generated self-signed cert")
    tls.add_argument(
        "--cert-san",
        action="append",
        default=[],
        help=(
            "Extra certificate Subject Alternative Name. Repeat or comma-separate values. "
            "Examples: --cert-san 192.168.1.50 --cert-san DNS:unity-mock.lab.local"
        ),
    )
    tls.add_argument("--cert-valid-days", type=int, default=825, help="Validity period for generated cert")
    tls.add_argument("--regenerate-cert", action="store_true", help="Regenerate auto cert/key even if they already exist")
    tls.add_argument("--no-generate-cert", action="store_true", help="Require --ssl-cert/--ssl-key instead of generating a self-signed cert")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = UnityMockServer((args.host, args.port), UnityMockHandler)
    server.args = args  # type: ignore[attr-defined]
    server.db = seed_database()  # type: ignore[attr-defined]
    server.authenticated_clients = set()  # type: ignore[attr-defined]
    server.quiet = args.quiet  # type: ignore[attr-defined]
    server.using_ssl = False  # type: ignore[attr-defined]
    server.tls_cert_path = None  # type: ignore[attr-defined]
    server.tls_key_path = None  # type: ignore[attr-defined]

    if not args.http:
        cert_path, key_path, generated_cert, dns_sans, ip_sans = ensure_tls_certificate(args)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.using_ssl = True  # type: ignore[attr-defined]
        server.tls_cert_path = cert_path  # type: ignore[attr-defined]
        server.tls_key_path = key_path  # type: ignore[attr-defined]
        server.generated_cert = generated_cert  # type: ignore[attr-defined]
        server.tls_dns_sans = dns_sans  # type: ignore[attr-defined]
        server.tls_ip_sans = ip_sans  # type: ignore[attr-defined]

    scheme = "https" if server.using_ssl else "http"  # type: ignore[attr-defined]
    print(f"Unity mock API listening on {scheme}://{args.host}:{args.port}")
    if server.using_ssl:  # type: ignore[attr-defined]
        cert_path = server.tls_cert_path  # type: ignore[attr-defined]
        key_path = server.tls_key_path  # type: ignore[attr-defined]
        cert_state = "generated" if getattr(server, "generated_cert", False) else "reused/provided"
        print(f"HTTPS certificate ({cert_state}): {cert_path}")
        print(f"HTTPS private key: {key_path}")
        print(f"Certificate SHA256 fingerprint: {certificate_sha256_fingerprint(cert_path)}")
        print("Certificate SAN DNS names: " + ", ".join(getattr(server, "tls_dns_sans", []) or ["<none>"]))
        print("Certificate SAN IPs: " + ", ".join(getattr(server, "tls_ip_sans", []) or ["<none>"]))
        print("For curl with the generated self-signed cert, use -k or --cacert " + str(cert_path))
        print("For MPB, either disable certificate validation during mock testing or import/trust this certificate.")
    else:
        print("Plain HTTP mode enabled by --http. Use HTTPS mode for Unity-like testing.")
    print(f"Credentials: {args.username}:{args.password} | X-EMC-REST-CLIENT: true | CSRF: {CSRF_TOKEN}")
    print("Useful probes:")
    curl_insecure = " -k" if server.using_ssl else ""  # type: ignore[attr-defined]
    print(f"  curl{curl_insecure} {scheme}://127.0.0.1:{args.port}/api/types/basicSystemInfo/instances")
    print(f"  curl{curl_insecure} -u '{args.username}:{args.password}' -H 'X-EMC-REST-CLIENT: true' '{scheme}://127.0.0.1:{args.port}/api/types/system/instances?fields=id,name,model,serialNumber,health&compact=true'")
    print(f"  curl{curl_insecure} -u '{args.username}:{args.password}' -H 'X-EMC-REST-CLIENT: true' '{scheme}://127.0.0.1:{args.port}/api/types/storageResource/instances?fields=id,name,type,sizeTotal,pool.name,health&compact=true'")
    server.serve_forever()


if __name__ == "__main__":
    main()
