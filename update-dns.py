#!/usr/bin/python

import os
import sys
import argparse
import netsnmp
import json
import urllib, urllib2
from collections import defaultdict

__author__ = 'Ta Xuan Truong (truongtx8 AT gmail DOT com)'

# Configurable variables
router_ip		= "0.0.0.0"
router_snmp_ver	= 2
router_snmp_com	= "public"
router_if_name	= ["pp0.0", "pp0.1", "pp0.2"]

cflare_apikey	= ""
clfare_email    = ""
cflare_zone		= ""
cflare_dns_list = [["fpt", "pp0.2"], ["vtel", "pp0.1"], ["vnpt", "pp0.0"],
                   ["vn1", "pp0.0"], ["vn2", "pp0.1"], ["vn3", "pp0.2"]]

tmp_data_file   = "/dev/shm/update-dns.tmp"

# Global variables declare
cflare_rec      = defaultdict(defaultdict)
if_router       = defaultdict(defaultdict)
if_cached       = defaultdict(defaultdict)

# Custom arguments
arg_verbose     = False
arg_force       = False

def read_args():
    """read_args function
    
    Return
        True if success
        False if fail
    """
    
    try:
        index_count = 0
        for i in sys.argv:
            if (i == "--help") or (i == "-h"):
                print "This script is used to update DNS record for dynamic IP address."
                print "Request arguments:"
                print " --router or -r | router address"
                print ""
                print "Optional arguments:"
                print " --force or -f  | force update address"
                sys.exit(0)
            if (i == "--force") or (i == "-f"):
                global arg_force
                arg_force = True

            if (i == "--verbose") or (i == "-v"):
                global arg_verbose 
                arg_verbose = True
            
            if (i == "--router") or (i == "-r"):
                try:
                    global router_ip
                    router_ip = sys.argv[index_count + 1]
                except IndexError:
                    print "Router address is missing or incorrect"
                    sys.exit(2)
            
            if (i == "--community") or (i == "-c"):
                global router_snmp_com
                router_snmp_com = sys.argv[index_count + 1]
            
            if (i == "--apikey") or (i == "-a"):
                try:
                    global cflare_apikey
                    cflare_apikey = sys.argv[index_count + 1]
                except IndexError:
                    print "API key is missing or incorrect"
                    sys.exit(2)
            
            if (i == "--mail") or (i == "-m"):
                try:
                    global clfare_email
                    clfare_email = sys.argv[index_count + 1]
                except IndexError:
                    print "Email address is missing or incorrect"
                    sys.exit(2)
            if (i == "--zone") or (i == "-z"):
                try:
                    global cflare_zone
                    cflare_zone = sys.argv[index_count + 1]
                except IndexError:
                    print "Zone name is missing or incorrect"
                    sys.exit(2)
            
            index_count += 1    
        #print i
        return True
            
    except IndexError:
        #print "!! - "
        return False

def get_ip():
    """get_ip function
    
    1) Get IP addresses from router interfaces via SNMP
    2) Update IP addresses to if_router
    
    Returns:
        True if success
        False if fail
    """
    
	# Processes CLI arguments
    (snmpcmd) = process_cli()
	
	# Determines whether the device is accessible
    device_oid_id = get_sys_object_id(snmpcmd)
    
    if not device_oid_id:
        print ('ERROR: Cannot contact %s. Check connectivity or '
        'SNMP parameters') % (snmpcmd['ipaddress'])
        return False
    
    #do_mib_interfaces_mapping(snmpcmd)
    if_map = defaultdict(defaultdict)
 
    # Initial Index, Names and Addresses
    ifname_oid = '.1.3.6.1.2.1.31.1.1.1.1'
    ifname_results = do_snmpwalk(snmpcmd, ifname_oid)
    for oid, val in sorted(ifname_results.items()):
        last_octet = get_oid_last_octet(oid)
        #ifmap[last_octet]['name'] = val
        #print last_octet, val
        if_map[int(last_octet)]['index'] = int(last_octet)
        if_map[int(last_octet)]['name'] = val
        if_map[int(last_octet)]['address'] = '0.0.0.0'

    # Update the correct IP address
    ifindex_oid = '.1.3.6.1.2.1.4.20.1.2'
    ifindex_results = do_snmpwalk(snmpcmd, ifindex_oid)
    for oid, val in sorted(ifindex_results.items()):
        last_value = get_oid_last_value(oid, ifindex_oid)
        #print last_value, int(val)
        #print if_router.keys()
        if (int(val) == if_map[int(val)]['index']):
            if_map[int(val)]['address'] = last_value
    
    # Reindex to if_router dictionary
    index_count = 0
    for if_name in router_if_name:
        for key in if_map:
            #print if_map[key].get('name')
            if if_map[key].get('name') in if_name:
                if_router[index_count]['index'] = if_map[key]['index']
                if_router[index_count]['name'] = if_map[key]['name']
                if_router[index_count]['address'] = if_map[key]['address']
                break                
        index_count += 1
    
    if arg_verbose:
        for i in if_router:
            print " > %s: index: %s; if_name: %s; if_address: %s" % (i, if_router[i]['index'], if_router[i]['name'], if_router[i]['address'])
    
    return True

def load_ip(file_uri):
    """load_ip function
    
    1) Load IP addresses from temporary cache file; creat one if not available
    2) Update IP addresses to if_cached
    
    Returns:
        True if success
        False if fail
    """
    
    try:
        cache_file = open(file_uri)
        cache_file.seek(0)
        
        for line in cache_file:
            content = line.split(';')
            if_cached[int(content[0])]['index'] = int(content[0])
            if_cached[int(content[0])]['name'] = content[1]
            if_cached[int(content[0])]['address'] = content[2]
        if arg_verbose:
            for i in if_cached:
                print " > %s: index: %s; if_name: %s; if_address: %s" % (i, if_cached[i]['index'], if_cached[i]['name'], if_cached[i]['address'])
        return True
        
    except IOError:
        cache_file = open(file_uri, 'w+')
        index_count = 0
        for interface in router_if_name:
            cache_file.writelines([str(index_count), ";", interface, ";0.0.0.0;\n"])
            if_cached[index_count]['address'] = "0.0.0.0"
            index_count += 1
        
        if arg_verbose:
            print " > %s" % (cache_file)
        
        cache_file.close
        
        return False

def write_ip(file_uri):
    """load_ip function
    
    1) Update IP addresses from if_cached to cache file
    
    Returns:
        True if success
        False if fail
    """
    
    try:
        cache_file = open(file_uri, 'w+')
        index_count = 0
        for interface in router_if_name:
            cache_file.writelines([str(index_count), ";", interface, ";", if_router[index_count]['address'], ";\n"])
            index_count += 1

        if arg_verbose:
            print " > %s" % (cache_file)

        cache_file.close
        return True
        
    except IOError:
        return False
    
def clfare_index(zone, dns_list, if_list):
    """clfare_index function
    
    1) Load IP addresses from temporary cache file; create one if not available
    2) Update IP addresses to if_cached
    
    Returns:
        True if success
        False if fail
    """
    
    parameters = {}
    parameters['a'] = 'rec_load_all'
    parameters['tkn'] = cflare_apikey
    parameters['email'] = clfare_email
    parameters['z'] = zone
    target = 'https://www.cloudflare.com/api_json.html'

    parameters = urllib.urlencode(parameters)
    handler = urllib2.urlopen(target, parameters)
    
    cflare_rec_id   = defaultdict(defaultdict)
    
    if handler.code < 400:
        cflare_results = json.loads(handler.read())
        
        # Index cflare_rec_id initial elements
        for cf_index in cflare_results['response']['recs']['objs']:
            cflare_rec_id[cf_index['rec_id']]['index'] = cf_index['rec_id']
            cflare_rec_id[cf_index['rec_id']]['name'] = cf_index['name']
            cflare_rec_id[cf_index['rec_id']]['address'] = cf_index['content']
    else:
        if arg_verbose:
            print ' > bad request or error'
        return False

    # Reindex to cflare_rec dictionary
    index_count = 0
    for dns in dns_list:
        for cf_index in cflare_rec_id:
            if dns[0] in cflare_rec_id[cf_index]['name']:
                cflare_rec[index_count]['index'] = cflare_rec_id[cf_index]['index']
                cflare_rec[index_count]['name'] = cflare_rec_id[cf_index]['name']
                cflare_rec[index_count]['address'] = cflare_rec_id[cf_index]['address']
                cflare_rec[index_count]['if_index'] = if_id(dns[1], router_if_name, False)
                
                if index_count > 0:
                    #if cflare_rec[index_count]['if_index'] == cflare_rec[index_count - 1]['if_index']:
                    if cflare_rec[index_count]['name'] == cflare_rec[index_count - 1]['name']:
                        cflare_rec[index_count]['if_index'] = if_id(dns[1], router_if_name, True)
                        dns[1] = if_list[cflare_rec[index_count]['if_index']]['name']
                        
                        if if_list[cflare_rec[index_count]['if_index']]['address'] == "0.0.0.0":
                            if arg_verbose:
                                print " > %s: interface is down. Select the next interface." % (dns[1])
                                
                            cflare_rec[index_count]['if_index'] = if_id(dns[1], router_if_name, True)
                            dns[1] = if_list[cflare_rec[index_count]['if_index']]['name']
                        #print dns[0], dns[1], cflare_rec_id[cf_index]['name'], index_count, "<--"

                index_count += 1
                #print cflare_rec
    if arg_verbose:
        for i in cflare_rec:
            print " > %s: index: %s; name: %s; address: %s; if_index: %s; if_address: %s" % (i, cflare_rec[i]['index'], cflare_rec[i]['name'], cflare_rec[i]['address'], cflare_rec[i]['if_index'], if_router[cflare_rec[i]['if_index']]['address'])
            #print i, ":", cflare_rec[i]['index'], cflare_rec[i]['name'], cflare_rec[i]['address'], cflare_rec[i]['if_index'], if_router[cflare_rec[i]['if_index']]['address']
            
    return True

def cflare_update(zone, cflare_rec_id, dns_name, ip_addr):
    """cflare_update function
        Update IP address for cflare_rec_id
    
    Returns:
        True if success
        False if fail
    """
    
    parameters = {}
    parameters['a'] = 'rec_edit'
    parameters['tkn'] = cflare_apikey
    parameters['id'] = cflare_rec_id
    parameters['email'] = clfare_email
    parameters['z'] = zone
    parameters['type'] = 'A'
    parameters['name'] = dns_name
    parameters['content'] = ip_addr
    parameters['ttl'] = "1"
    target = 'https://www.cloudflare.com/api_json.html'

    parameters = urllib.urlencode(parameters)
    handler = urllib2.urlopen(target, parameters)
    
    if handler.code < 400:
        cflare_results = json.loads(handler.read())
        if cflare_results['result'] == "success":
            if arg_verbose:
                print " > Record ID %s for DNS %s.%s updated with IP value %s" % (cflare_rec_id, dns_name, zone, ip_addr)
            return True
        else:
            if arg_verbose:
                print " > Record ID %s for DNS %s.%s (%s)" % (cflare_rec_id, dns_name, zone, cflare_results['msg'])
            return False
    
    else:
        if arg_verbose:
            print ' > bad request or error'
        return False

def if_id (if_name, if_list, if_next):
    """if_id function
    
    1) 
    2)
    
    Return
        if_id of if_name in the if_list
    """
    
    index_count = 0
    for interface_name in if_list:
        if if_name in interface_name:
            if if_next:
                if index_count + 1 == len(if_list):
                    return 0
                else:
                    return index_count + 1
            else:
                return index_count
        
        index_count += 1
    
            
    #if if_id == len(if_list) - 1:
    #    return 0
    #else:
    #    return if_id + 1
    
def is_number(val):
    """Check if argument is a number
 
    Args:
        val: String to check
 
    Returns:
        True if a number
    """
 
    try:
        float(val)
        return True
    except ValueError:
        return False

def is_ip_diff(src_list, dst_list):
    """compare_ip function
    
    1) Compare IP addresses to if_cached
    
    Returns:
        True if diffirent
        False if both same
    """
    
    return_results = False
    
    for i in src_list:
        if src_list[i]['address'] != dst_list[i]['address']:
            return_results = True
            break
            
    return return_results

def get_oid_last_octet(oid):
    """Get the last octet of OID
 
    Args:
        oid: OID to check
 
    Returns:
        Last octet
    """
 
    octets = oid.split('.')
    return octets[-1]

def get_oid_last_value(oid, index_oid):
    """Get the last value of OID
 
    Args:
        oid: OID to check
 
    Returns:
        Last last value
    """
    #oid_last_value = oid.split('=')
    oid_last_value = oid.replace(index_oid + ".", '')
    return oid_last_value

def get_sys_object_id(snmpcmd):
    """Get the sysObjectID of the device
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
 
    Returns:
        val: OID value
    """
 
    sysobjectid = '.1.3.6.1.2.1.1.2.0'
    snmp_results = do_snmpget(snmpcmd, sysobjectid)
    for val in snmp_results.values():
        return val

def process_cli():
    """Process command line args
 
    Args:
        None
 
    Returns:
        snmpcmd: SNMP variables required to do SNMP queries on device
    """
 
    # Initialize SNMP variables
    snmpcmd = {}
    snmpcmd['ipaddress']    = router_ip
    snmpcmd['community']    = router_snmp_com
    snmpcmd['secname']      = None
    snmpcmd['version']      = router_snmp_ver
    snmpcmd['authpassword'] = None
    snmpcmd['authprotocol'] = None
    snmpcmd['privpassword'] = None
    snmpcmd['privprotocol'] = None
    snmpcmd['port']         = 161
 
    if not snmpcmd['version']:
        print 'ERROR: SNMP version not specified'
        sys.exit(2)
 
    if (snmpcmd['version'] == 2) and (not snmpcmd['community']):
        print 'ERROR: SNMPv2 community string not defined'
        sys.exit(2)
 
    if (not snmpcmd['ipaddress']):
        print 'ERROR: IP address of device to query is not defined'
        sys.exit(2)
 
    return (snmpcmd)

def do_snmpwalk(snmpcmd, oid_to_get):
    """Do an SNMPwalk
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk
 
    Returns:
        Dictionary of tuples (OID, value)
    """
 
    return do_snmpquery(snmpcmd, oid_to_get, False)

def do_snmpget(snmpcmd, oid_to_get):
    """Do an SNMPget
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk
 
    Returns:
        Dictionary of tuples (OID, value)
    """
 
    return do_snmpquery(snmpcmd, oid_to_get, True)
 
def do_snmpquery(snmpcmd, oid_to_get, snmpget):
    """Do an SNMP query
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk
        snmpget: Flag determining whether to do a GET or WALK
 
    Returns:
        Dictionary of tuples (OID, value)
    """
 
    # Initialize variables
    return_results = {}
    results_objs = False
    session = False
 
    # Get OID
    try:
        session = netsnmp.Session(DestHost=snmpcmd['ipaddress'],
            Version=snmpcmd['version'], Community=snmpcmd['community'],
            SecLevel='authPriv', AuthProto=snmpcmd['authprotocol'],
            AuthPass=snmpcmd['authpassword'], PrivProto=snmpcmd['privprotocol'],
            PrivPass=snmpcmd['privpassword'], SecName=snmpcmd['secname'],
            UseNumeric=True)
        results_objs = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
 
        if snmpget:
            session.get(results_objs)
        else:
            session.walk(results_objs)
 
    except Exception as exception_error:
    # Check for errors and print out results
        print ('ERROR: Occurred during SNMPget for OID %s from %s: '
               '(%s)') % (oid_to_get, snmpcmd['ipaddress'], exception_error)
        sys.exit(2)
 
    # Crash on error
    if (session.ErrorStr):
        print ('ERROR: Occurred during SNMPget for OID %s from %s: '
               '(%s) ErrorNum: %s, ErrorInd: %s') % (
                oid_to_get, snmpcmd['ipaddress'], session.ErrorStr,
                session.ErrorNum, session.ErrorInd)
        sys.exit(2)
 
    # Construct the results to return
    for result in results_objs:
        if is_number(result.val):
            return_results[('%s.%s') % (result.tag, result.iid)] = (
                float(result.val))
        else:
            return_results[('%s.%s') % (result.tag, result.iid)] = (
                result.val)
 
    return return_results

def main():
    """main function
    
    """
    
    if read_args():
        print "OK - Loaded custom argument(s)"
    else:
        print "!! - Invalided or missing argument(s)"
        sys.exit(2)
    
    if get_ip():
        print "OK - Loaded IP addresses from device %s" % router_ip
    else:
        print "!! - Can not load IP addresses from device %s" % router_ip
        sys.exit(2)
    
    if load_ip(tmp_data_file):
        print "OK - Loaded IP addresses from %s" % tmp_data_file
    else:
        print "!! - Can not loaded IP addresses from %s" % tmp_data_file
    
    if (is_ip_diff(if_router, if_cached)) or arg_force:
        if clfare_index(cflare_zone, cflare_dns_list, if_router):
            print "OK - Indexed IP addresses for zone %s" % cflare_zone
        else:
            print "!! - Can not index IP addresses for zone %s" % cflare_zone
        
        if write_ip(tmp_data_file):
            print "OK - Wrote IP addresses to %s" % tmp_data_file
        else:
            print "!! - Wrote IP addresses to %s" % tmp_data_file
        
        for i in cflare_rec:
            #print i, ":", cflare_rec[i]['index'], cflare_rec[i]['name'], cflare_rec[i]['address'], cflare_rec[i]['if_index']
            if (cflare_rec[i]['address'] != if_router[cflare_rec[i]['if_index']]['address']) or arg_force:
                
                if cflare_update(cflare_zone, cflare_rec[i]['index'],
                    cflare_rec[i]['name'].replace("." + cflare_zone, ""), if_router[cflare_rec[i]['if_index']]['address']):
                    print "OK - Updated record ID %s" % (cflare_rec[i]['index'])
                else:
                    print "!! - Can not update record ID %s" % (cflare_rec[i]['index'])
    else:
        print "OK - Nothing needs to be modified or updated."
main()