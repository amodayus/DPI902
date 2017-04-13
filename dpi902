#!/usr/bin/python

#This program takes a network interface in Linux using the ip command and will create a bash script.
#The bash script, named workfile, is then run manually by the user. The bash script uses arp to find
# any hosts that are online and displays them nicely.

import os
import sys
import subprocess
import ipaddress

#Figure out what connected devices the system has
def connected_devices():
	conn_devices = subprocess.check_output("ip link | grep ^[0-9+] | tr -s ' ' | cut -d ' ' -f 2", shell=True)
	with open('workfile', 'w') as f:
		f.write(str(conn_devices))
	with open('workfile', 'r') as f:
		conn_devices = f.readlines()
#Create a device list		
	dev_list = []
	for i in conn_devices:
		i = i[:-2]
		if i == "lo":
			()
		else:	
			dev_list.append(i)
	return dev_list

#Figure out the networks, IPv4 and IPv6, the interfaces are connected to.

def connected_networks(device):
	networks = subprocess.check_output("ip addr show " + device + "  | grep inet | tr -s ' ' | cut -d ' ' -f 3", shell=True)
	with open('workfile', 'w') as f:
		f.write(networks)
	with open('workfile', 'r') as f:
		networks = f.readlines()
	net4_list = []
	for i in networks:
		i = i[:-1]
		#Check for IPv4
		if "." in i:
			net4_list.append(i)
	if len(net4_list) == 0:
		print "No IP address found"
		print "Exiting"
		sys.exit(0)
	else:
		return net4_list

#Check if a device name on the system is passed to the program.
def arg_check():
	
	if len(sys.argv) == 2 and sys.argv[1] in connected_devices():
			()
	else:
		print "Usage: dpi902 [ <interface name> ]"
		sys.exit(0)

def list_hosts(network):
	hosts = ipaddress.ip_network(network, strict=False)
	return hosts
	
def discover(host):
	
	try:
		arp_cmd = subprocess.check_output("echo arping -rR -c 1 %s %s", shell=True) % (host, "2> /dev/null &")
		return arp_cmd
	except subprocess.CalledProcessError as e:
		()

def main():
	hosts = []
	arg_check()
	devices = connected_devices()
	for i in devices:
		print "You have these active interfaces on the system: %s" % i
	networks = connected_networks(sys.argv[1])
	for i in networks:
		print "The IPv4 network connected to this device is: %s " % ipaddress.ip_network(unicode(i), strict=False)
		print "The number of hosts available to scan on this network are the following: "
		for x in list_hosts(unicode(i)).hosts():
			if x == ipaddress.ip_address(unicode(i[:-3])):
				()
			else:
				hosts.append(str(x))
		print len(hosts)
	scan = raw_input("Proceed with scan? y/n: ")
	if scan == "y":
		c = 0
		a = "sleep 1 \n"
		with open('workfile', 'w') as f:
			f.write('#!/bin/bash\n')
		for host in hosts:
			#print host
			#print c
			with open('workfile', 'a+') as f:
				f.write(discover(host))
				c = c + 1
			if c == 4:
				with open('workfile', 'a+') as f:
					#print a
					f.write(a)
					c = 0
	else:
		sys.exit(0)
		
			
main()
