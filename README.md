# Z-WireGuard

## Presentation:

Z-Wireguard is a Wireguard Server Manager for client to site connexion.
It allow you to create/remove easily Wireguard Server and manage users keys.

Don't forget to open your ports on your Firewall/Router/Box on the port you have configured to make it works

## It allow you to segment the vpn access:

You will be able to manage which VPN have access to what with the localhost firewall (UFW) in /etc/ufw/before.rule.

Example:

```
-A ufw-before-forward -s 10.0.0.0/24 -d 192.168.0.1 -p tcp --dport 80 -j DROP
-A ufw-before-forward -s 10.0.0.0/24 -d 192.168.0.1 -p tcp --dport 443 -j DROP
-A ufw-before-forward -s 10.0.0.0/24 -d 192.168.0.254 -j DROP
```

## Requirement:

- [x] Debian based distro (Only tested on Ubuntu22)
- [x] Python3

## What will be installed:

Resolvconf: To be sure the dns conf won't change
Syslog-ng: To manage wireguard logs
Ufw: For the firewalling
Wireguard: Obviously

## Where are stored the clients configuration and keys:

 All the configuration are stored in /etc/wireguard/
wg.json: is where ZWireguard store informations
<your_vpn_name>.conf: is the configuration of your vpn

```
┌─[root@Ubuntu22]─[/etc/wireguard]
└──╼ #tree adm
adm # > Directory of the VPN named "adm"
├── clients > 
│   └── aze > 
│       ├── aze.conf # > Client configuration to connect that is what you have yo share with your clients
│       ├── private.key 
│       └── public.key
└── server
    ├── private.key
    └── public.key
```

## Log files:

/var/log/wireguard.log: See all wireguard logs
/var/log/wireguard_client.log : See only when client connect and disconnect from the vpn

## Proof Of Concept:

![z-wireguard](C:\Users\guillaume\Desktop\z-wireguard.gif)