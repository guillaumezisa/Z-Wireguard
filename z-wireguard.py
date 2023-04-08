#!/usr/bin/env python3

import os
import json
import urllib.request


red = '\033[91m'
green= '\033[92m'
blue= '\033[34m'
neutral= "\x1b[0m"


def banner():
    print(red+" ______  __          ___                                    _ ")
    print("|___  /  \ \        / (_)                                  | |")
    print("   / /____\ \  /\  / / _ _ __ ___  __ _ _   _  __ _ _ __ __| |")
    print("  / /______\ \/  \/ / | | '__/ _ \/ _` | | | |/ _` | '__/ _` |")
    print(" / /__      \  /\  /  | | | |  __/ (_| | |_| | (_| | | | (_| |")
    print("/_____|      \/  \/   |_|_|  \___|\__, |\__,_|\__,_|_|  \__,_|")
    print("                                   __/ |                      ")
    print("                                  |___/                       "+neutral)
    print(red+"Don't forget to open the ports on your external firewalls to make it works!"+neutral)

def wg_init(iface_name,endpoint,host_ip,port,network,vpn_ip,dns):
    if os.path.isfile("/etc/wireguard/wg.json") is False:
        data = {
            "iface": [{
                "name": iface_name,
                "conf":{
                    "endpoint":endpoint,
                    "host_ip":host_ip,
                    "host_port":port,
                    "vpn_network":network,
                    "vpn_ip":vpn_ip,
                    "dns":dns,
                    "interface":"",
                    "keys":{
                        "public":"",
                        "private":"",
                        },
                    "clients":[]
                }
            }]
        }

        data["iface"][0]["conf"]["interface"] = os.popen("ip route |grep default | awk '{print $5}'").read().replace("\n","")

        os.system("mkdir -p /etc/wireguard/"+data["iface"][0]["name"]+"/server")
        os.system("mkdir -p /etc/wireguard/"+data["iface"][0]["name"]+"/clients")
        wg_install()
        os.system("modprobe wireguard")
        os.system("echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control")
    else:
        os.system("mkdir -p /etc/wireguard/"+iface_name+"/server")
        os.system("mkdir -p /etc/wireguard/"+iface_name+"/clients")
        with open("/etc/wireguard/wg.json","r") as file:
            data = json.load(file)
        
        new_data = {
                "name": iface_name,
                "conf":{
                    "endpoint":endpoint,
                    "host_ip":host_ip,
                    "host_port":port,
                    "vpn_network":network,
                    "vpn_ip":vpn_ip,
                    "dns":dns,
                    "interface":"",
                    "keys":{
                        "public":"",
                        "private":"",
                        },
                    "clients":[]
                }
            }
        new_data["conf"]["interface"] = os.popen("ip route |grep default | awk '{print $5}'").read().replace("\n","")
        data["iface"].append(new_data)

    with open('/etc/wireguard/wg.json', 'w') as json_file:
        json.dump(data, json_file)


def wg_install():
    print(red+"> Updating the system")
    os.system("sudo apt update -y > /dev/null")

    print("> Installing resolvconf")
    os.system("sudo apt install resolvconf -y > /dev/null")
    os.system("echo 'nameserver 1.1.1.1' >> /etc/resolv.conf")

    print("> Installing Wireguard")
    os.system("sudo apt install wireguard -y > /dev/null")

    print("> Installing UFW")
    os.system("sudo apt install ufw -y > /dev/null")

    print("> Installing Syslog-ng")
    os.system("sudo apt install syslog-ng -y > /dev/null")

    print("> Configure Syslog-ng to generate wireguard logs")
    os.system("echo '############################' > /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo '#  Wireguard configuration #' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo '############################' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo 'destination d_wg_cli { file(\"/var/log/wireguard_clients.log\"); };' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo 'destination d_wg { file(\"/var/log/wireguard.log\"); };' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo 'filter f_wg_cli { match(\"Keypair\");};' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo 'filter f_wg { match(\"wireguard\");};' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo 'log { source(s_src); filter(f_wg_cli); destination(d_wg_cli);};' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("echo 'log { source(s_src); filter(f_wg); destination(d_wg);};' >> /etc/syslog-ng/conf.d/wireguard.conf")
    os.system("service syslog-ng restart")

    

    print("> UFW Start Configuration"+neutral)
    os.system("ufw default allow FORWARD > /dev/null")
    file_insert_top("/etc/ufw/before.rules","*nat\n: POSTROUTING ACCEPT [0:0]\nCOMMIT")
    os.system("service ufw restart")


def wg_srv_key_gen(iface):
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        if data["iface"][i]["name"] == iface:
            os.system("umask 077 /etc/wireguard/"+iface+"/server/")
            os.system("wg genkey | sudo tee /etc/wireguard/"+iface+"/server/private.key > /dev/null")
            data["iface"][i]["conf"]["keys"]["private"] = os.popen("cat /etc/wireguard/"+iface+"/server/private.key").read().replace("\n","")
            os.system("wg pubkey < /etc/wireguard/"+iface+"/server/private.key > /etc/wireguard/"+iface+"/server/public.key")
            data["iface"][i]["conf"]["keys"]["public"] = os.popen("cat /etc/wireguard/"+iface+"/server/public.key").read().replace("\n","")
            
            os.system("sudo chmod go= /etc/wireguard/"+iface+"/server/private.key")
            os.system("sudo chmod go= /etc/wireguard/"+iface+"/server/public.key")

            with open('/etc/wireguard/wg.json', 'w') as json_file:
                json.dump(data, json_file)

def wg_srv_conf_gen(iface):
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        if data["iface"][i]["name"] == iface:
            os.system("echo '[Interface]' > /etc/wireguard/"+iface+".conf")
            os.system("echo 'Address = "+data["iface"][i]["conf"]["vpn_ip"]+"' >> /etc/wireguard/"+iface+".conf")
            os.system("echo 'SaveConfig = False' >> /etc/wireguard/"+iface+".conf")
            os.system("echo 'ListenPort = "+data["iface"][i]["conf"]["host_port"]+"' >> /etc/wireguard/"+iface+".conf")
            os.system("echo 'PrivateKey = "+data["iface"][i]["conf"]["keys"]["private"]+"' >> /etc/wireguard/"+iface+".conf")
            
            os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")
            os.system("sysctl -p /etc/sysctl.conf > /dev/null")

def wg_launch(iface):
    os.system("sudo systemctl enable wg-quick@"+iface+".service")
    os.system("sudo systemctl start wg-quick@"+iface+".service")

def wg_display_srv():
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        print(red+"NAME: "+green+data["iface"][i]["name"]) 
        print("     "+blue+"ENDPOINT(PublicIp):  "+neutral+data["iface"][i]["conf"]["endpoint"]) 
        print("     "+blue+"HOST(PrivateIp):     "+neutral+data["iface"][i]["conf"]["host_ip"]) 
        print("     "+blue+"NETWORK_INTERFACE:   "+neutral+data["iface"][i]["conf"]["interface"]) 
        print("     "+blue+"PORT(Udp):           "+neutral+data["iface"][i]["conf"]["host_port"]) 
        print("     "+blue+"VPN_Net(PublicIp):   "+neutral+data["iface"][i]["conf"]["vpn_network"]) 
        print("     "+blue+"VPN_IP(PublicIp):    "+neutral+data["iface"][i]["conf"]["vpn_ip"]) 
        print("     "+blue+"DNS(PublicIp):       "+neutral+data["iface"][i]["conf"]["dns"]) 
        print("     "+blue+"PUBLIC_KEY:          "+neutral+data["iface"][i]["conf"]["keys"]["public"]) 
        print("     "+blue+"PRIVATE_KEY:         "+neutral+data["iface"][i]["conf"]["keys"]["private"]) 
    input("[ Press enter to continue... ]")

def loop():
    while True:
        banner()

        print(blue+"Enter the following number to get what you need:"+neutral)
        print(green+" 1 "+neutral+"- Install a Wireguard Server")
        print(green+" 2 "+neutral+"- List Wireguard Servers")
        print(green+" 3 "+neutral+"- Manage Wireguard servers")
        print(green+" 4 "+neutral+"- Remove Wireguard Server")
        print(green+" q "+neutral+"- Exit")
        user_input = input(red+"> "+neutral)

        if user_input == "1":
            iface_name_status = False
            while iface_name_status is False:
                exist = False
                iface_name = input(blue+"Please enter the name of the new wireguard interface:\n"+red+"> "+neutral)
                if os.path.isfile("/etc/wireguard/wg.json") is True:
                    with open("/etc/wireguard/wg.json") as f:
                        data = json.load(f)
                        for i in range(len(data["iface"])):
                            if data["iface"][i]["name"] == iface_name:
                                print(red+"This wireguard interface already exist\n"+neutral)
                                exist = True   
                        if exist is False:
                            iface_name_status = True
                            ip = os.popen("ip route | grep default | awk '{print $3}'").read().replace("\n","")
                            break
                else:
                    ip = os.popen("ip route | grep default | awk '{print $3}'").read().replace("\n","")
                    iface_name_status = True
                    break

            ip_public = urllib.request.urlopen('https://ident.me').read().decode('utf8')
            #endpoint = input(blue+"Please enter the endpoint IP or Domain [default: "+ip_public+"]:\n"+red+"> "+neutral)
            endpoint = input(blue+"Please enter the endpoint IP or Domain [default: hide for the demo ;)]:\n"+red+"> "+neutral)

            if endpoint == "": endpoint = ip_public


            default_gateway_iface = os.popen("ip route | grep default | awk '{print $5}'").read().replace("\n","")
            default_ip = os.popen("ip a | grep '"+default_gateway_iface+"' | grep '/' | awk '{print $2}'").read().replace("\n","")[:-3]
            host_ip = input(blue+"Please enter the host IP [default:"+default_ip+"]:\n"+red+"> "+neutral)
            if host_ip == "": host_ip = default_ip

            host_port = input(blue+"Please enter the host port [default: 51820]:\n"+red+"> "+neutral)
            if host_port == "": host_port = "51820"
            
            vpn_network = input(blue+"Please enter the VPN network [default: 10.0.0.0/24]:\n"+red+"> "+neutral)
            if vpn_network == "": vpn_network = "10.0.0.0/24"

            vpn_ip = input(blue+"Please enter the VPN IP [default: 10.0.0.1/24]:\n"+red+"> "+neutral) 
            if vpn_ip == "": vpn_ip = "10.0.0.1/24"

            dns = input(blue+"Please enter a dns [default: 1.1.1.1]:\n"+red+"> "+neutral)
            if dns == "": dns="1.1.1.1"
            wg_init(iface_name,endpoint,host_ip,host_port,vpn_network,vpn_ip,dns)
            private_key = wg_srv_key_gen(iface_name)
            wg_srv_conf_gen(iface_name)
            wg_launch(iface_name)

        elif user_input == "2":
            wg_display_srv()
                 

        elif user_input == "3":
            with open("/etc/wireguard/wg.json","r") as file:
                data = json.load(file)
            print(red+"Available Wireguard servers are:"+neutral)
            for i in range(len(data["iface"])):
                print(green+" "+str(i)+neutral+" - "+data["iface"][i]["name"]) 
            
            id = input(blue+"Please enter an id to start:\n"+red+"> "+neutral)
            while True:
                banner()
                print(green+" 1 "+neutral+"- Check configuration")
                print(green+" 2 "+neutral+"- List Client")
                print(green+" 3 "+neutral+"- Add Clients")
                print(green+" 4 "+neutral+"- Delete Client")
                print(green+" 0 "+neutral+"- Return")
                print(green+" q "+neutral+"- Exit")
                user_input = input(green+"@"+blue+data["iface"][int(id)]["name"]+red+"> "+neutral)

                if user_input == "1":
                    input("Press enter to continue..")
                if user_input == "2":
                    with open("/etc/wireguard/wg.json","r") as file:
                        data = json.load(file)
                    for i in range(len(data["iface"][int(id)]["conf"]["clients"])):
                        print(data["iface"][int(id)]["conf"]["clients"][i])
                        print(red+"CLIENT NAME: "+green+data["iface"][int(id)]["conf"]["clients"][i]["username"]) 
                        print("     "+blue+"IP:             "+neutral+data["iface"][int(id)]["conf"]["clients"][i]["ip"]) 
                        print("     "+blue+"PUBLIC_KEY:     "+neutral+data["iface"][int(id)]["conf"]["clients"][i]["keys"]["public"]) 
                        print("     "+blue+"PRIVATE_KEY:    "+neutral+data["iface"][int(id)]["conf"]["clients"][i]["keys"]["private"]) 
                    input("[ Press enter to continue... ]")

                elif user_input == "3":
                    username = input(blue+"Enter a new name for the user [exemple: Albert_Smith_1]:\n"+red+"> "+neutral)
                    ip = input(blue+"Enter a new ip for the user for exemple 10.7.0.2:\n"+red+"> "+neutral)
                    data_client = wg_user_keys(data["iface"][int(id)]["name"],username,ip)
                    wg_user_conf(data["iface"][int(id)]["name"],data_client)
                    wg_srv_write_new_conf(data["iface"][int(id)]["name"])
                    ufw_write_new_conf(data["iface"][int(id)]["name"])
                    os.system("clear")
                    os.system("cat /etc/wireguard/"+data["iface"][int(id)]["name"]+"/clients/"+username+"/"+username+".conf")
                    print(red+"You can find the  client configuration at:\n"+blue+"/etc/wireguard/"+data["iface"][int(id)]["name"]+"/clients/"+username+"/"+username+".conf"+neutral)
                    input("[ Press enter to continue... ]")
                elif user_input == "4":
                    username = input(blue+"Enter an username to remove:\n"+red+"> "+neutral)
                    wg_client_remove(data["iface"][int(id)]["name"],username)
                    input("[ Press enter to continue... ]")
                elif user_input == "0":
                    loop()
                elif user_input == "q":
                    exit()
                
        elif user_input == "4":
            server = input(blue+"Enter the name of the server you want to remove:\n"+red+"> "+neutral)
            wg_srv_remove(server)
        elif user_input == "q":
            exit()
        
def wg_user_keys(iface,username,ip):

    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        if data["iface"][i]["name"] == iface:

            os.system("mkdir /etc/wireguard/"+iface+"/clients/"+username)
            private_key = os.popen("wg genkey | sudo tee /etc/wireguard/"+iface+"/clients/"+username+"/private.key").read().replace("\n","")
            public_key = os.popen("sudo cat /etc/wireguard/"+iface+"/clients/"+username+"/private.key | wg pubkey | sudo tee /etc/wireguard/"+iface+"/clients/"+username+"/public.key").read().replace("\n","")
            os.system("sudo chmod go= /etc/wireguard/"+iface+"/clients/"+username+"/public.key")
            os.system("sudo chmod go= /etc/wireguard/"+iface+"/clients/"+username+"/private.key")
            data["iface"][i]["conf"]["clients"].append({"username":username,"ip":ip,"keys":{"private":private_key,"public":public_key}})
            with open('/etc/wireguard/wg.json', 'w') as json_file:
                json.dump(data, json_file)
            return {"username":username,"ip":ip,"keys":{"private":private_key,"public":public_key}}

def wg_user_conf(iface,data_client):
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        if data["iface"][i]["name"] == iface:
            os.system("echo '[Interface]' > /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo 'PrivateKey = "+data_client["keys"]["private"]+"' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo 'Address = "+data_client["ip"]+"/24' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo 'DNS = "+data["iface"][i]["conf"]["dns"]+"\n' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo '[Peer]' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo 'PublicKey = "+data["iface"][i]["conf"]["keys"]["public"]+"' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo 'AllowedIPs = 0.0.0.0/0' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo 'Endpoint = "+data["iface"][i]["conf"]["endpoint"]+":"+data["iface"][i]["conf"]["host_port"]+"' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")
            os.system("echo 'PersistentKeepalive = 25' >> /etc/wireguard/"+iface+"/clients/"+data_client["username"]+"/"+data_client["username"]+".conf")

def wg_srv_write_new_conf(iface):
    
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        if data["iface"][i]["name"] == iface:
            os.system("echo '[Interface]' > /etc/wireguard/"+iface+".conf")
            os.system("echo 'Address = "+data["iface"][i]["conf"]["vpn_ip"]+"' >> /etc/wireguard/"+iface+".conf")
            os.system("echo 'SaveConfig = False' >> /etc/wireguard/"+iface+".conf")
            os.system("echo 'ListenPort = "+data["iface"][i]["conf"]["host_port"]+"' >> /etc/wireguard/"+iface+".conf")
            os.system("echo 'PrivateKey = "+data["iface"][i]["conf"]["keys"]["private"]+"' >> /etc/wireguard/"+iface+".conf")

            for y in range(len(data["iface"][i]["conf"]["clients"])):
                os.system("echo '#####\n[Peer]' >> /etc/wireguard/"+iface+".conf")
                os.system("echo 'PublicKey = "+data["iface"][i]["conf"]["clients"][y]["keys"]["public"]+"' >> /etc/wireguard/"+iface+".conf")
                os.system("echo 'AllowedIPs = "+data["iface"][i]["conf"]["clients"][y]["ip"]+"/32\n' >> /etc/wireguard/"+iface+".conf")
            os.system("sudo systemctl restart wg-quick@"+iface+".service")
            break

def ufw_write_new_conf(iface):
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        if data["iface"][i]["name"] == iface:
            os.system("ufw route allow in on "+iface+" out on "+data["iface"][i]["conf"]["interface"])
            os.system("ufw allow "+data["iface"][i]["conf"]["host_port"]+"/udp")
            os.system("ufw allow 22")
            with open("/etc/ufw/before.rules","r") as f:
                lines = f.readlines()
            for y in range(len(lines)):
                if lines[y] == "COMMIT\n":
                    if "-A POSTROUTING" in lines[y-1] or ": POSTROUTING" in lines[y-1]:
                        lines[y] = lines[y].replace("COMMIT\n","-A POSTROUTING -s "+data["iface"][i]["conf"]["vpn_network"]+" -o "+data["iface"][i]["conf"]["interface"]+" -j MASQUERADE\nCOMMIT\n")
                        break
            os.system("rm /etc/ufw/before.rules")
            for y in range(len(lines)):
                with open("/etc/ufw/before.rules","a") as fi:
                    fi.write(lines[y])
            os.system("ufw disable")
            os.system("ufw enable")

def file_insert_top(file_name, line):
    dummy_file = file_name + '.bak'
    with open(file_name, 'r') as read_obj, open(dummy_file, 'w') as write_obj:
        write_obj.write(line + '\n')
        for line in read_obj:
            write_obj.write(line)
    os.remove(file_name)
    os.rename(dummy_file, file_name)

def wg_client_remove(iface,client_name):
    public_key = ""
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        print(data["iface"][i]["conf"]["clients"])
        if iface == data["iface"][i]["name"]:       
            for y in range(len(data["iface"][i]["conf"]["clients"])):
                if data["iface"][i]["conf"]["clients"][y]["username"] ==  client_name:
                    public_key = data["iface"][i]["conf"]["clients"][y]["keys"]["public"]
                    data["iface"][i]["conf"]["clients"].pop(y)
                    break
    if public_key == "":
        print(red+"Client has not been found"+neutral)
        input("[ Press enter to continue... ]")
    else:
        os.system("rm -r /etc/wireguard/"+iface+"/clients/"+client_name)
        with open("/etc/wireguard/"+iface+".conf","r") as f:
            lines = f.readlines()
        for i in range(len(lines)):
            if public_key in lines[i]:
                for y in range(4):
                    lines.pop(i-1)

                break
        os.system("cat /etc/wireguard/"+iface+".conf")
        os.system("rm /etc/wireguard/"+iface+".conf")
        with open("/etc/wireguard/"+iface+".conf","a") as f:
            for i in range(len(lines)):
                f.write(lines[i])
        with open('/etc/wireguard/wg.json', 'w') as json_file:
            json.dump(data, json_file)
        os.system("cat /etc/wireguard/"+iface+".conf")
        input(red+"Client has been remove"+neutral)
        input("[ Press enter to continue... ]")

def wg_srv_remove(iface):
    vpn_network = ""
    with open("/etc/wireguard/wg.json","r") as file:
        data = json.load(file)
    for i in range(len(data["iface"])):
        if data["iface"][i]["name"] == iface:
            vpn_network = data["iface"][i]["conf"]["vpn_network"]
            data["iface"].pop(i)
            break
    if vpn_network == "": 
        print(red+"Server has not been found"+neutral)
        input("[ Press enter to continue... ]")
        loop()
    os.system("ip link delete "+iface+" > /dev/null")
    os.system("rm -r /etc/wireguard/"+iface+"*")
    with open("/etc/ufw/before.rules","r") as f:
        lines = f.readlines()
    
    for i in range(len(lines)):
        if vpn_network in lines[i]:
            lines.pop(i)
            break

    os.system("rm /etc/ufw/before.rules")
    with open("/etc/ufw/before.rules","a") as f:
        for i in range(len(lines)):
            f.write(lines[i])

    with open('/etc/wireguard/wg.json', 'w') as json_file:
        json.dump(data, json_file)
    print(red+"Server has been removed"+neutral)
    input("[ Press enter to continue... ]")

loop()



