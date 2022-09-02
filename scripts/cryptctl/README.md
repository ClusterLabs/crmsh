# cryptctl

## Intorducion

The cryptctl server daemon provides a LUKS-based disk encryption. This script aims to setup an HA environment for the cryptctl-server

## Prerequsits

The cryptctl server needs following resources

* /etc/sysconfig/cryptctl-server The configuration of the server. This will be created once the server was setup and will be only modified if the configuration will be changed like changing the administrator password. It is sufficient to copy this file to all nodes when the cluster will be created.
* The server certificate files in the directory /etc/cryptctl/servertls/. The content of this directory will not be changed until the certifcates are valid. It is sufficient to copy these files to all nodes when the cluster will be created.
* /var/lib/cryptctl/keydb The content of this directory must be provided on shared storage like NAS or NFS server. The encryption keys will be saved here. For these directory a Filesystem resource agent will be created.
* An IP address the cryptctl-server is listening on. An IPAddr2 resource agent will be created for this reason.

## Setup

### Setp cryptctl server
As first step you have to setup the cryptctl server:
```shell
cryptctl init-server
```

### Create a basic cluster
If not already done you have to setup a basic cluster with at last two nodes. It is very important that Node1 must be the server where you have confiugred the cryptctl server.

```shell
crm cluster init -i <NetDev> -A <AdminIP> -n <ClusterName> -y
```

Join the cluster from other nodes:
```shell
ssh <Node2>
crm cluster join -y <Node1>
```

### Setup the resource group for the cryptctl server

You can setup all needed resource agents and copy all files to all nodes whit the cryptcl crm-shell-script in one step. It is scrictly recommended to verify the setup in first step:

```shell
crm script verify cryptctl \
                  cert-path=</etc/cryptctl/servertls/certificate-name> \
                  cert-key-path=</etc/cryptctl/servertls/certificate-key-name> \
                  virtual-ip:ip=<IP-Address> \
                  filesystem:device=<Path to the device> 
```

If the check was succesfull you have to setup the cluster group by running the script:
```shell
crm script run cryptctl \
                  cert-path=</etc/cryptctl/servertls/certificate-name> \
                  cert-key-path=</etc/cryptctl/servertls/certificate-key-name> \
                  virtual-ip:ip=<IP-Address> \
                  filesystem:device=<Path to the device> 
```
