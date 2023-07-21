# Documentation for PoshAlto, a Primitive PowerShell tool to Automate PAN-NGFW Config Changes

Written by ravagedshell <github.com/ravagedshell>
Last Modified 05/05/2019
Note, this script is only tested to work using the RESTful XML API on PAN OS 8.1 and earlier.

# Purpose:
The purpose of this automation script is to enable users to import and implement robust firewall configurations with little more work than filling out some excel spreadsheets and running a PowerShell command. I created this out of neseccity when onboarding new power generation facilities back when I worked in the Energy Industry. Back then, some people thought spending money on Panorama was a bit untenable, but I was responsible for onboarding new sites and bringing their firewalls into compliance with NERC-CIP standards and didnt want to do them all through the GUI or Copy-Paste over SSH one-by-one. I think I made this in like 20-minutes, maybe I'll put some work into this some time and make something more useful out of it.

Background knowledge of security policies, zone-based firewalls, IPSec Tunnels, NAT policies, and other firewall concepts are required to properly fill out the required spreadsheets. At the time that this documentation was written, there are currently 12 separate automation functions.

In order to support this, you must utilize CSVs with the following headers:

## Delimiting Characters:
* To add multiple members of the source, destination, source zone, destination zone, application, service, source user fields, delimit your entries with the semi-colon ; 
* The script will process this as a new member, allowing you to have multiple members for the same security or NAT rule.
* Do not use any other character to delimit multiple members
* To delimit multiple members of a service object, for either source or destination ports, utilize the character semi-colon ;
* Do not utilize spaces of any sort as it will result in failure of just about all functions within this script.
## Recommended Order of Operations:
If you intend to utilize this automation script in it’s entirety, then it is recommended that operations take place in a specific order to minimize errors. Items should be completed in the order provided below:

1.	Create Security Zones (Add-SecurityZones)
2.	Create Tags (Add-Tags)
3.	Create Service Objects (Add-ServiceObjects)
4.	Create Address Objects (Add-AddressObjects)
5.	Create Security Rules (Add-SecurityRules)
6.	Create NAT Rules (Add-NATRules)

If you are also utilized the IPSec commands, we recommend completing them in the following order, after the above listed items have already been completed:

1.	Add-TunnelInterface
2.	Add-StaticRoutes
3.	Add-IKECryptoProfile
4.	Add-IPSecCryptoProfile
5.	Add-IKEGateway
6.	Add-IPSecTunnel

Included Files:
The following files are included and intended for use by specific functions of this script:
|    Filename                |    Used By Function          |
|----------------------------|------------------------------|
|    addressobjects.csv      |    Add-AddressObjects        |
|    ikegateways.csv         |    Add-IKEGateway            |
|    ikeprofiles.csv         |    Add-IKECryptoProfile      |
|    ipsecprofiles.csv       |    Add-IPSecCryptoProfile    |
|    ipsec-proxyid.csv       |    Add-IPSecTunnel           |
|    ipsectunnel.csv         |    Add-IPSecTunnel           |
|    natpolicies.csv         |    Add-NATRules              |
|    securitypolicies.csv    |    Add-SecurityRules         |
|    securityzones.csv       |    Add-SecurityZones         |
|    serviceobjects.csv      |    Add-ServiceObjects        |
|    staticroutes.csv        |    Add-StaticRoutes          |
|    tags.csv                |    Add-Tags                  |
|    tunnelinterfaces.csv    |    Add-TunnelInterface       |

## Loading the Script:
Import-Module .\PAN-OSAutomation-v1-0.ps1

## Required CSV Headers:
If you have elected not to utilize the included CSV files, or have lost access to them, the following headers are required for each specific function, all header names are case sensitive, and should all be lowercase.:

### Add-AddressObjects:
| name        |
| address     |
| description |

### Add-Tags:
| name        |
| color     |
| comment |

### Add-ServiceObjects:
| name        |
| protocol     |
| destination |

### Add-SecurityZones:
| name        |
| network     |
 
### Add-SecurityRules:
| srczone        |
| src     |
| dstzone        |
| dst     |
| service        |
| application     |
| disabled        |
| lstart    |
| lend        |
| action     |
| tags        |
| description     |

### Add-TunnelInterface:
| name    |
| ipaddress        |
| virtualrouter     |
| securityzone        |

### Add-IKECryptoProfile:
| name    |
| hash     |
| dhgroup |
| encryption |
| lifetime |

### Add-IPSecCryptoProfile:
| name    |
| authentication |
| dhgroup |
| encryption |
| lifetime |

### Add-StaticRoutes:
| name    |
| virtualrouter |
| interface |
| metric |
| destination |

 
Add-IKEGateway:
| name    |
| version |
| peer |
| local |
| interface |
| psk    |
| dpd |
| ikeprofile |
| natt |
| peerid |
| peeridtype |
| fragmentation |

### Add-IPSecTunnel
For the IPSec tunnel, there are two required CSVs. One defines the IPSec tunnel, the other includes all the proxy IDs for networks to import/export. 
#### For the IPSec Tunnel Definition:
| name |
| ikegateway |
| ipseccrypto |
| tunnelinterface |
| fragmentation |
#### For the Proxy IDs:
| tunnelname |
| proxyidname |
| local |
| remote |
| protocol |

### Add-NATRules
| name |
| bidrectional |
| translation |
| srczone |
| src |
| dstzone |
| dst |
| service |
| tags |
| type |


### Common Parameters:
For all functions (except for Add-IPSecTunnel) the following parameters must be defined
#### CSVFileLocation
The path to the CSV file that you are using to import the configurations.
#### FirewallIP 
The IP address of the Palo-Alto Firewall
#### APIKey
The API Secret key for your user, for info on how to generate this and enable API access, see references for link to Palo-Alto documentation For the function *“Add-IPSecTunnel”*, the “CSVFileLocation” parameter is not present, instead you must specific the location of two separate CSV Files using the following parameters:

##### TunnelCSVFile
Includes the information for defining the IPSecTunnel
##### ProxyIDCSVFile
Includes the information for what networks to import/export. All other parameters remain the same and are required.

### Example:
`Import-Module .\PAN-OSAutomation-v1-0.ps1`

`Add-NATRules -CSVFileLocation .\natpolicies.csv -APIKey “34888dfs$$eerds…” -FirewallIP 172.16.20.1`

`Add-IPSecTunnel -TunnelCSVFile ipsectunnel.csv -ProxyIDCSVFile ipsec-proxyid.csv - APIKey “34888dfs$$eerds…” -FirewallIP 172.16.20.1`

### References
To enable API Access:

https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/enable-api-access.html

To generate an API Secret: 

https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key

For the Application ID Encyclopedia:

https://applipedia.paloaltonetworks.com/
