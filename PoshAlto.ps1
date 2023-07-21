add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

function Add-AddressObjects{
    Param( 
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $Addresses = Import-CSV $CSVFileLocation
    foreach($Address in $Addresses){
        $Name = "'" + $Address.name +"'"
        $IPv4 = $Address.address
        $Description = $Address.description
        $URL = "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/shared/address/entry[@name=$Name]&element=<ip-netmask>$IPv4</ip-netmask><description>$Description</description>$TagString"
        Invoke-WebRequest -UseBasicParsing $URL
    }
}

function Add-Tags{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )

    $Tags = Import-CSV $CSVFileLocation
    foreach($Tag in $Tags){
        $Comments = $null
        $Color = $null
        $Name = "'" + $Tag.name + "'"
        $Color = $Tag.color
        $Comments = $Tag.comment
        $URL = "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name=$Name]&element=<color>$Color</color><comments>$Comments</comments>"
        Invoke-WebRequest -UseBasicParsing $URL
    }
}

function Add-ServiceObjects{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $Services = Import-CSV $CSVFileLocation
    foreach($Service in $Services){
        $Name =  "'" + $Service.name + "'"
        $Protocol = $Service.proto
        $DestinationPorts = $Service.destination
        $DestinationPorts = $DestinationPorts -replace ";","," 
        $ValueString = "<protocol><$Protocol><port>$DestinationPorts</port></$Protocol></protocol>"
        $URL = "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name=$Name]&element=$ValueString"
        Invoke-WebRequest -UseBasicParsing $URL
        Write-Output $URL                      
    }
}

function Add-SecurityRules{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $Rules = Import-CSV $CSVFileLocation
    foreach($Rule in $Rules){
        $Name = "'" + $Rule.name + "'"
        $SrcZoneImport = $Rule.srczone
        $SrcImport = $Rule.src
        $DstZoneImport = $Rule.dstzone
        $DstImport = $Rule.dst
        $ServiceImport = $Rule.service
        $AppIDImport = $Rule.application
        $Disabled = $Rule.disabled
        $LogStart = $Rule.lstart
        $LogEnd = $Rule.lend
        $Description = $Rule.description
        $Action = $Rule.Action
        $TagsImport = $Rule.tags
        $SrcZones = $SrcZoneImport.Split(";")
        $SrcNames = $SrcImport.Split(";")
        $DstZones = $DstZoneImport.Split(";")
        $DstNames = $DstImport.Split(";")
        $Services = $ServiceImport.Split(";")
        $AppIDs = $AppIDImport.Split(";")
        $Tags = $TagsImport.Split(";")
        $SrcNameString = $null
        $SrcZoneString = $null
        $DstNameString = $null
        $DstZoneString = $null
        $ServiceString = $null
        $AppIDString = $null
        $TagString = $null
        if($Tags -ne $null){
            $TagString = "<tag>"
            foreach($Tag in $Tags){
                $TagString = $TagString + "<member>$Tag</member>"
            }
            $TagString = $TagString + "</tag>"
        }
        foreach($SrcZone in $SrcZones){
            $SrcZoneString = $SrcZoneString + "<member>$SrcZone</member>"
        }
        foreach($SrcName in $SrcNames){
            $SrcNameString = $SrcNameString + "<member>$SrcName</member>"
        }
        foreach($DstZone in $DstZones){
            $DstZoneString = $DstZoneString + "<member>$DstZone</member>"
        }
        foreach($DstName in $DstNames){
            $DstNameString = $DstNameString + "<member>$DstName</member>"
        }
        foreach($Service in $Services){
            $ServiceString = $ServiceString + "<member>$Service</member>"
        }
        foreach($AppID in $AppIDs){
            $AppIDString = $AppIDString + "<member>$AppID</member>"
        }
        Invoke-WebRequest -UseBasicParsing  "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name=$Name]&element=<source>$SrcNameString</source><destination>$DstNameString</destination><service>$ServiceString</service><application>$AppIDString</application><source-user><member>any</member></source-user><hip-profiles><member>any</member></hip-profiles><action>$Action</action><disabled>$Disabled</disabled><description>$Description</description><from>$SrcZoneString</from><to>$DstZoneString</to>$TagString"
    }
}

function Add-TunnelInterface{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $TunnelInterfaces = Import-Csv $CSVFileLocation

    foreach($Interface in $TunnelInterfaces){
        $Name = "'" + $Interface.name + "'"
        $CleanName = $Interface.name
        $IPAddress = "'" + $Interface.ipaddress + "'"
        $VirtualRouter = "'" + $Interface.virtualrouter + "'"
        $SecurityZone = "'" + $Interface.securityzone + "'"
        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units/entry[@name=$Name]&element=<ip><entry name=$IPAddress></entry></ip>"
        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name=$VirtualRouter]&element=<interface><member>$CleanName</member></interface>"
        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name=$SecurityZone]&element=<network><layer3><member>$CleanName</member></layer3></network>"

    }
              
}

function Add-IKECryptoProfile{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $IKEProfiles = Import-Csv $CSVFileLocation

    foreach($Profile in $IKEProfiles){
        $Name = "'" + $Profile.name + "'"
        $Integrity = $Profile.hash
        $DHGroup = $Profile.dhgroup
        $Encryption = $Profile.encryption
        $Lifetime = $Profile.lifetime
        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name=$Name]&element=<hash><member>$Integrity</member></hash><dh-group><member>$DHGroup</member></dh-group><encryption><member>$Encryption</member></encryption><lifetime><hours>$Lifetime</hours></lifetime>"
    }
}

function Add-IPSecCryptoProfile{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $IPSECProfiles = Import-Csv $CSVFileLocation

    foreach($Profile in $IPSECProfiles){
        $Name = "'" + $Profile.name + "'"
        $Authentication = $Profile.authentication
        $DHGroup = $Profile.dhgroup
        $Encryption = $Profile.encryption
        $Lifetime = $Profile.lifetime
        Invoke-WebRequest "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name=$Name]&element=<esp><authentication><member>$Authentication</member></authentication><encryption><member>$Encryption</member></encryption></esp><dh-group>$DHGroup</dh-group>"
    }
}

function Add-IKEGateway{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $IKEGateways = Import-Csv $CSVFileLocation

    foreach($Gateway in $IKEGateways){

        $Name = "'" + $Gateway.name + "'"
        $Version = $Gateway.version
        $Peer = $Gateway.peer
        $LocalIP = $Gateway.local
        $LocalInterface = $Gateway.interface
        $PSK = $Gateway.psk
        $DPD = $Gateway.dpd
        $IKEProfile = $Gateway.ikeprofile
        $NAT = $Gateway.natt
        $PeerID = $Gateway.peerid
        $PeerIDType = $Gateway.peeridtype
        $Fragmentation = $Gateway.fragmentation
        
        if($Peer -eq "dynamic" -or $Peer -eq "Dynamic"){
            $Peer = "<dynamic/>"
        }else{
            $Peer = "<ip>$Peer</ip>"
        }
       
        Invoke-WebRequest "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name=$Name]&element=<authentication><pre-shared-key><key>$PSK</key></pre-shared-key></authentication><protocol><ikev1><dpd><enable>$DPD</enable></dpd></ikev1><ikev2><dpd><enable>$DPD</enable></dpd><ike-crypto-profile>$IKEProfile</ike-crypto-profile></ikev2><version>$Version</version></protocol><local-address><ip>$LocalIP</ip><interface>$LocalInterface</interface></local-address><protocol-common><nat-traversal><enable>$NAT</enable></nat-traversal><fragmentation><enable>$Fragmentation</enable></fragmentation></protocol-common><peer-address>$Peer</peer-address><peer-id><id>$PeerID</id><type>$PeerIDType</type></peer-id>"                                                                                                                 

    }
}
                        
function Add-IPSecTunnel{
    Param(
        $TunnelCSVFile,
        $ProxyIDCSVFile,
        $APIKey,
        $FirewallIP
    )
    $IPSecTunnels = Import-Csv $TunnelCSVFile
    $ProxyIDs = Import-CSV $ProxyIDCSVFile

    foreach($Tunnel in $IPSecTunnels){
        $Name = "'" + $Tunnel.name + "'"
        $IKEGateway = "'" + $Tunnel.ikegateway + "'"
        $IPSecProfile = $Tunnel.ipseccrypto 
        $TunnelInterface= $Tunnel.tunnelinterface
        $ProxyIDString = $null
        foreach($ProxyID in $ProxyIDs){
            if(($ProxyID.tunnelname) -eq ($Tunnel.name)){
                $ProxyIDName = "'" + $ProxyID.proxyidname + "'"
                $Local = $ProxyID.local
                $Remote = $ProxyID.remote
                $Protocol = $ProxyID.protocol
                $ProxyIDString = $ProxyIDString + "<entry name=$ProxyIDName><protocol><$Protocol/></protocol><local>$Local</local><remote>$Remote</remote></entry>"
            }
        }
        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name=$Name]&element=<auto-key><ike-gateway><entry name=$IKEGateway/></ike-gateway><proxy-id>$ProxyIDString</proxy-id><ipsec-crypto-profile>$IPSecProfile</ipsec-crypto-profile></auto-key><tunnel-interface>$TunnelInterface</tunnel-interface>"
    }
}
              
              
function Add-SecurityZones{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    $SecurityZones = Import-Csv $CSVFileLocation

    foreach($SecZone in $SecurityZones){
        $Name = "'" + $SecZone.zonename + "'" 
        $Network = $SecZone.network
        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name=$Name]&element=<network><$Network/></network>"
    }
}
                       

function Add-NATRules{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )


    $NATRules = Import-Csv $CSVFileLocation    
    foreach($Rule in $NATRules){
        $Name = "'" + $Rule.name + "'"
        $BiDirectional = $Rule.bidirectional 
        $TranslatedAddress = $Rule.translation
        $NATType = $Rule.nattype
        $SrcZoneImport = $Rule.srczone
        $SrcImport = $Rule.src
        $DstZoneImport = $Rule.dstzone
        $DstImport = $Rule.dst
        $ServiceImport = $Rule.service
        $TagsImport = $Rule.tags
        $SrcZones = $SrcZoneImport.Split(";")
        $SrcNames = $SrcImport.Split(";")
        $DstZones = $DstZoneImport.Split(";")
        $DstNames = $DstImport.Split(";")
        $Services = $ServiceImport.Split(";")
        $Tags = $TagsImport.Split(";")
        $SrcNameString = $null
        $SrcZoneString = $null
        $DstNameString = $null
        $DstZoneString = $null
        $ServiceString = $null
        $TagString = $null
        
        if($Tags -ne $null){
            $TagString = "<tag>"
            foreach($Tag in $Tags){
                $TagString = $TagString + "<member>$Tag</member>"
            }
            $TagString = $TagString + "</tag>"
        }
        foreach($SrcZone in $SrcZones){
            $SrcZoneString = $SrcZoneString + "<member>$SrcZone</member>"
        }
        foreach($SrcName in $SrcNames){
            $SrcNameString = $SrcNameString + "<member>$SrcName</member>"
        }
        foreach($DstZone in $DstZones){
            $DstZoneString = $DstZoneString + "<member>$DstZone</member>"
        }
        foreach($DstName in $DstNames){
            $DstNameString = $DstNameString + "<member>$DstName</member>"
        }
        foreach($Service in $Services){
            $ServiceString = $ServiceString + "<member>$Service</member>"
        }
    
        if(($Rule.type) -eq "exemption"){
            $XMLString = "<to>$DstZoneString</to><from>$SrcZoneString</from><source>$SrcNameString</source><destination>$DstNameString</destination><service>$Service</service>"
        }
        if(($Rule.type) -eq "source"){
            $XMLString = "<source-translation><static-ip><translated-address>$TranslatedAddress</translated-address><bi-directional>$BiDirectional</bi-directional></static-ip></source-translation><to>$DstZoneString</to><from>$SrcZoneString</from><source>$SrcNameString</source><destination>$DstNameString</destination><service>$Service</service><nat-type>$NATType</nat-type>"
        }
        if(($Rule.type) -eq "destination"){
            $XMLString = "<to>$DstZoneString</to><from>$SrcZoneString</from><source>$SrcNameString</source><destination>$DstNameString</destination><destination-translation><translated-address>$TranslatedAddress</translated-address></destination-translation><service>$Service</service>"
        }

        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules/entry[@name=$Name]&element=$XMLString"
    }
}

function Add-StaticRoutes{
    Param(
        $CSVFileLocation,
        $APIKey,
        $FirewallIP
    )
    
    $StaticRoutes = Import-CSV $CSVFileLocation
    
    foreach($Route in $StaticRoutes){
        $Name = "'" + $Route.name + "'"
        $VirtualRouter = "'" + $Route.virtualrouter + "'"
        $Interface = $Route.interface
        $Metric = $Route.metric
        $Destination = $Route.destination 
        Invoke-WebRequest -UseBasicParsing "https://$FirewallIP/api/?key=$APIKey&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name=$VirtualRouter]/routing-table/ip/static-route/entry[@name=$Name]&element=<interface>$Interface</interface><metric>$Metric</metric><destination>$Destination</destination>"
    }

}