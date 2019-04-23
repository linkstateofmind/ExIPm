<#################################################################
    .NAME  
        ExIPm.ps1

    .SYNOPSIS  
        External IP lookup script - localized with MaxMind

    .DESCRIPTION
        Lookup external IPv4 and IPv6 addresses from Maxmind GeoIP database. 
        Features full validation of bogon and RFC 1918 space filtering.

        This script performs the following:
        o Prepares the Maxmind Geolite2 database in csv format for both IPv4 and IPv6
            * Calculates the start and end IPs for a netblock
            * Converts start and end IPv4 netblocks into longint (int64) format
            * Converts start and end IPv6 netblocks into bigint format
            * Merges ASN and City Location data into two master CSVs for IPv4 and IPv6

        o Performs input validation to quickly parse and identify IP addresses 
            * Parses and validates random input into arrays of IPv4 and IPv6 formatted strings
            * Converts input IP Address into longint or bigint format for range validation
            * Validates input contains only non-RFC1918 IPv4 and non-Reserved IPv6 Addresses
        o Handles connections to 3 million+ row CSV as if it were a Database
         
            * Query Function with object input provides query, provider, and connection string data
            * Queries Maxmind CSV with a SQL BETWEEN statement to determine if integer in range

        o Populates objects with specified results and returns content to console or csv output.

    .NOTES  
        Name:           ExIPm.ps1
        Author:         Ben Leedham
        Title:          Security Engineer
        Date Created:   09/01/2015
        Maxmind added:  10/19/2018
        Last Updated:   04/15/2019

    .USAGE  
        C:\Utilities\ExIPm.ps1 -ip "1.0.98.55"
        VERBOSE: Performing IP Address validation and bogon filtering.
        VERBOSE: 0) 1.0.98.55, 16802359, 4

        ip           : 1.0.98.55
        network      : 1.0.98.0/23
        asn          : 18144
        hostname     : 55.98.0.1.megaegg.ne.jp
        city         : Okayama
        continent    : Asia
        country      : Japan
        isocode      : JP
        organization : Energia Communications
        region       : Okayama
        subregion    : 
        timezone     : Asia/Tokyo
        coordinates  : 34.6615, 133.9332
        postal       : 700-0821
        geoid        : 1854383

    .COMMENTS
        Resolves external IP Addresses locally using the Maxmind database (CSV format). 
        This script stemmed from multiyear incident response efforts, which required extensive use
        of IP resolution for IPv4 and IPv6.  
        
        While other utilities perform the same function, this script allows for greater extensibility 
        with other custom written tools.  Gives a greater perspective for how these values are handled 
        in security and networking systems.

        Links to other code included where reference material was used.

        Download Maxmind from:
        https://dev.maxmind.com/geoip/geoip2/geoip2-city-country-csv-databases/

#####################>

Param(
[string]$ip,
[switch]$file,
[switch]$export,
[string]$path = $("C:\Utilities"),
$ExecutionPolicy = $(Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Scope CurrentUser),
$VerbosePreference = $("silentlycontinue"),
$ErrorActionPreference = $("continue")
)
###########################################
# Maxmind Dataset Merging Functions - IPv4 & IPv6
##########
# Merges the Maxmind Geolite2 database csvs into one record based on specific criteria for IPv4 and IPv6.
# In an effort to reduce the number of queries per IP, opted to preprocess and combine this information.
# As the data is stored in a 3 million line CSV, reducing time per query is important.
#
# Impractical to use import-csv on a 3 million line csv, so it is treated like a database.


Function Prepare-MaxmindCity($s)
{
# Function 1 - initial prep for merge ASN, Locations, and IPBlock csvs
# Run once, then keep in case you need to recreate the process - takes hours to run
switch ($s) 
{
    4 {$name = "GeoLite2-City-Blocks-IPv4"}
    6 {$name = "GeoLite2-City-Blocks-IPv6"}
}

Write-Verbose -Message $name -Verbose

$v1 = New-Object PSObject
$v1 | Add-Member NoteProperty -Name "csv" -Value "$path\Libraries\GeoLite2\$name.csv"
$v1 | Add-Member NoteProperty -Name "table" -Value (Split-Path $v1.csv -leaf).Replace(".","#")
$v1 | Add-Member NoteProperty -Name "sql" -Value "SELECT network,geoname_id,postal_code,latitude,longitude FROM [$($v1.table)]"

Write-Verbose -Message $v1.csv
Write-Verbose -Message $v1.table
Write-Verbose -Message $v1.sql

$prep = $(Query-CSV -object $v1)

write-verbose -Message "$($prep[0].network), $($prep[0].geoname_id)"

# Streamwriter is faster for creating csvs and functions similarly to python read/writes.
$streamWriter = [System.IO.StreamWriter] "$path\Libraries\GeoLite2\$name-update.csv"
[string]$writeout = "network,ip_int_start,ip_int_end,geoid,postal,latitude,longitude"
$streamWriter.WriteLine($writeout);

    for($c=0; $c -lt $prep.count; $c++)
    {
        $data = Get-IPStartEnd -network $prep[$c].network
        [string]$writeout = $($prep[$c].network) + ","`
                            + $($data.ip_int_start) + ","`
                            + $($data.ip_int_end) + ","`
                            + $($prep[$c].geoname_id) + ","`
                            + $($prep[$c].postal_code) + ","`
                            + $($prep[$c].latitude) + ","`
                            + $($prep[$c].longitude)

        $streamWriter.WriteLine($writeout);

        if($c -match "[0-9]{1,3}0000$")
        {
            # Writes $c every 10000 elements
            Write-Verbose -message $c -Verbose
        }
    }
$streamWriter.close();
$streamWriter.Dispose();
}


Function Prepare-MaxmindASN($s)
{
# Function 2 - Prep ASN csv
# Run once, then keep in case you need to recreate the process - takes hours to run.
switch ($s) 
{
    4 {$name = "GeoLite2-ASN-Blocks-IPv4"}
    6 {$name = "GeoLite2-ASN-Blocks-IPv6"}
}

write-verbose -Message $name -Verbose


$v1 = New-Object PSObject
$v1 | Add-Member NoteProperty -Name "csv" -Value "$path\Libraries\GeoLite2\$name.csv"
$v1 | Add-Member NoteProperty -Name "table" -Value (Split-Path $v1.csv -leaf).Replace(".","#")
$v1 | Add-Member NoteProperty -Name "sql" -Value "SELECT network,autonomous_system_number,autonomous_system_organization FROM [$($v1.table)]"

Write-verbose -Message $v1.csv
Write-verbose -Message $v1.table
Write-verbose -Message $v1.sql

$prep = $(Query-CSV -object $v1)

write-verbose -Message "$($prep[0].network), $($prep[0].autonomous_system_number)"

# Streamwriter is faster for creating csvs and functions similarly to python read/writes.
$streamWriter = [System.IO.StreamWriter] "$path\Libraries\GeoLite2_20181009\$name-update.csv"
[string]$writeout = "network,ip_int_start,ip_int_end,asn,org"
$streamWriter.WriteLine($writeout);

    for($c=0;$c -lt $prep.count;$c++)
    {
        $data = Get-IPStartEnd -network $prep[$c].network

        [string]$writeout = $($prep[$c].network) + ","`
                            + $($data.ip_int_start) + ","`
                            + $($data.ip_int_end) + ","`
                            + $($prep[$c].autonomous_system_number) + ","`
                            + $($prep[$c].autonomous_system_organization)

        $streamWriter.WriteLine($writeout);

        if($c -match "[0-9]{1,3}0000$")
        {
            # Writes $c every 10000 elements
            Write-Verbose -message $c -Verbose
        }
    }
$streamWriter.close();
$streamWriter.Dispose();
}


Function Merge-MaxmindData($s)
{
# Function 3 - merge ASN, Locations, and IPBlock csvs
# Run once, then keep in case you need to recreate the process - takes hours to run
switch ($s) 
{
    4 {$name = "Blocks-IPv4"}
    6 {$name = "Blocks-IPv6"}
}

write-verbose -Message $name -Verbose

$v1 = New-Object PSObject
$v1 | Add-Member NoteProperty -Name "csv" -Value "$path\Libraries\GeoLite2\GeoLite2-City-$name-update.csv"
$v1 | Add-Member NoteProperty -Name "table" -Value (Split-Path $v1.csv -leaf).Replace(".","#")
$v1 | Add-Member NoteProperty -Name "sql" -Value "SELECT network,ip_int_start,ip_int_end,geoid,postal,latitude,longitude FROM [$($v1.table)]"

Write-verbose -Message $v1.csv
Write-verbose -Message $v1.table
Write-verbose -Message $v1.sql

$prep = $(Query-CSV -object $v1)

# Streamwriter is faster for creating csvs and functions similarly to python read/writes.
$streamWriter = [System.IO.StreamWriter] "$path\Libraries\GeoLite2\GeoLite2-City-$name-update2.csv"

[string]$writeout = "network,"`
                    + "ip_int_start,"`
                    + "ip_int_end,"`
                    + "asn,"`
                    + "geoid,"`
                    + "city,"`
                    + "continent,"`
                    + "country,"`
                    + "isocode,"`
                    + "org,"`
                    + "region,"`
                    + "subregion,"`
                    + "timezone,"`
                    + "postal,"`
                    + "latitude,"`
                    + "longitude"

$streamWriter.WriteLine($writeout);

    for($c=0;$c -lt $prep.count;$c++)
    {
        $v2 = New-Object PSObject
        $v2 | Add-Member NoteProperty -Name "csv" -Value "$path\Libraries\GeoLite2\GeoLite2-City-Locations-en.csv"
        $v2 | Add-Member NoteProperty -Name "table" -Value $(Split-Path $v2.csv -leaf).Replace(".","#")
        $v2 | Add-Member NoteProperty -Name "geoid" -Value $prep[$c].geoid
        $v2 | Add-Member NoteProperty -Name "sql" -Value "SELECT * from [$($v2.table)] WHERE geoid like $($prep[$c].geoid)"

        $obj2 = $(Query-CSV -object $v2)

        [int]$value = $prep[$c].ip_int_start
        $v3 = New-Object PSObject
        $v3 | Add-Member NoteProperty -Name "csv" -Value "$path\Libraries\GeoLite2\GeoLite2-ASN-$name-update.csv"
        $v3 | Add-Member NoteProperty -Name "table" -Value $(Split-Path $v3.csv -leaf).Replace(".","#")
        $v3 | Add-Member NoteProperty -Name "sql" -Value "SELECT * from [$($v3.table)] WHERE $value BETWEEN ip_int_start and ip_int_end"

        $obj3 = $(Query-CSV -object $v3)

        [string]$writeout = $($prep[$c].network) + ","`
                            + $($prep[$c].ip_int_start) + ","`
                            + $($prep[$c].ip_int_end) + ","`
                            + $($obj3.asn) + ","`
                            + $($prep[$c].geoid) + ","`
                            + $($obj2.city_name) + ","`
                            + $($obj2.continent) + ","`
                            + $($obj2.country) + ","`
                            + $($obj2.isocode) + ","`
                            + $($obj3.org) + ","`
                            + $($obj2.region) + ","`
                            + $($obj2.subregion) + ","`
                            + $($obj2.timezone) + ","`
                            + $($prep[$c].postal) + ","`
                            + $($prep[$c].latitude) + ","`
                            + $($prep[$c].longitude)

        $streamWriter.WriteLine($writeout);

        if($c -match "[0-9]{1,3}0000$")
        {
            # Writes $c every 10000 elements
            Write-Verbose -message $c -Verbose
        }
    }
$streamWriter.close();
$streamWriter.Dispose();
}

####################
# Utility Functions
######


Function Get-IPStartEnd($network)
{<######################################### 
    .SYNOPSIS  
        Get the start and end IP addresses for both IPv4 and IPv6

    .DESCRIPTION
        This function contains converts IPv4 and IPv6 network addresses with cidr masks
        into binary strings to determine start and end of a range. The script converts IPv4 to
        network address and broadcast address, then it converts those numbers into INT64 values (longint).
        This function converts IPv6 addresses based on hextets and cidr masks.  Depending on the cidr mask,
        it will determine the high end and low end of a range.  These values are converted into bigint format.

    .NOTES
        Author    Ben Leedham
        Title     Security Engineer
        Date      03/29/2019

    .EXAMPLE 
        Get-IPrangeStartEnd -network 192.168.8.3/24

    .REFERENCES
        https://gallery.technet.microsoft.com/scriptcenter/Start-and-End-IP-addresses-bcccc3a9
        https://stackoverflow.com/questions/42118198/parsing-ipv6-cidr-into-first-address-and-last-address-in-powershell
        https://gallery.technet.microsoft.com/scriptcenter/Ipv6-to-Decimal-Number-ff06bcb1

    .COMMENTS
        Major alterations to original scripts and code samples for input values, logic, datatypes, etc.
        Removed superfluous functions and repurposed code to create a better start/end function.

        IPv4 Conversion Process
        Using cidr, calculates subnet mask, from subnet max performs binary anding (-band) and binary xoring (-bxor) 
        to determine network and broadcast addresses. Result produces values that are converted to LongInt (int64) format. 
        Significantly shorter than integer IPv6 addresses.

        IPv6 Conversion Process
        Process goes Hextet String Network address -> Binary String IPv6 Network address  ->  Binary String IPV6 (start/end)
        -> Hextet IPv6 Addresses (start/end) -> Two 8 byte long byte arrays -> Shift byte arrays to appropriate position ->
        Converts and produces Bigint integer values for start and end addresses.

        Comparison
        In both scenarios, the numbers represent a conversion of where (in total count) they reside among all network addresses.
        Start and end represents an integer value for the entire range that can be arithmatically compared.
        Effectively allows for range comparisons regardless of input.
        IPv6 conversion function needs additional work.
#########################################>
    try
    {
    # Common variables
    [string]$network = $network
    [string]$ip = $($network -split "/")[0]
    [int64]$cidr = $($network -split "/")[1]
        
        # IPv4 conversion below
        if($network -match "\.")
        {
            Function Convert-IPtoINT64 ($ip) 
            { 
                [array]$octets = $ip.split(".") 
                [int64]$int64 = $($([int64]$octets[0]*16777216)`
                                + $([int64]$octets[1]*65536)`
                                + $([int64]$octets[2]*256)`
                                + $([int64]$octets[3]))
            return $int64;
	        } 

	        Function Convert-INT64toIP ($int)
            { 
                $var = $(([math]::truncate($int/16777216)).tostring() + "."`
                       + ([math]::truncate(($int%16777216)/65536)).tostring() + "."`
                       + ([math]::truncate(($int%65536)/256)).tostring() + "."`
                       + ([math]::truncate($int%256)).tostring())
        
            return $var;
	        } 

	        if ($ip) 
            {
                $ipaddr = [Net.IPAddress]::Parse($ip)
            } 
	        if ($cidr) 
            {
                $cidrbin = $("1"*$cidr+"0"*(32-$cidr))
                $cidrint64 = [Convert]::ToInt64($cidrbin,2)
                $mask_dec = Convert-INT64toIP -int $cidrint64
                $maskaddr = [Net.IPAddress]::Parse($mask_dec)
            }
	        if ($ip) 
            {
			    $networkaddr = New-Object Net.IPAddress ($maskaddr.address -band $ipaddr.address)
            } 
	        if ($ip) 
		    {
			    $broadcastaddr = New-Object Net.IPAddress ([System.Net.IPAddress]::parse("255.255.255.255").address `
			                     -bxor $maskaddr.address -bor $networkaddr.address)
		    } 

            [int64]$startaddr = Convert-IPtoINT64 -ip $networkaddr.ipaddresstostring
            [int64]$endaddr = Convert-IPtoINT64 -ip $broadcastaddr.ipaddresstostring
        }

        # IPv6 conversion below
        if($network -match ":")
        {
            [array]$hextets = $($ip -replace '::','').Split(':')


            Function Get-BinIP($hextets)
            {
                [array]$binip = @()
                foreach($hextet in $hextets)
                {
                    [string]$hextet ='0x'+ $hextet
                    [string]$bin = [Convert]::ToString($hextet, 2).PadLeft(16,'0')
                    [array]$binip += $bin
                }

                [string]$binip = $binip -join ''
                return $binip
            }


            Function Get-BinStartEnd($binip, $cidr)
            {
                # Checks to see if the binary string is less than 64 bytes
                If($binip.Length -lt $cidr.length)
                {
                    [int]$difference = $cidr.Length - $binip.Length
                    [string]$missing = ("1" * $difference).ToString()
                    $missing = $missing.Padleft(16,'0')
                    [string]$binip = $($binip + $missing) -replace ',',''
                    $binstart = $binip.PadRight(128,'0')
                    $binend = $binip.PadRight(128,'1')
                }
                elseIf($binip.Length -ge $cidr.length)
                {
                    # Add binary 1 to IPv6 Binary string to avoid collapsing the address
                    # otherwise IPAddress .NET Class will cause byte conversion to fail.
                    #
                    [string]$binstart = $binip.substring(0, $cidr).padright(127,'0').padright(128,'1')
                    [string]$binend = $binip.substring(0, $cidr).padright(128,'1')
                }
                return $binstart, $binend
            }


            Function Convert-BintoIPv6 ($binary)
            {
                [array]$bin = @()
                [array]$hextets = @()
                While ($binary)
                { 
                    $x, $binary = ([char[]]$binary).where({$_}, 'Split', 16)
                    [array]$bin += $x -join ''
                }

                foreach($hextet in $bin)
                {
                    $hextet = [Convert]::ToInt32("$hextet",2)
                    [array]$hextets += '{0:X4}' -f $hextet
                }

                [string]$ipv6 = $hextets -join ':'
                return $ipv6
            }

    
            Function Convert-IPv6toBigInt($ip)
            {
                # Convert IP Address to binary format
                $bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    
                if ([System.BitConverter]::IsLittleEndian)
                {
                    [array]::reverse([BigInt[]]$bytes)
                }

                # Distribute the 16 bytes into 2 nodes and convert to unsigned 64 bit integer
                [BigInt[]]$BigIntArray = @(0,0);
                $BigIntArray[0] += [BitConverter]::ToUInt64($bytes, 8)
                $BigIntArray[1] = [BitConverter]::ToUInt64($bytes, 0)

                # Shift left each byte to 64 bits to get the multiples of 2 each bit
                $BigIntArray[0] = $BigIntArray[0] -shl 64
                [bigint]$integer_ip = $BigIntArray[0] + $BigIntArray[1]
                return $integer_ip
            }

            [string]$binip = Get-BinIP -hextets $hextets
            [string]$binstart = $(Get-BinStartEnd -binip $binip -cidr $cidr)[0]
            [string]$binend = $(Get-BinStartEnd -binip $binip -cidr $cidr)[1]

            [ipaddress]$startip = Convert-BintoIPv6 -binary $binstart
            [ipaddress]$endip = Convert-BintoIPv6 -binary $binend
            [bigint]$startaddr = Convert-IPv6toBigInt -ip $startip
            [bigint]$endaddr = Convert-IPv6toBigInt -ip $endip

            Write-Verbose -Message $startip
            Write-Verbose -Message $endip
            Write-Verbose -Message $startaddr
            Write-Verbose -Message $endaddr
            
        }
    }
    catch{}

    $PSObject = New-Object PSObject
    $PSObject | Add-Member NoteProperty -Name "network" -Value $network
    $PSObject | Add-Member NoteProperty -Name "ip_int_start" -Value $startaddr
    $PSObject | Add-Member NoteProperty -Name "ip_int_end" -Value $endaddr

return $PSObject
}


Function Query-CSV($object)
{<######################################### 
    .SYNOPSIS  
        Connect to a CSV as if it was a database using a connection string 
        and retrieve values from tables via SQL.  Accepts a custom PSObject with specific values.

    .EXAMPLE 
        $v1 = New-Object PSObject
        $v1 | Add-Member NoteProperty -Name "csv" -Value 'GeoLite2-City-Blocks-IPv4-update.csv'
        $v1 | Add-Member NoteProperty -Name "table" -Value (Split-Path $v1.csv -leaf).Replace(".","#")
        $v1 | Add-Member NoteProperty -Name "integer_ip" -Value $integer_ip
        $v1 | Add-Member NoteProperty -Name "sql" -Value "SELECT * from [$($v1.table)] WHERE $integer_ip BETWEEN ip_int_start and ip_int_end"
    
        Query-CSV -object $v1

    .REFERENCES
        Borrows heavily from reference material, but includes several customizations.
        https://www.powershellmagazine.com/2015/05/12/natively-query-csv-files-using-sql-syntax-in-powershell/
        https://codereview.stackexchange.com/questions/140892/powershell-script-to-read-line-by-line-large-csv-files
###########################################>
    try
    {
        $firstRowColumnNames = "Yes"
        $delimiter = ","

        # Identify installed providers and choose 16 as default
        $provider_elements = $(New-Object System.Data.OleDb.OleDbEnumerator).GetElements() 
        $provider = $provider_elements | Where-Object { $_.SOURCES_NAME -like "Microsoft.ACE.OLEDB.*" }
        if ($provider -is [system.array]) 
        { 
            $provider = $provider.SOURCES_NAME | where {$_ -match "16"}
        } 
        else 
        {
            $provider = $provider.SOURCES_NAME 
        }

        # Create Connection String
        $conn = New-Object System.Data.OleDb.OleDbConnection("Provider=$provider;"`
							      + "Data Source=$(Split-Path $object.csv);"`
							      + "Extended Properties='text;"`
							      + "HDR=$firstRowColumnNames;"`
							      + "FMT=Delimited';")
        $conn.open()
        $cmd = New-Object System.Data.OleDB.OleDBCommand
        $cmd.Connection = $conn
        $cmd.CommandText = $object.sql

        $datatable = New-Object System.Data.DataTable
        $datatable.Load($cmd.ExecuteReader("CloseConnection"))

        $cmd.Dispose() | Out-Null
        $conn.Close() | Out-Null
        $conn.Dispose() | Out-Null

        return $datatable;
    }
    catch
    {
        Write-Verbose -Message "An Error occurred in the query." -Verbose
    }
}

#######################
# Validation Functions
######


Function Validate-IPs($ip)
{<#####################
    .SYNOPSIS 
         Performs IP Address validation for IPv4 and IPv6 addresses,
         returning them in an array for further processing.

    .DESCRIPTION 
        Original code from my script titled "Exip.ps1."  I've modified and included validation code 
        that verifies IPv6 and IPv6 format match, filters RFC1918 space, and filters reserved 
        IPv6 addressing.
        
    .NOTES 
        Name:       Validate-IPs
        Author:     Ben Leedham
        Title:      Security Engineer
        Date:       04/15/2019

    .USAGE
        Validate-IPs -ip "8.8.8.8"

    .COMMENT
        IPv6 Regular expression was borrowed. Logic and function setup is original work.  
        Used reference material for IP to byte conversions and Reserved/RFC 1918 space addresses.

    .REFERENCE
        Reference included for RFC compliant IPv6 matching Regular Expression
        https://www.powershelladmin.com/wiki/PowerShell_.NET_regex_to_validate_IPv6_address_(RFC-compliant)

#####################> 
    [string]$regv4 = "(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    [array]$ipv4 = $($ip | select-string -Pattern $regv4 -AllMatches | % { $_.Matches.Groups } | where{$_.value}) | select -Unique

    [string]$regv6 = ':(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))'
    [array]$ipv6 = $($ip | select-string -Pattern $regv6 -AllMatches | % { $_.Matches.Groups } | where{$_.value}) | select -Unique

    [array]$intiparray = @()

    Write-Verbose -Message "Performing IP Address validation and bogon filtering." -Verbose
    For($c1=0; $c1 -lt $($ipv4.value).count; $c1++)
    {
        try
        {
            [ipaddress]$ia = $ipv4[$c1].value
            [array]$io = $ia.IPAddressToString -split "\."
            if([int]$io[0] -eq "10"){continue}
            elseif([int]$io[0] -eq "127"){continue}
            elseif([int]$io[0] -eq "128" -and [int]$io[1] -eq "0"){continue}
            elseif([int]$io[0] -eq "169" -and [int]$io[1] -eq "254"){continue}
            elseif([int]$io[0] -eq "172" -and [int]$io[1] -ge "16" -and [int]$io[1] -le "32"){continue}
            elseif([int]$io[0] -eq "191" -and [int]$io[1] -eq "255"){continue}
            elseif([int]$io[0] -eq "192" -and [int]$io[1] -eq "0" -and [int]$io[2] -eq "0"){continue}
            elseif([int]$io[0] -eq "192" -and [int]$io[1] -eq "0" -and [int]$io[2] -eq "2"){continue}
            elseif([int]$io[0] -eq "192" -and [int]$io[1] -eq "168"){continue}
            elseif([int]$io[0] -eq "198" -and [int]$io[1] -eq "18"){continue}
            elseif([int]$io[0] -eq "198" -and [int]$io[1] -eq "19"){continue}
            elseif([int]$io[0] -eq "223" -and [int]$io[1] -eq "255" -and [int]$io[2] -eq "255"){continue}
            elseif([int]$io[0] -gt "224"){continue}
            elseif([int]$io[0] -eq "0"){continue}
            else
            {
                # Convert IP Address to binary format
                $bytes = [System.Net.IPAddress]::Parse($ia).GetAddressBytes()

                if ([BitConverter]::IsLittleEndian) 
                {
                    [Array]::Reverse($bytes)
                }
                [int64]$integer_ip = [BitConverter]::ToUInt32($bytes, 0)

                # Added to a custom psobject for easy output
                $PSObj = New-Object PSObject
                $PSObj | Add-Member NoteProperty -Name "ipaddress" -Value $ia.IPAddressToString
                $PSObj | Add-Member NoteProperty -Name "decimal" -Value $integer_ip
                $PSObj | Add-Member NoteProperty -Name "type" -Value 4
                [array]$intiparray += $PSObj

                Write-Verbose -message "$c1) $($PSObj.ipaddress), $($PSObj.decimal), $($PSObj.type)" -Verbose
            }
        }
        catch{}
    }
    For($c2=0; $c2 -lt $($ipv6.value).count; $c2++)
    {
        try
        {
            [ipaddress]$ib = $ipv6[$c2].value
            [array]$ih = $ib -split ":"
            if([int]$ih[0] -eq "fe80"){continue}
            elseif([int]$ih[0] -eq "0000"){continue}
            elseif([int]$ih[0] -eq "0200"){continue}
            elseif([int]$ih[0] -eq "3ffe"){continue}
            elseif([int]$ih[0] -eq "2001" -and [int]$ih[1] -eq "db8"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "e000"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "7f00"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "0000"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "ff00"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "0a00"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "ac10"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "c0a8"){continue}
            elseif([int]$ih[0] -eq "fc00"){continue}
            elseif([int]$ih[0] -eq "fec0"){continue}
            elseif([int]$ih[0] -eq "ff00"){continue}
            else
            {
                # Convert IP Address to binary format
                $bytes = [System.Net.IPAddress]::Parse($ib).GetAddressBytes()

                if ([System.BitConverter]::IsLittleEndian)
                {
                    [array]::reverse([BigInt[]]$bytes)
                }

                # Distribute the 16 bytes into 2 nodes and convert to unsigned 64 bit integer
                [BigInt[]]$BigIntArray=@(0,0);
                $BigIntArray[0] += [BitConverter]::ToUInt64($bytes,8);
                $BigIntArray[1] = [BitConverter]::ToUInt64($bytes,0);

                # Shift left each byte to 64 bits to get the multiples of 2 each bit
                $BigIntArray[0] = $BigIntArray[0] -shl 64;
                [Bigint]$integer_ip6 = $BigIntArray[0] + $BigIntArray[1];

                # Added to a custom psobject for easy output
                $PSObj = New-Object PSObject
                $PSObj | Add-Member NoteProperty -Name "ipaddress" -Value $ib.IPAddressToString
                $PSObj | Add-Member NoteProperty -Name "decimal" -Value $integer_ip6
                $PSObj | Add-Member NoteProperty -Name "type" -Value 6
                [array]$intiparray += $PSObj

                Write-Verbose -message "$c2) $($PSObj.ipaddress), $($PSObj.decimal), $($PSObj.type)" -Verbose
            }
        }
        catch{}
    }

    return $intiparray
}


####################
# Main Function
######
Function Run-Main($ip)
{
    $intiparray = Validate-IPs -ip $ip
    For($ia=0; $ia -lt $($intiparray| Measure-Object).count; $ia++)
    {
        [string]$type = $intiparray[$ia].type

        $query = New-Object PSObject
        $query | Add-Member NoteProperty -Name "csv" -Value "$path\Libraries\GeoLite2\GeoLite2-City-Blocks-IPv$type-update2.csv"
        $query | Add-Member NoteProperty -Name "table" -Value $(Split-Path $query.csv -leaf).Replace(".","#")
        $query | Add-Member NoteProperty -Name "sql" -Value "SELECT * FROM [$($query.table)] WHERE $($intiparray[$ia].decimal) BETWEEN ip_int_start and ip_int_end"

        $obj = Query-CSV -object $query

        try
        {
            [string]$ToIP = $intiparray[$ia].ipaddress
            [string]$DNShost = [System.Net.Dns]::GetHostEntry($ToIP).hostname
            [string]$latlong = "$($obj.latitude), $($obj.longitude)"
        }
        catch{continue}

        $PSObject = New-Object PSObject
        $PSObject | Add-Member NoteProperty -Name "ip" -Value $ToIP
        $PSObject | Add-Member NoteProperty -Name "network" -Value $obj.network
        $PSObject | Add-Member NoteProperty -Name "asn" -Value $obj.asn
        $PSObject | Add-Member NoteProperty -Name "hostname" -Value $DNShost
        $PSObject | Add-Member NoteProperty -Name "city" -Value $obj.city
        $PSObject | Add-Member NoteProperty -Name "continent" -Value $obj.continent
        $PSObject | Add-Member NoteProperty -Name "country" -Value $obj.country
        $PSObject | Add-Member NoteProperty -Name "isocode" -Value $obj.isocode
        $PSObject | Add-Member NoteProperty -Name "organization" -Value $obj.org
        $PSObject | Add-Member NoteProperty -Name "region" -Value $obj.region
        $PSObject | Add-Member NoteProperty -Name "subregion" -Value $obj.subregion
        $PSObject | Add-Member NoteProperty -Name "timezone" -Value $obj.timezone
        $PSObject | Add-Member NoteProperty -Name "coordinates" -Value $latlong
        $PSObject | Add-Member NoteProperty -Name "postal" -Value $obj.postal
        $PSObject | Add-Member NoteProperty -Name "geoid" -Value $obj.geoid
    
        if($export.IsPresent){$global:array += $PSObject}
        Write-Output $PSObject
    }
}


####################
# Main Execution
######

# Running main function with conditional logic for input/output

if([string]$ip -ne "" -and -not [switch]$file.IsPresent)
{
    if([switch]$export.IsPresent)
    {
        [array]$global:array = @()
        [datetime]$date = Get-Date -Format "yyyyMMdd-hhmm"
        [string]$csv = "ExIPs-" + $date + ".csv"
        [string]$logging = "$path\Logs\ExIPs\$csv"

        New-Item -Path $logging -ItemType "File" -Force | Out-Null
        Run-Main -ip $ip
        $global:array | Export-Csv -NoTypeInformation -Path $logging
        Remove-Variable -Name $global:array -ErrorAction "SilentlyContinue" -Force
    }
    else
    {
        Run-Main -ip $ip
    }
}

if([switch]$file.IsPresent)
{
    [string]$data = $(Get-Content -Path "$path\Libraries\ExIPfile.txt" | Out-String)
    if([switch]$export.IsPresent)
    {
        [array]$global:array = @()
        [datetime]$date = Get-Date -Format "yyyyMMdd-hhmm"
        [string]$csv = "ExIPs-" + $date + ".csv"
        [string]$logging = "$path\Logs\ExIPs\$csv"

        New-Item -Path $logging -ItemType "File" -Force | Out-Null
        Run-Main -ip $data
        $global:array | Export-Csv -NoTypeInformation -Path $logging
        Remove-Variable -Name $global:array -ErrorAction "SilentlyContinue" -Force
    }
    else
    {
        Run-Main -ip $data
    }
}
