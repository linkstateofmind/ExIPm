# ExIPm
External IP Lookup via MaxMind Database (CSV format)

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
