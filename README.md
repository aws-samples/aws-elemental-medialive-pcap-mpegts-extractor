## AWS Elemental Medialive Pcap Mpegts Extractor

MPEG TS extractor for tcpdump pcap captures

## License

This library is licensed under the Apache 2.0 License. 

#### 1. To compile the source, use any gcc or ANSI c compiler
   $ gcc tsextract.c -o tsextract
######   Repo contains a centos 7 compiled Linux executable.

#### 2. Usage: 

  ###### a. ./tsextract < [pcapfile]   > [tsfile]  
      The < and > are required, because the program uses file redirection i.e, reads from stdin and out to stdout.
  ###### b. You can filter by destination IP and Destination UDP port like this:
      ./tsextract [dest_ip] [dest_udp_port] < [pcapfile] > [tsfile]

#### 3. Features and Limitations:
   
  ###### a. This program is pretty barebones at the moment, but will extract MPEG-TS, and RTP payloads into output ts.
  ###### b. Works only with Ethernet captures, and UDP only.
  ###### c. At the moment, captures with VLAN headers are not supported. Will probably add that soon.
  ###### d. No support for Linux cooked captures. i.e, This will not work if you captured with tcpdump -i any ...
  ###### e. No support (yet) for filtering by source IP.
  ###### f. At the moment, dest IP and PORT are matched using string compare, so the match may fail if you use say, 10.01.02.03 instead of 10.1.2.3. (see below)
            To see what IP you should use, check with tcpdump -r [pcapfile]
 ###### g. Next generation pcaps are not supported. I will add that program in a bit
      

#### 4. Possible Next steps:

  ###### a. Add parsing for VLAN traffic.
  ###### b. Improve command line parsing code - which is a bit of a hack at the moment.
  ###### c. Add filtering based on source IP  
