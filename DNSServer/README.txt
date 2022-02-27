Name: Harel Zahari  Username: harel.zahari
Name: Naor Zaharia   Username: naor.zaharia

SinkholeServer.java:
Entry point of the program, it creates the DNSServer according to the input parameters (with or without blocklist) and starts listening for DNS requests on port 5300.

DNSServer.java:
Listens to DNS request from clients on port 5300, and iteratively finds an answer for the DNS request using queries to the DNS server port 53. (Class also handle UDP timeouts or packets lost and set relevent flags to DNS packets when send answer)

DNSResolver.java:
The class parsing a DNS packet to the relevant fields, this way we could see the server progress and get relevent data while the DNSServer listens or working on DNS requests.

BlockList.java:
Load a blocklist file into memory (using HashSet data structure) and providing methods for query such as iterating the collection or getting info about it (like if a site is on blocklist or not etc).