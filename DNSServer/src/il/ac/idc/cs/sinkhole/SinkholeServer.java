package il.ac.idc.cs.sinkhole;

public class SinkholeServer {

    // Program Entry Point
    public static void main(String[] args) {
        DNSServer dnsServer = null;

        // Create DNS server with or without blocklist according to command parameters
        if (args.length == 1) {
            dnsServer = new DNSServer(args[0]);
        } else {
            dnsServer = new DNSServer();
        }

        // DNS server start listen to requests
        dnsServer.Listen();
    }

}
