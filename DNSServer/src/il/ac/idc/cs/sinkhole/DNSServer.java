package il.ac.idc.cs.sinkhole;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Random;

public class DNSServer {

    private final String[] k_RootServers = { "a.root-servers.net", "b.root-servers.net", "c.root-servers.net", "d.root-servers.net", "e.root-servers.net", "f.root-servers.net", "g.root-servers.net", "h.root-servers.net", "i.root-servers.net", "j.root-servers.net", "k.root-servers.net", "l.root-servers.net", "m.root-servers.net" };
    private static final int sk_UDPDNSBufferSize = 1024;
    private static final int sk_DNSPort = 53;
    private static final int sk_ServerListenPort = 5300;
    private static final int sk_MaxRequestCount = 16;
    private static final int sk_MSTimeOutUDPSocket = 2000;
    private static final int sk_AmoutOfTimeForUDPPacketResend = 3;
    private static Random s_RandomObj = new Random();
    private DatagramSocket m_ServerSocketClient;
    private BlockList m_BlockList;
    private int m_RemainingResendTries;

    // Empty Constructor - run when there is not a blocklist file as parameter
    public DNSServer() {
        this("");
    }

    // BlockList Constructor - run when there is a blocklist file as parameter
    public DNSServer(String i_BlockListURL) {
        m_BlockList = new BlockList(i_BlockListURL);
        try {
            m_ServerSocketClient = new DatagramSocket(sk_ServerListenPort);
        } catch (SocketException i_E) {
            System.err.println("Had issue to create server socket for requests");
        }
    }

    // DNS server Listen on port 5300 for DNS requests
    public void Listen() {
        try {
            byte[] dnsAnswer;
            System.out.println("DNS Server is listening to requests");
            while (true) {
                DatagramPacket receivedClientDatagramPacket = serverGetData(m_ServerSocketClient);
                if (!isNeedToBlockAddress(receivedClientDatagramPacket)) {
                    dnsAnswer = findIPIteratively(minimizePacketMessageLength(receivedClientDatagramPacket));
                    serverSendData(m_ServerSocketClient, receivedClientDatagramPacket.getAddress(), receivedClientDatagramPacket.getPort(), updateFlagsOnDNSLegalAnswer(dnsAnswer));
                } else {
                    dnsAnswer = minimizePacketMessageLength(receivedClientDatagramPacket);
                    serverSendData(m_ServerSocketClient, receivedClientDatagramPacket.getAddress(), receivedClientDatagramPacket.getPort(), updateFlagsOnDNSIllegalAnswer(dnsAnswer));
                }
            }
        } catch (Exception i_E) {
            System.err.println(i_E.getMessage() + " - Server Listen Error");
        } finally {
            m_ServerSocketClient.close();
        }
    }

    // Check if the DNS request is valid or should be block
    private boolean isNeedToBlockAddress(DatagramPacket i_DatagramPacket) {
        DNSResolver dnsResolver = new DNSResolver();
        dnsResolver.SetDNSMessage(i_DatagramPacket.getData());

        return m_BlockList.IsInBlockList(dnsResolver.GetQueryNameString());
    }

    // Find DNS answer iteratively for client request
    private byte[] findIPIteratively(byte[] i_DatagramPacketClientRequest) {
        DatagramSocket serverSocket = null;
        DNSResolver dnsResolver = new DNSResolver();
        int iterationCounter = 0;

        try {
            serverSocket = new DatagramSocket();
            serverSocket.setSoTimeout(sk_MSTimeOutUDPSocket);
            serverSendData(serverSocket, getRandomRootServerIP(), sk_DNSPort, i_DatagramPacketClientRequest);
            try {
                dnsResolver.SetDNSMessage(serverGetData(serverSocket).getData());
            } catch (Exception i_E) {
                serverSendData(serverSocket, getRandomRootServerIP(), sk_DNSPort, i_DatagramPacketClientRequest);
            }
            while (iterationCounter <= sk_MaxRequestCount && dnsResolver.GetNSCOUNT() > 0 && dnsResolver.GetRCODE() == 0 && dnsResolver.GetANCOUNT() == 0) {
                serverSendData(serverSocket, dnsResolver.GetNextHopIP(), sk_DNSPort, i_DatagramPacketClientRequest);
                try {
                    DatagramPacket currentDatagramPacketReply = serverGetData(serverSocket);
                    dnsResolver.SetDNSMessage(minimizePacketMessageLength(currentDatagramPacketReply));
                } catch (Exception i_E) {
                    if (m_RemainingResendTries > 0) { // Try to resend packet
                        serverSendData(serverSocket, dnsResolver.GetNextHopIP(), sk_DNSPort, i_DatagramPacketClientRequest);
                    } else {
                        return generateServerFailureAnswer(i_DatagramPacketClientRequest);
                    }
                    m_RemainingResendTries--;
                }
                iterationCounter++;
            }
        } catch (SocketException i_E) {
            System.err.println(i_E.getMessage() + " - Find IP Iteratively Error");
        } finally {
            serverSocket.close();
        }

        return dnsResolver.GetFullMessage();
    }

    // Server get DatagramPacket and resolve it using DNSResolver class
    private DatagramPacket serverGetData(DatagramSocket i_ServerSocket) throws Exception {
        DatagramPacket receivedDatagramPacket = null;
        DNSResolver dnsResolver = new DNSResolver();
        byte[] receivedData = new byte[sk_UDPDNSBufferSize];

        receivedDatagramPacket = new DatagramPacket(receivedData, receivedData.length);
        i_ServerSocket.receive(receivedDatagramPacket);
        dnsResolver.SetDNSMessage(receivedDatagramPacket.getData());
        m_RemainingResendTries = sk_AmoutOfTimeForUDPPacketResend;

        return receivedDatagramPacket;
    }

    // Server send DatagramPacket
    private void serverSendData(DatagramSocket i_ServerSocket, InetAddress i_ReceiverIP, int i_ReceiverPort, byte[] i_Message) {
        try {
            DatagramPacket sendDatagramPacket = new DatagramPacket(i_Message, i_Message.length, i_ReceiverIP, i_ReceiverPort);
            i_ServerSocket.send(sendDatagramPacket);
        } catch (Exception i_E) {
            System.err.println(i_E.getMessage() + " - Send Data Error");
        }
    }

    // Get random root server for first query
    private InetAddress getRandomRootServerIP() {
        int rootServerIndex = s_RandomObj.nextInt(k_RootServers.length);
        InetAddress inetAddressResult = null;

        try {
            inetAddressResult = InetAddress.getByName(k_RootServers[rootServerIndex]);
        } catch (UnknownHostException i_E) {
            System.err.println("Had issues to get random root DNS server");
        }

        return inetAddressResult;
    }

    // Minimize message length of DatagramPacket
    private byte[] minimizePacketMessageLength(DatagramPacket i_DatagramPacket) {
        return Arrays.copyOfRange(i_DatagramPacket.getData(), 0, i_DatagramPacket.getLength());
    }

    // Update DNS flags to server failure
    private byte[] generateServerFailureAnswer(byte[] i_DNSRequestMessage) {
        i_DNSRequestMessage[2] = (byte) (i_DNSRequestMessage[2] | 0x81);
        i_DNSRequestMessage[3] = (byte) 0x82;

        return i_DNSRequestMessage;
    }

    // Update DNS flags on legal request
    private byte[] updateFlagsOnDNSLegalAnswer(byte[] dnsAnswerMessage) {
        dnsAnswerMessage[2] = (byte) (dnsAnswerMessage[2] & 0xFB);
        dnsAnswerMessage[3] = (byte) (dnsAnswerMessage[3] | 0x80);

        return dnsAnswerMessage;
    }

    // Update DNS flags on ILlegal request
    private byte[] updateFlagsOnDNSIllegalAnswer(byte[] dnsAnswerMessage) {
        dnsAnswerMessage[2] = (byte) (dnsAnswerMessage[2] | 0x81);
        dnsAnswerMessage[3] = (byte) 0x83;

        return dnsAnswerMessage;
    }

}
