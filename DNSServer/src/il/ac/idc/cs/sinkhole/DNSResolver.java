package il.ac.idc.cs.sinkhole;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

public class DNSResolver {
    private static final int sk_HeaderSizeInBytes = 12;
    private static final int sk_QueryNumConstFieldsLength = 5;
    private static final int sk_AnswerNumConstFieldsLength = 11;
    private static final byte sk_DNSPointerHex = (byte) 0xc0;
    private static final byte sk_DNSFieldsEndHex = (byte) 0x00;
    private byte[] m_FullDNSMessage;
    // Header Fields
    private int m_ID;
    private int m_ANCOUNT;
    private int m_NSCOUNT;
    private int m_RCODE;
    private boolean m_IsQuery;
    // Query Fields
    private String m_QueryName;
    private int m_QueryNameEndOffset;
    // Response Fields
    private String m_AnswerAdressName;
    private int m_AdressAnswerEndOffset;
    private byte[] m_RDATA;
    private int m_RDATALength;

    // Empty Constructor - DNS Resolver
    public DNSResolver() {
    }

    // Load DNS Message to the resolver and analyze it
    public void SetDNSMessage(byte[] i_FullDNSMessage) {
        m_FullDNSMessage = i_FullDNSMessage;
        UpdateDNSResolver();
    }

    // Extract and store ID from DNS packet
    private void setID() {
        m_ID = ((m_FullDNSMessage[0] << 8) & (0x0FF00)) | (m_FullDNSMessage[1] & (0x0FF));
    }

    // Extract and store QR from DNS packet
    private void setQR() {
        m_IsQuery = m_FullDNSMessage[2] >> 7 == 0;
    }

    // Extract and store NSCOUNT from DNS packet
    private void setNSCOUNT() {
        m_NSCOUNT = ((m_FullDNSMessage[8] << 8) & (0x0FF00)) | (m_FullDNSMessage[9] & (0x0FF));
    }

    // Extract and store RCODE from DNS packet
    private void setRCODE() {
        m_RCODE = (m_FullDNSMessage[3]) & (0x000F);
    }

    // Extract and store ANCOUNT from DNS packet
    private void setANCOUNT() {
        m_ANCOUNT = ((m_FullDNSMessage[6] << 8) & (0x0FF00)) | (m_FullDNSMessage[7] & (0x0FF));
    }

    // Extract and store QueryName from DNS packet
    private void setQueryName() {
        byte[] queryName = getDataFromDNSPacket(sk_HeaderSizeInBytes, m_FullDNSMessage.length);
        m_QueryName = createServerStringFromArray(queryName);
        m_QueryNameEndOffset = sk_HeaderSizeInBytes + getFieldLength(sk_HeaderSizeInBytes);
    }

    // Extract and store AnswerAddressName from DNS packet
    private void setAnswerAddressName() {
        m_AnswerAdressName = null;
        m_AdressAnswerEndOffset = 0;

        if (!m_IsQuery && m_NSCOUNT > 0) {
            byte[] result = getDataFromDNSPacket(m_QueryNameEndOffset + sk_QueryNumConstFieldsLength, m_FullDNSMessage.length);
            m_AnswerAdressName = toStringDataArray(result);
            int startOfAdressAnswerOffset = m_QueryNameEndOffset + sk_QueryNumConstFieldsLength;
            m_AdressAnswerEndOffset = startOfAdressAnswerOffset + getFieldLength(m_QueryNameEndOffset + sk_QueryNumConstFieldsLength);
        }
    }

    // Extract and store RDATA Length from DNS packet
    private void setRDATALength() {
        m_RDATALength = 0;

        if (!m_IsQuery && m_NSCOUNT > 0) {
            m_RDATALength = ((m_FullDNSMessage[m_AdressAnswerEndOffset + 9] << 8) & 0x0FF00) | (m_FullDNSMessage[m_AdressAnswerEndOffset + 10] & 0x0FF);
        }
    }

    // Extract and store RDATA from DNS packet
    private void setRDATA() {
        m_RDATA = null;

        if (!m_IsQuery && m_NSCOUNT > 0) {
            m_RDATA = getDataFromDNSPacket(m_AdressAnswerEndOffset + sk_AnswerNumConstFieldsLength, m_RDATALength);
        }
    }

    // Get full DNS message loaded to resolver
    public byte[] GetFullMessage() {
        return m_FullDNSMessage;
    }

    // Get NSCOUNT from DNS message field loaded to resolver
    public int GetNSCOUNT() {
        return m_NSCOUNT;
    }

    // Get ANCOUNT from DNS message field loaded to resolver
    public int GetANCOUNT() {
        return m_ANCOUNT;
    }

    // Get RCODE from DNS message field loaded to resolver
    public int GetRCODE() {
        return m_RCODE;
    }

    // Get QueryName from DNS message field loaded to resolver
    public String GetQueryNameString() {
        return m_QueryName;
    }

    // Get data from DNS message
    private byte[] getDataFromDNSPacket(int i_Offset, int i_Length) {
        StringBuilder result = new StringBuilder();
        int currentIndex = i_Offset;
        int lengthCounter = 0;
        byte currentByte = m_FullDNSMessage[currentIndex];

        while (currentByte != sk_DNSFieldsEndHex && lengthCounter < i_Length) {
            if (currentByte == sk_DNSPointerHex) {
                result.append(getPointerData(currentIndex));
                break;
            } else {
                result.append((char) currentByte);
            }

            currentByte = m_FullDNSMessage[++currentIndex];
            lengthCounter++;
        }

        result.append((char) (0x00));

        return (result.toString()).getBytes();
    }

    // Return Data for pointer offset until hex 0x00 sign
    private StringBuilder getPointerData(int i_Offset) {
        StringBuilder result = new StringBuilder();
        int currentIndex = m_FullDNSMessage[i_Offset + 1];
        byte currentByte = m_FullDNSMessage[currentIndex];

        while (currentByte != sk_DNSFieldsEndHex) {
            result.append((char) currentByte);
            currentByte = m_FullDNSMessage[++currentIndex];
        }

        return result;
    }

    // Get field length from offset index
    private int getFieldLength(int i_Offset) {
        int fieldLength = 0;
        int currentIndex = i_Offset;
        byte currentByte = m_FullDNSMessage[currentIndex];

        while (currentByte != sk_DNSFieldsEndHex) {
            fieldLength++;

            if (currentByte == sk_DNSPointerHex) {
                break;
            }

            currentByte = m_FullDNSMessage[++currentIndex];
        }

        return fieldLength;
    }

    // Generate server string
    private String createServerStringFromArray(byte[] i_ByteArray) {
        int currentIndex = 0;
        int currentPartLength;
        StringBuilder resultStringBuilder = new StringBuilder();

        while (currentIndex < i_ByteArray.length - 1 && m_ANCOUNT == 0) {
            currentPartLength = i_ByteArray[currentIndex++];
            for (int i = 0; i < currentPartLength; i++) {
                resultStringBuilder.append((char) i_ByteArray[currentIndex++]);
            }
            if (currentIndex != i_ByteArray.length - 1)
                resultStringBuilder.append('.');
        }

        return resultStringBuilder.toString();
    }

    // Generate next hop InetAddress from RDATA string
    public InetAddress GetNextHopIP() {
        InetAddress nextHopIpAddress = null;

        try {
            nextHopIpAddress = InetAddress.getByName(createServerStringFromArray(m_RDATA));
        } catch (UnknownHostException i_E) {
            System.err.println("Can't resolve next hop ip address");
        }

        return nextHopIpAddress;
    }

    // Create string from byte array
    private String toStringDataArray(byte[] i_InputData) {
        return new String(Arrays.copyOfRange(i_InputData, 0, i_InputData.length));
    }

    // Print to console current resolver state
    public void printDNSMessageData() {
        try {
            UpdateDNSResolver();
            System.out.println("ID: " + m_ID);
            System.out.println("Is Query: " + m_IsQuery);
            System.out.println("ANCOUNT: " + m_ANCOUNT);
            System.out.println("NSCOUNT: " + m_NSCOUNT);
            System.out.println("RCODE: " + m_RCODE);
            System.out.println("QueryName: " + m_QueryName);
            if (m_NSCOUNT > 0) {
                System.out.println("AnswerAdressName: " + m_AnswerAdressName);
            }
            if (m_RDATA != null) {
                System.out.println("RDATALength: " + m_RDATALength);
                System.out.println("RDATA: " + createServerStringFromArray(m_RDATA));
            }
            System.out.println("----------------------------------------------------");
        } catch (Exception i_E) {
            System.err.println("DNSResolver Error - Print DNS Data Error");
        }
    }

    // Update resolver state
    public void UpdateDNSResolver() {
        setID();
        setQR();
        setANCOUNT();
        setNSCOUNT();
        setRCODE();
        setQueryName();
        if (!m_IsQuery && m_NSCOUNT > 0) {
            try {
                setAnswerAddressName();
            } catch (Exception i_E) {
                System.err.println("DNSResolver Error - setAnswerAdressName Error");
            }
            try {
                setRDATALength();
            } catch (Exception i_E) {
                System.err.println("DNSResolver Error - setRDATALength Error");
            }
            try {
                setRDATA();
            } catch (Exception i_E) {
                System.err.println("DNSResolver Error - setRDATA Error");
            }
        }
    }

}
