package com.example.yuxuan.netsniffer;

public class Packet {

    private String packetType;
    private String timestamp;
    private String sourceIP; // & port
    private String destIP; // & port
    private String flag;

    public Packet(String data){
        // String manipulation here
        this.packetType = "";
        this.timestamp = "";
        this.sourceIP = "";
        this.destIP = "";
        this.flag = "";
    }

    public String getPacketType(){ return packetType; }
    public String getTimestamp(){ return timestamp; }
    public String getSourceIP() { return sourceIP; }
    public String getDestIP() { return destIP; }
    public String getFlag() { return flag; }
}
