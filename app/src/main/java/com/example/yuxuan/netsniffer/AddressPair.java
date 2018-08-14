package com.example.yuxuan.netsniffer;

public class AddressPair {

    private String address;
    private int value;

    AddressPair(String address, int value){
        this.address = address;
        this.value = value;
    }

    AddressPair(int value, String address){
        this.address = address;
        this.value = value;
    }

    public String getAddr(){
        return address;
    }

    public void setAddr(String address){
        this.address = address;
    }

    public int getValue(){
        return value;
    }

    public void setValue(int value){
        this.value = value;
    }

    public void incrementByOne(){
        this.value += 1;
    }

    public boolean addrEquals(String addr){
        if(address.equals(addr))
            return true;
        return false;
    }
}
