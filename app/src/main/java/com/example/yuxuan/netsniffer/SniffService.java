package com.example.yuxuan.netsniffer;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.support.annotation.Nullable;
import android.util.Log;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class SniffService extends Service {

    @Nullable
    @Override
    public IBinder onBind(Intent intent){
        return null;
    }


    @Override
    public int onStartCommand(Intent intent, int flags, int startID){
        Toast.makeText(this,"Sniff Service Started!",Toast.LENGTH_LONG).show();

        // start sniffing - run TCPDump dual threads
        return START_STICKY;
    }

    @Override
    public void onDestroy(){
        super.onDestroy();

        try {
            Process p = Runtime.getRuntime().exec("ps tcpdump");
            DataInputStream is = new DataInputStream(p.getInputStream());

            ByteArrayOutputStream res = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while((length = is.read(buffer)) != -1){
                res.write(buffer,0,length);
            }
            String temp = res.toString("UTF-8");

            temp = temp.replaceAll("^root *([0-9]*).*", "$1");
            int pid = Integer.parseInt(temp);

            p.destroy();

            p = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(p.getOutputStream());
            String kill = "kill " + pid;
            os.writeBytes(kill);
            os.flush();
            os.writeBytes("exit\n");
            os.flush();
            os.close();

            p.destroy();

        } catch(IOException io){
            Log.d("TCPDUMP IOEX:",io.getMessage());
        }

        Toast.makeText(this,"Sniff Service Destroyed",Toast.LENGTH_LONG).show();
    }
}
