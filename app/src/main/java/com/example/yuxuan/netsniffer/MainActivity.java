package com.example.yuxuan.netsniffer;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Html;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringWriter;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    boolean check;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = findViewById(R.id.editText);
        check = checkResources();
        if(!check)
            tv.setText("NetSniffer requires certain resources to function, press the button below to copy the required binaries to device internal storage");
        else
            tv.setText("NetSniffer has required resources, to proceed, choose an option on the top right menu");

        tv.setKeyListener(null);

        // Example of a call to a native method
        // TextView tv = (TextView) findViewById(R.id.sample_text);
        // tv.setText(stringFromJNI());
    }

    public boolean checkResources(){

        boolean flag = false;

        File res = new File("/data/data/com.example.yuxuan.netsniffer/tcpdump");
        File res1 = new File("/data/data/com.example.yuxuan.netsniffer/nmap");
        if(res.exists() && res1.exists())
           flag = true;


        return flag;
    }

    public void getRes(View view){
        Toast toast;
        toast = Toast.makeText(getApplicationContext(), "Fetching NetSniffer resources",Toast.LENGTH_SHORT);
        toast.show();

        File resTCPDump = new File("/data/data/com.example.yuxuan.netsniffer/tcpdump");
        if(!resTCPDump.exists()){

            // copy tcpdump to memory
            try {
                InputStream fis = this.getAssets().open("tcpdump");
                byte[] fbuffer = new byte[fis.available()];
                fis.read(fbuffer);
                fis.close();

                File targetFile = new File("/data/data/com.example.yuxuan.netsniffer/tcpdump");
                OutputStream fos = new FileOutputStream(targetFile);
                fos.write(fbuffer);
                fos.close();

                Process p = Runtime.getRuntime().exec("/system/bin/chmod 777 /data/data/com.example.yuxuan.netsniffer/tcpdump");
                p.waitFor();
                p.destroy();

                Log.d("TCPDump Resource: ","TCPDump binary saved on device");

            } catch (IOException io){
                Log.d("TCPDump res (IOEX): ",io.getMessage());
            } catch (InterruptedException ie){
                Log.d("TCPDump res (INTEX): ",ie.getMessage());

            }
        }

        File resNmap = new File("/data/data/com.example.yuxuan.netsniffer/nmap");
        if(!resNmap.exists()){

            // copy tcpdump to memory
            try {
                InputStream fis = this.getAssets().open("nmap");
                byte[] fbuffer = new byte[fis.available()];
                fis.read(fbuffer);
                fis.close();

                File targetFile = new File("/data/data/com.example.yuxuan.netsniffer/nmap");
                OutputStream fos = new FileOutputStream(targetFile);
                fos.write(fbuffer);
                fos.close();

                Process p = Runtime.getRuntime().exec("/system/bin/chmod 777 /data/data/com.example.yuxuan.netsniffer/nmap");
                p.waitFor();
                p.destroy();


                Log.d("NMAP Resource: ","Nmap binary saved on device");

            } catch (IOException io){
                Log.d("Nmap res (IOEX): ",io.getMessage());
            } catch (InterruptedException ie){
                Log.d("Nmap res (INTEX): ",ie.getMessage());

            }
        }
        check = true;
        Toast.makeText(getApplicationContext(),"Completed",Toast.LENGTH_SHORT).show();
        TextView tv = findViewById(R.id.editText);
        tv.setText("NetSniffer has required resources, to proceed, choose an option on the top right menu");
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item){

        Toast toast;
        Intent intent;
        switch(item.getItemId()){

            case R.id.sniff_service:
                if(check) {
                    toast = Toast.makeText(getApplicationContext(), "Sniff", Toast.LENGTH_SHORT);
                    toast.show();
                    intent = new Intent(this, SniffActivity.class);
                    startActivity(intent);
                } else
                    Toast.makeText(getApplicationContext(),"NetSniffer cannot proceed",Toast.LENGTH_SHORT).show();
                return true;

            case R.id.map_service:
                toast = Toast.makeText(getApplicationContext(), "Map", Toast.LENGTH_SHORT);
                toast.show();
                intent = new Intent(this, MapActivity.class);
                startActivity(intent);
                return true;

            case R.id.setting:
                toast = Toast.makeText(getApplicationContext(), "Setting", Toast.LENGTH_SHORT);
                toast.show();
                intent = new Intent(this, SettingActivity.class);
                startActivity(intent);
                return true;

            case R.id.help:
                toast = Toast.makeText(getApplicationContext(), "Help", Toast.LENGTH_SHORT);
                toast.show();
                intent = new Intent(this, HelpActivity.class);
                startActivity(intent);
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
