package com.example.yuxuan.netsniffer;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = findViewById(R.id.editText);
        tv.setText("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam eget turpis vehicula nibh ultricies ornare." +
                " Aenean hendrerit ullamcorper pretium. Quisque ut augue consectetur, ornare leo ut, iaculis tellus.");
        tv.setKeyListener(null);
        // Example of a call to a native method
        // TextView tv = (TextView) findViewById(R.id.sample_text);
        // tv.setText(stringFromJNI());
    }

    public void getRoot(View view){
        Toast toast;
        toast = Toast.makeText(getApplicationContext(), "Granting root to NetSniffer!",Toast.LENGTH_SHORT);
        toast.show();
/*
        Process suProcess;
        try{
            suProcess = Runtime.getRuntime().exec("su");

            DataOutputStream os = new DataOutputStream(suProcess.getOutputStream());
            DataInputStream is = new DataInputStream(suProcess.getInputStream());
            suProcess.waitFor();

            if(os != null && is != null){
                os.writeBytes("id\n");
                os.flush();

                ByteArrayOutputStream res = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while((length = is.read(buffer)) != -1){
                    res.write(buffer,0,length);
                }
                String currUid = res.toString("UTF-8");
                //String currUid = is.readLine();
                boolean suGranted = false;
                if(currUid == null){
                    Log.d("ROOT:","Unable to get root access");
                    Toast.makeText(getApplicationContext(),"Unable to get root access",Toast.LENGTH_LONG).show();
                }

                else if(currUid.contains("uid=0")){
                    suGranted = true;
                    Log.d("ROOT:","Root access granted");
                    Toast.makeText(getApplicationContext(),"Root access granted",Toast.LENGTH_LONG).show();

                    // copy tcpdump to memory
                    InputStream fis = this.getAssets().open("tcpdump");
                    byte[] fbuffer = new byte[fis.available()];
                    fis.read(fbuffer);
                    fis.close();

                    File targetFile = new File("/data/data/com.example.yuxuan.netsniffer/tcpdump");
                    OutputStream fos = new FileOutputStream(targetFile);
                    fos.write(fbuffer);
                    fos.close();

                    Process p = Runtime.getRuntime().exec("/system/bin/chmod 744 /data/data/com.example.yuxuan.netsniffer/tcpdump");
                    p.waitFor();
                    p.destroy();
                    Toast.makeText(getApplicationContext(),"TCPDump extracted",Toast.LENGTH_LONG).show();
                }

                else{
                    Log.d("ROOT:","Root access rejected");
                    Toast.makeText(getApplicationContext(), "Root access rejected",Toast.LENGTH_LONG).show();
                }

                os.writeBytes("exit\n");
                os.flush();

                is.close();
                os.close();
                suProcess.destroy();

                if(!suGranted){
                    is.close();
                    os.close();
                    suProcess.destroy();
                    System.exit(0);
                }
            }



        } catch (Exception e){
            Log.d("ROOT:","Root access failed ["+e.getClass().getName()+"] : "+e.getMessage());
            Toast.makeText(getApplicationContext(),"IOException : exec(su) failed",Toast.LENGTH_SHORT).show();
        }
*/
        File res = new File("/data/data/com.example.yuxuan.netsniffer/tcpdump");
        if(!res.exists()){
            Log.d("TCPDump Resource: ","TCPDump binary does not exist");
            // copy tcpdump to memory
            try {
                InputStream fis = this.getAssets().open("tcpdump");                // !!!!!
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
                toast = Toast.makeText(getApplicationContext(),"Sniff!",Toast.LENGTH_SHORT);
                toast.show();
                intent = new Intent(this,SniffActivity.class);
                startActivity(intent);
                return true;

            case R.id.setting:
                toast = Toast.makeText(getApplicationContext(), "Setting!", Toast.LENGTH_SHORT);
                toast.show();
                intent = new Intent(this, SettingActivity.class);
                startActivity(intent);
                return true;

            case R.id.help:
                toast = Toast.makeText(getApplicationContext(), "Help!", Toast.LENGTH_SHORT);
                toast.show();
                intent = new Intent(this, SettingActivity.class);
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
