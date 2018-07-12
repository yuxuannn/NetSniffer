package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class HelpActivity extends AppCompatActivity {


    /*** ListView ***/
    ItemAdapter itemAdapter;
    String[] dataArray;
    ListView listView;
    Context context;

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    private MapTest nmap;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_help);
        verifyStoragePermissions(this);
        context = this;
        nmap = new MapTest(context);
        listView = (ListView)findViewById(R.id.list);
   }


   public String getAddress(){
        TextView tv = findViewById(R.id.editText2);
        return tv.getText().toString();
   }

   public void start(View view){
        if(!nmap.isStarted)
            nmap.start("/data/data/com.example.yuxuan.netsniffer/nmap -sP "+getAddress()+" --datadir /data/data/com.example.yuxuan.netsniffer/ > /sdcard/Download/nmap.txt\n");
        else
            Toast.makeText(getApplicationContext(),"Nmap already started",Toast.LENGTH_SHORT).show();
   }


   public void addData(String data, final Context context){
       final String content = data;
       runOnUiThread(new Runnable(){
          @Override
          public void run(){

                listView = (ListView)findViewById(R.id.list);
                dataArray = content.split("\\n");

                itemAdapter = new ItemAdapter(context,dataArray);
                listView.setAdapter(itemAdapter);
           }
       });
   }


    public static void verifyStoragePermissions(Activity activity) {
        // Check if we have write permission
        int permission = ActivityCompat.checkSelfPermission(activity, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            // We don't have permission so prompt the user
            ActivityCompat.requestPermissions(
                    activity,
                    PERMISSIONS_STORAGE,
                    REQUEST_EXTERNAL_STORAGE
            );
        }
    }

    public class MapTest{

        private boolean isStarted;

        // command to launch nmap
        private String command;

        //  process where tcpdump will be executed
        private Process process;

        // pid of tcpdump process
        private int pid;

        // timer to create a process and exec tcpdump on it
        private Timer nmapTimer;

        // timer task to create a process and exec tcpdump
        private TimerTask nmapTimerTask;

        /*** display thread ***/
        // buffered reader to read file
        private BufferedReader reader;

        // timer to manage the display of packets
        private Timer displayTimer;

        // timer task that periodically reads the buffer and sends packets to the UI
        private TimerTask displayThread;

        // temporary string to replace buffer
        private String tempData;

        // temporary context
        private Context context;

        public MapTest(Context context){
            super();
            this.isStarted = false;
            tempData = "";
            this.context = context;
            init();
        }

        // initializes threads, process and timer task used for scanning
        private void init() {

            // init tcpdump timer task and launch tcpdump on it
            nmapTimerTask = new TimerTask() {
                public void run() {
                    try {
                        // create a process with root privilege
                        process = Runtime.getRuntime().exec("su");
                        DataOutputStream os = new DataOutputStream(process.getOutputStream());
                        os.writeBytes(command);
                        os.flush();
                        os.writeBytes("exit\n");
                        os.flush();
                        os.close();

                        // sleep 1 second to ensure that the new process is listed by the system
                        Thread.sleep(1000);

                        // get pid of process that exec tcpdump with ps command
                        Process process2 = Runtime.getRuntime().exec("su");
                        DataOutputStream dos = new DataOutputStream(process2.getOutputStream());
                        dos.writeBytes("ps | grep /data/data/com.example.yuxuan.netsniffer/nmap > /sdcard/Download/ps.txt\n");
                        dos.flush();
                        dos.writeBytes("exit\n");
                        dos.flush();
                        dos.close();

                        process2.destroy();
                    } catch (Exception e) {
                        // handle exception
                        e.printStackTrace();
                    }
                }
            };

            // init timer task that displays data to UI
            displayThread = new TimerTask() {
                public void run() {

                    boolean stop = false;
                    try {
                        File dumpedFile = new File("/sdcard/Download/nmap.txt");
                        //if(!dumpedFile.exists())
                        //    Toast.makeText(getApplicationContext(),"'output.txt' does not exist",Toast.LENGTH_SHORT).show();

                        reader = new BufferedReader(new FileReader(dumpedFile));
                        String temp;

                        //clearListView();

                        while ((temp = reader.readLine())!= null) {
                            Log.d("READ PKT:", temp);

                            if (temp.contains("Starting")) {
                                tempData += temp;
                                tempData += "\n";
                            } else if (temp.contains("MAC")) {
                                tempData += "\t"+temp;
                                tempData += "\n";
                            } else if (temp.contains("done")){
                                tempData += temp;
                                stop = true;
                            } else
                                tempData += " "+temp;

                        }

                    } catch(IOException io){
                        Log.d("IOEX",io.getMessage());
                        //Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show();
                    }

                    //String temp = buffer.toString();
                    addData(tempData,context);
                    tempData = "";
                    if(reader != null)
                        try { reader.close(); } catch(IOException io) { }//Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show(); }
                    //Log.d("Display Thread : ",temp);
                    if(stop)
                        stop();
                }
            };
        }


        // start scanning process
        public void start(String arg){
            isStarted = true;

            command = arg;
            init();

            // launch tcpdump process
            nmapTimer = new Timer();
            nmapTimer.schedule(nmapTimerTask,0);

            // send updates to UI every 3s
            displayTimer = new Timer(true);
            displayTimer.schedule(displayThread,3000,1000); // might require tweaking

        }

        // stop scanning process
        public void stop(){
            // stop display thread
            displayTimer.cancel();

            // stop the tcpdump process
            nmapTimer.cancel();
            process.destroy();
            //buffer.setLength(0);
            tempData = "";

            try{
                // a new process is spawned to kill ALL nmap processes, terminates immediately after
                File psFile = new File("sdcard/Download/ps.txt");
                BufferedReader br = new BufferedReader(new FileReader(psFile));
                String line, check = "root      ";
                while((line = br.readLine()) != null) {

                    if(line.contains(check)) {
                        Process process2 = Runtime.getRuntime().exec("su");
                        DataOutputStream os = new DataOutputStream(process2.getOutputStream());

                        for (int i = -1; (i = line.indexOf(check, i + 1)) != -1; i++) {
                            int index = i+10;
                            int endIndex = line.indexOf(" ",index);
                            pid = Integer.parseInt(new String(line.substring(index,endIndex)));
                            os.writeBytes("kill "+pid+"\n");
                            os.flush();
                        }

                        os.writeBytes("exit\n");
                        os.flush();
                        os.close();
                    }
                }
            } catch(IOException io){
                //Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show();
            }

            // delete temporary ps file
            try{
                Process process2 = Runtime.getRuntime().exec("su");
                DataOutputStream os = new DataOutputStream(process2.getOutputStream());
                os.writeBytes("rm /sdcard/Download/ps.txt\n");
                os.flush();
                os.writeBytes("exit\n");
                os.flush();
                os.close();
            } catch(IOException io){ }

            // delete the temporary output file
            try{
                Process process2 = Runtime.getRuntime().exec("su");
                DataOutputStream os = new DataOutputStream(process2.getOutputStream());
                os.writeBytes("rm /sdcard/Download/nmap.txt\n");
                os.flush();
                os.writeBytes("exit\n");
                os.flush();
                os.close();
            } catch(IOException io){
                io.printStackTrace();
            }

            // to restart the process, re init threads and timers
            init();
            isStarted = false;
            command = "";
        }


        public boolean isStarted(){
            return isStarted;
        }

    }

}
