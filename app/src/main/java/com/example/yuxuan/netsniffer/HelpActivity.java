package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
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
import java.util.Timer;
import java.util.TimerTask;

public class HelpActivity extends AppCompatActivity {


    ArrayAdapter<String> adapter;
    ArrayList<String> dataBuffer;
    ListView listView;

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    private TCPDump tcpDump;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_help);
        verifyStoragePermissions(this);
        tcpDump = new TCPDump();
        init();
   }

   public void init(){
        //adapter.clear();
        dataBuffer = new ArrayList<String>();
        adapter = new ArrayAdapter<String>(this,android.R.layout.simple_list_item_1,dataBuffer);
        listView = (ListView)findViewById(R.id.list);
        listView.setAdapter(adapter);
        addData("Packet Information");
   }

   public void start(View view){
        tcpDump.start();
   }

   public void stop(View view){
        tcpDump.stop();
        //clearListView();
   }

   public void addData(String data){
       final String content = data;
       runOnUiThread(new Runnable(){
          @Override
          public void run(){
                String[] tempDataArray = content.toString().split("\\n");
                dataBuffer.clear();
                for(int i=0; i<tempDataArray.length; i++){
                    dataBuffer.add(tempDataArray[i]);
                }
                adapter = new ArrayAdapter<String>(HelpActivity.this,android.R.layout.simple_list_item_1,dataBuffer);
                listView.setAdapter(adapter);
           }
       });
   }

   public void clearListView(){
        adapter.clear();
        dataBuffer.clear();
        adapter.notifyDataSetChanged();
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

    public class TCPDump{

        private boolean isStarted;

        /***tcpdump***/
        // command to launch tcpdump
        private final String command = "/data/data/com.example.yuxuan.netsniffer/tcpdump -l -i wlan0 > /sdcard/Download/output.txt\n";

        //  process where tcpdump will be executed
        private Process process;

        // pid of tcpdump process
        private int pid;

        // timer to create a process and exec tcpdump on it
        private Timer tcpdumpTimer;

        // timer task to create a process and exec tcpdump
        private TimerTask tcpdump;

        /*** display thread ***/
        // buffered reader to read file
        private BufferedReader reader;

        // timer to manage the display of packets
        private Timer displayTimer;

        // timer task that periodically reads the buffer and sends packets to the UI
        private TimerTask displayThread;

        // temporary string to replace buffer
        private String tempData;

        public TCPDump(){
            super();
            //buffer = new StringBuffer(size);
            this.isStarted = false;
            tempData = "";
            init();
        }

        // initializes threads, process and timer task used for scanning
        private void init() {

            // init tcpdump timer task and launch tcpdump on it
            tcpdump = new TimerTask() {
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
                        Process process2 = Runtime.getRuntime().exec("ps /data/data/com.example.yuxuan.netsniffer/tcpdump");
                        // read output of ps
                        DataInputStream is = new DataInputStream(process2.getInputStream());

                        ByteArrayOutputStream res = new ByteArrayOutputStream();
                        byte[] tempBuffer = new byte[3072];
                        int length;
                        while ((length = is.read(tempBuffer)) != -1) {
                            res.write(tempBuffer, 0, length);
                        }

                        String temp = res.toString("UTF-8");

                        temp = temp.replaceAll("^root *([0-9]*).*","$1");
                        pid = Integer.parseInt(temp);
                        Log.d("PID (TCP): ", "" + pid);

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

                    try {
                        File dumpedFile = new File("/sdcard/Download/output.txt");
                        //if(!dumpedFile.exists())
                        //    Toast.makeText(getApplicationContext(),"'output.txt' does not exist",Toast.LENGTH_SHORT).show();

                        reader = new BufferedReader(new FileReader(dumpedFile));
                        String temp;

                        clearListView();

                        while ((temp = reader.readLine())!= null) {
                            Log.d("READ PKT:", temp);
                            //addData(temp);
                            tempData += temp;
                            tempData += "\n";
                            //updateDisplay(temp);
                        }

                    } catch(IOException io){
                        Log.d("IOEX",io.getMessage());
                        //Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show();
                    }

                    //String temp = buffer.toString();
                    addData(tempData);
                    //tempData = "";
                    if(reader != null)
                        try { reader.close(); } catch(IOException io) { }//Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show(); }
                    //Log.d("Display Thread : ",temp);

                }
            };
        }


        // start scanning process
        public void start(){
            isStarted = true;

            // launch tcpdump process
            tcpdumpTimer = new Timer();
            tcpdumpTimer.schedule(tcpdump,0);

            // send updates to UI every 3s
            displayTimer = new Timer(true);
            displayTimer.schedule(displayThread,5000,1000); // might require tweaking

        }

        // stop scanning process
        public void stop(){
            // stop display thread
            displayTimer.cancel();

            // stop the tcpdump process
            tcpdumpTimer.cancel();
            process.destroy();
            //buffer.setLength(0);
            tempData = "";

            // destroy the tcpdump process doesn't cause the process to be stopped on the system
            // to achieve that the process must be killed
            try{
                // a new process is spawned to kill tcpdump, terminates immediately after
                String killCommand = "kill "+pid;
                Process process2 = Runtime.getRuntime().exec("su");
                DataOutputStream os = new DataOutputStream(process2.getOutputStream());
                os.writeBytes(killCommand);
                os.flush();
                os.writeBytes("exit\n");
                os.flush();
                os.close();
            } catch(IOException io){
                //Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show();
            }

            // delete the temporary output file
            try{
                Process process2 = Runtime.getRuntime().exec("su");
                DataOutputStream os = new DataOutputStream(process2.getOutputStream());
                os.writeBytes("rm /sdcard/Download/output.txt\n");
                os.flush();
                os.close();
            } catch(IOException io){
                io.printStackTrace();
            }

            // to restart the process, re init threads and timers
            init();
            isStarted = false;
        }


        public boolean isStarted(){
            return isStarted;
        }

    }

}
