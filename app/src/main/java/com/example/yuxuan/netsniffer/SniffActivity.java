package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.provider.ContactsContract;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import org.w3c.dom.Text;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class SniffActivity extends AppCompatActivity{

    private TCPDump tcpdump;

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sniff);

        TextView display;
        display = (TextView) findViewById(R.id.sniffDisplay);
        display.setKeyListener(null);
        display.setText("To start, choose an option from the menu on the top right");

        verifyStoragePermissions(this);
        tcpdump = new TCPDump();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.sniff_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        Toast toast;
        switch (item.getItemId()) {
            case R.id.start_live:
                toast = Toast.makeText(getApplicationContext(),"Start Live",Toast.LENGTH_SHORT);
                toast.show();

                // start live service, output to screen
                if(!tcpdump.isStarted())
                    tcpdump.start();

                return true;

            case R.id.start_pcap:
                toast = Toast.makeText(getApplicationContext(), "Start PCAP", Toast.LENGTH_SHORT);
                toast.show();

                // start live pcap
                if(!tcpdump.isStartedPCAP())
                    tcpdump.startPCAP();

                return true;

            case R.id.stop_sniff:
                toast = Toast.makeText(getApplicationContext(),"Stop Sniff", Toast.LENGTH_SHORT);
                toast.show();

                // stop live pcap
                if(tcpdump.isStarted() || tcpdump.isStartedPCAP)
                    tcpdump.stop();

                return true;

            case R.id.clear_live:
                toast = Toast.makeText(getApplicationContext(), "Clear List", Toast.LENGTH_SHORT);
                toast.show();

                // clear current list on screen
                getDisplay().setText("To start, choose an option from the menu on the top right");

                return true;

            default:
                return super.onOptionsItemSelected(item);
        }

    }


    public void updateDisplay(String content){
        final String data = content;
        runOnUiThread(new Runnable(){
            @Override
            public void run(){
                TextView tv = (TextView)findViewById(R.id.sniffDisplay); tv.setText(data);
            }
        });
    }

    public TextView getDisplay(){
        TextView tv = (TextView)findViewById(R.id.sniffDisplay);
        return tv;
    }

    public class TCPDump{

        private boolean isStarted;
        private boolean isStartedPCAP;

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

        /*** PCAP ***/
        // running instance
        private int counter;

        // pcap process
        private Process pcapProcess;

        // pcap timer
        private Timer pcapTimer;

        // pcap timertask
        private TimerTask pcapTimerTask;

        public TCPDump(){
            super();

            this.isStarted = false;
            this.isStartedPCAP = false;
            counter = 0;
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

                        // sleep to ensure that the new process is listed by the system
                        Thread.sleep(1000);

                        // get pid of process that exec tcpdump with ps command
                        Process process2 = Runtime.getRuntime().exec("su");
                        DataOutputStream dos = new DataOutputStream(process2.getOutputStream());
                        dos.writeBytes("ps | grep /data/data/com.example.yuxuan.netsniffer/tcpdump > /sdcard/Download/ps.txt\n");
                        dos.flush();
                        dos.writeBytes("exit\n");
                        dos.flush();
                        dos.close();

                        /*** THIS PART DOES NOT WORK ***/
                        DataInputStream is = new DataInputStream(process2.getInputStream());
                        BufferedReader br = new BufferedReader(new InputStreamReader(is));
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while((line = br.readLine()) != null)
                            sb.append(line + "\n");

                        updateDisplay(sb.toString());

                        String[] tempArray = sb.toString().split(" ");
                        for(int i=0; i<tempArray.length; i++){
                            if(tempArray[i].equals("root"))
                                pid = Integer.parseInt(tempArray[i+1]);
                        }

                        /*** ***/

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
                        /*if(!dumpedFile.exists())
                            Toast.makeText(getApplicationContext(),"'output.txt' does not exist",Toast.LENGTH_SHORT).show();
                        */
                        reader = new BufferedReader(new FileReader(dumpedFile));
                        String temp;


                        while ((temp = reader.readLine())!= null) {
                            Log.d("READ PKT:", temp);
                            tempData += temp;
                            tempData += "\n---\n";
                            //updateDisplay(temp);
                        }

                    } catch(IOException io){
                        Log.d("IOEX",io.getMessage());
                    }

                    updateDisplay(tempData);
                    tempData = "";
                    if(reader != null)
                        try { reader.close(); } catch(IOException io) { }//Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show(); }


                }
            };

            pcapTimerTask = new TimerTask() {
                public void run() {
                    try {
                        // create a process with root privilege
                        pcapProcess = Runtime.getRuntime().exec("su");
                        DataOutputStream os = new DataOutputStream(pcapProcess.getOutputStream());
                        os.writeBytes("/data/data/com.example.yuxuan.netsniffer/tcpdump -i wlan0 -w /sdcard/Download/output-"+counter+".pcap\n");
                        os.flush();
                        os.writeBytes("exit\n");
                        os.flush();
                        os.close();

                        // sleep 1 second to ensure that the new process is listed by the system
                        Thread.sleep(1000);

                        // get pid of process that exec tcpdump with ps command
                        Process process2 = Runtime.getRuntime().exec("su");
                        DataOutputStream dos = new DataOutputStream(process2.getOutputStream());
                        dos.writeBytes("ps | grep /data/data/com.example.yuxuan.netsniffer/tcpdump > /sdcard/Download/ps.txt\n");
                        dos.flush();
                        dos.writeBytes("exit\n");
                        dos.flush();
                        dos.close();

                        /*** THIS PART DOES NOT WORK ***/
                        DataInputStream is = new DataInputStream(process2.getInputStream());
                        BufferedReader br = new BufferedReader(new InputStreamReader(is));
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while((line = br.readLine()) != null)
                            sb.append(line + "\n");

                        updateDisplay(sb.toString());

                        String[] tempArray = sb.toString().split(" ");
                        for(int i=0; i<tempArray.length; i++){
                            if(tempArray[i].equals("root"))
                                pid = Integer.parseInt(tempArray[i+1]);
                        }

                        /*** ***/

                        process2.destroy();
                    } catch (Exception e) {
                        //Toast.makeText(getApplicationContext(),e.getMessage(),Toast.LENGTH_SHORT).show();
                        e.printStackTrace();
                    }
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
            displayTimer.schedule(displayThread,3000,1000); // might require tweaking

        }

        public void startPCAP(){
            isStartedPCAP = true;

            // launch PCAP process
            pcapTimer = new Timer();
            pcapTimer.schedule(pcapTimerTask,0);

            updateDisplay("Sniffing to PCAP ... ");
        }


        // stop scanning process
        public void stop(){

            if(isStarted){
                // stop display thread
                displayTimer.cancel();

                // stop the tcpdump process
                tcpdumpTimer.cancel();
                process.destroy();
                //buffer.setLength(0);
                tempData = "";
            }
            if(isStartedPCAP){
                counter += 1;
                pcapTimer.cancel();
                pcapProcess.destroy();
                updateDisplay("PCAP saved as "+getFileName());
            }

            // destroy the tcpdump process doesn't cause the process to be stopped on the system
            // to achieve that the process must be killed
            try{
                // a new process is spawned to kill ALL tcpdump processes, terminates immediately after
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
                os.writeBytes("rm /sdcard/Download/output.txt\n");
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
            isStartedPCAP = false;
        }


        public boolean isStarted(){ return isStarted;}

        public boolean isStartedPCAP(){
            return isStartedPCAP;
        }

        public String getFileName(){
            return "output-"+(counter-1)+".pcap";
        }

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
}