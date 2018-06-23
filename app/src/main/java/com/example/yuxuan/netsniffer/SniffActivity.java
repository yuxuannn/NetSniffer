package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Handler;
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

            case R.id.stop_live:
                toast = Toast.makeText(getApplicationContext(), "Stop Live", Toast.LENGTH_SHORT);
                toast.show();

                // stop live service
                if(tcpdump.isStarted())
                    tcpdump.stop();

                return true;

            case R.id.save_pcap:
                toast = Toast.makeText(getApplicationContext(), "Save to PCAP", Toast.LENGTH_SHORT);
                toast.show();
                // prompt for PCAP filename to save to, save current list to default set dir
                return true;

            case R.id.load_pcap:
                toast = Toast.makeText(getApplicationContext(),"Load from PCAP", Toast.LENGTH_SHORT);
                toast.show();
                // open file viewer, user chooses PCAP file to load, then details displayed on screen
                return true;

            case R.id.clear_live:
                toast = Toast.makeText(getApplicationContext(), "Clear List", Toast.LENGTH_SHORT);
                toast.show();

                // clear current list on screen
                TextView tv = (TextView)findViewById(R.id.sniffDisplay);
                tv.setText("To start, choose an option from the menu on the top right");

                return true;

            default:
                return super.onOptionsItemSelected(item);

        }

    }

/*
    public void updateDisplay(String data){
        this.data = data;
        dataHandler.post(dataRunnable);
    }

    final Runnable dataRunnable = new Runnable(){
        public void run(){
            display.setText(data);
        }
    };*/
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

        /***tcpdump***/
        // command to launch tcpdump
        private final String command = "/data/data/com.example.yuxuan.netsniffer/tcpdump -l -i wlan0 > /sdcard/Download/output.txt\n";

        //  process where tcpdump will be executed
        private Process process;

        // pid of tcpdump process
        private int pid;

        // buffer to store captured packets
        private StringBuffer buffer;

        // buffer size
        private int size = 150000;

        // timer task to create a process and exec tcpdump on it
        private Timer tcpdumpTimer;

        // timer task to create a pricess and exec tcpdump
        private TimerTask tcpdump;

        /*** reader thread ***/
        // thread that reads output file created by tcpdump
        private Thread readThread;

        // output file of tcpdump
        private File dumpedFile;

        // buffered reader to read file
        private BufferedReader reader;

        /*** display thread ***/
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
            //checkResource();
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
                        Process process2 = Runtime.getRuntime().exec("ps tcpdump");
                        // read output of ps
                        DataInputStream is = new DataInputStream(process2.getInputStream());

                        ByteArrayOutputStream res = new ByteArrayOutputStream();
                        byte[] tempBuffer = new byte[1024];
                        int length;
                        while ((length = is.read(tempBuffer)) != -1) {
                            res.write(tempBuffer, 0, length);
                        }

                        String temp = res.toString("UTF-8");

                        temp = temp.replaceAll("^root *([0-9]*).*","$1");
                        pid = Integer.parseInt(temp);
                        Log.d("PID (TCP): ", "" + pid);
                        updateDisplay("PID : "+temp);

                        Toast.makeText(getApplicationContext(),"PID:"+pid,Toast.LENGTH_SHORT);

                        process2.destroy();
                    } catch (Exception e) {
                        // handle exception
                        e.printStackTrace();
                    }
                }
            };
/*
            // init the reader thread
            readThread = new Thread() {
                public void run() {
                    try {
                        // ensure the file to be read exists
                        boolean fileOK = false;

                        while (!fileOK) {
                            dumpedFile = new File("/sdcard/Download/output.txt");
                            if (dumpedFile.exists()) {
                                fileOK = true;
                                Toast.makeText(getApplicationContext(),"Output detected", Toast.LENGTH_SHORT).show();
                            }
                        }

                        // open a reader on tcpdump output file
                        reader = new BufferedReader(new FileReader(dumpedFile));
                        String temp;
                        // the while loop is broken if the thread is interrupted
                        while (!Thread.interrupted()) {
                            temp = reader.readLine();
                            if (temp != null) {
                                Log.d("READ PKT:", temp);
                                //buffer.append(temp);
                                //if(buffer.capacity() == size)
                                //    buffer.setLength(0);
                                tempData += temp;
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            };
*/
            // init timer task that displays data to UI
            displayThread = new TimerTask() {
                public void run() {

                    try {
                        File dumpedFile = new File("/sdcard/Download/output.txt");
                        if(!dumpedFile.exists())
                            Toast.makeText(getApplicationContext(),"'output.txt' does not exist",Toast.LENGTH_SHORT).show();

                        reader = new BufferedReader(new FileReader(dumpedFile));
                        String temp;


                        while ((temp = reader.readLine())!= null) {
                            Log.d("READ PKT:", temp);
                            tempData += temp;
                            tempData += "\n";
                            //updateDisplay(temp);
                        }

                    } catch(IOException io){
                        Log.d("IOEX",io.getMessage());
                        Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show();
                    }

                    //String temp = buffer.toString();
                    updateDisplay(tempData);
                    tempData = "";
                    try { reader.close(); } catch(IOException io) { Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show(); }
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

            // start the reader thread
            //readThread.start();

            // send updates to UI every 3s
            displayTimer = new Timer(true);
            displayTimer.schedule(displayThread,4000,2000);

        }

        // stop scanning process
        public void stop(){
            // stop display thread
            displayTimer.cancel();

            // stop the reader thread
            // interrupting the thread will cause while loop to break
            //readThread.interrupt();

            // close the reader for tcpdump output file
            //try { reader.close(); } catch (IOException io) { Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show(); }

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
                Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show();
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

        public StringBuffer getOutput(){
            return buffer;
        }

        public boolean isStarted(){
            return isStarted;
        }


/*
        public void checkResource(){
            File res = new File("/data/data/com.example.yuxuan.netsniffer/tcpdump");
            if(!res.exists()){
                Log.d("TCPDump Resource: ","TCPDump binary does not exist copying to memory");
                // copy tcpdump to memory
                try {
                    InputStream fis = sniffActivity.getAssets().open("tcpdump");                // !!!!!
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

                } catch (IOException io){

                } catch (InterruptedException ie){

                }
            }
        }
*/
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