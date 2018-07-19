package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.provider.ContactsContract;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputType;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.ListView;
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

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    private TCPDump tcpdump;
    private ListView listView;
    private ItemAdapter itemAdapter;
    private String[] dataArray;
    private Context context;

    private String filterAddress;
    private String filterPort;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sniff);


        verifyStoragePermissions(this);
        context = this;
        tcpdump = new TCPDump(context);
        listView = (ListView)findViewById(R.id.sniffList);
        filterAddress = null;
        filterPort = null;
        updateDisplay("To start, choose an option from the menu on the top right",context);
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
        AlertDialog.Builder builder;
        switch (item.getItemId()) {
            case R.id.start_live:
                toast = Toast.makeText(getApplicationContext(),"Start Live",Toast.LENGTH_SHORT);
                toast.show();

                // start live service, output to screen
                if(!tcpdump.isStarted()) {
                    if(filterAddress != null && filterPort != null){
                        // start tcpdump with filtered address & port

                    } else if (filterAddress != null){
                        // start tcpdump with filtered address

                    } else if (filterPort != null){
                        // start tcpdump with filtered port

                    } else {
                        // start tcpdump with no filters
                        tcpdump.start();
                    }
                }
                return true;

            case R.id.add_filter_address:
                toast = Toast.makeText(getApplicationContext(), "Filter Address", Toast.LENGTH_SHORT);
                toast.show();

                // add filter by address
                builder = new AlertDialog.Builder(this);
                builder.setTitle("Filter by Address");

                // set up input
                final EditText inputAddr = new EditText(this);
                inputAddr.setInputType(InputType.TYPE_CLASS_TEXT);
                builder.setView(inputAddr);

                // set up buttons
                builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        // additional input check required
                        filterAddress = inputAddr.getText().toString();
                        Toast.makeText(getApplicationContext(),"Filter by "+filterAddress, Toast.LENGTH_SHORT).show();
                    }
                });
                builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        // cancel
                        filterAddress = null;
                        dialog.cancel();
                    }
                });

                builder.show();

                return true;

            case R.id.add_filter_port:
                toast = Toast.makeText(getApplicationContext(), "Filter Port", Toast.LENGTH_SHORT);
                toast.show();

                // add filter by port
                builder = new AlertDialog.Builder(this);
                builder.setTitle("Filter by Port");

                // set up input
                final EditText inputPort = new EditText(this);
                inputPort.setInputType(InputType.TYPE_CLASS_TEXT);
                builder.setView(inputPort);

                // set up buttons
                builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        // additional input check required
                        filterPort = inputPort.getText().toString();
                        Toast.makeText(getApplicationContext(),"Filter by port "+filterPort, Toast.LENGTH_SHORT).show();
                    }
                });
                builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        // cancel
                        filterPort = null;
                        dialog.cancel();
                    }
                });

                builder.show();

                return true;

            case R.id.filter_clear:
                toast = Toast.makeText(getApplicationContext(), "Clear Filter", Toast.LENGTH_SHORT);
                toast.show();

                // clear all filters
                filterAddress = null;
                filterPort = null;

                return true;

            case R.id.start_pcap:
                toast = Toast.makeText(getApplicationContext(), "Start PCAP", Toast.LENGTH_SHORT);
                toast.show();

                // start live pcap
                if(!tcpdump.isStartedPCAP()) {
                    if(filterAddress != null && filterPort != null){
                        // start tcpdump PCAP with filtered address & port

                    } else if (filterAddress != null){
                        // start tcpdump PCAP with filtered address

                    } else if (filterPort != null){
                        // start tcpdump PCAP with filtered port

                    } else {
                        // start tcpdump PCAP with no filters
                        tcpdump.startPCAP();
                    }
                }

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
                updateDisplay("To start, choose an option from the menu on the top right",context);

                return true;

            default:
                return super.onOptionsItemSelected(item);
        }

    }


    public void updateDisplay(String data, final Context context){
        final String content = data;
        runOnUiThread(new Runnable(){
            @Override
            public void run(){

                listView = (ListView)findViewById(R.id.sniffList);
                dataArray = content.split("\\n");

                itemAdapter = new ItemAdapter(context,dataArray);
                listView.setAdapter(itemAdapter);
            }
        });
    }

    public void showToast(String content){
        final String data = content;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(getApplicationContext(),data,Toast.LENGTH_SHORT).show();
            }
        });
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

        // temporary context
        private Context context;

        public TCPDump(Context context){
            super();

            this.context = context;
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
                            tempData += "\n";
                            //updateDisplay(temp);
                        }

                    } catch(IOException io){
                        Log.d("IOEX",io.getMessage());
                    }

                    updateDisplay(tempData,context);
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

            showToast("Sniffing to PCAP ... ");
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
                showToast("PCAP saved as "+getFileName());
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