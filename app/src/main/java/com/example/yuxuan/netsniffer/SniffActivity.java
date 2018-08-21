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
import android.widget.AdapterView;
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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sniff);


        verifyStoragePermissions(this);
        context = this;
        tcpdump = new TCPDump(context);
        listView = (ListView)findViewById(R.id.sniffList);
        filterAddress = null;
        updateDisplay("To start, choose an option from the menu on the top right", context);
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
                toast = Toast.makeText(getApplicationContext(),"Start Live", Toast.LENGTH_SHORT);
                toast.show();

                // start live service, output to screen
                if(!tcpdump.isStarted() && !tcpdump.isStartedProm()) {
                    if (filterAddress != null){
                        // start tcpdump with filtered address
                        tcpdump.start(filterAddress);
                    } else {
                        // start tcpdump with no filters
                        tcpdump.start();
                    }
                } else
                    Toast.makeText(getApplicationContext(), "Already started", Toast.LENGTH_SHORT).show();
                return true;

            case R.id.start_prom:
                toast = Toast.makeText(getApplicationContext(), "Start Prom", Toast.LENGTH_SHORT);
                toast.show();

                // start prom service, output to screen
                if(!tcpdump.isStarted() && !tcpdump.isStartedProm()) {
                    if(filterAddress != null){
                        // start pcbin with filtered address
                        tcpdump.startProm(filterAddress);
                    } else {
                        // start pcbin with no filters
                        tcpdump.startProm();
                    }
                } else
                    Toast.makeText(getApplicationContext(), "Already started", Toast.LENGTH_SHORT).show();
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

            case R.id.filter_clear:
                toast = Toast.makeText(getApplicationContext(), "Clear Filter", Toast.LENGTH_SHORT);
                toast.show();

                // clear all filters
                filterAddress = null;
                Toast.makeText(getApplicationContext(), "Filters Cleared", Toast.LENGTH_SHORT).show();

                return true;

            case R.id.stop_sniff:
                toast = Toast.makeText(getApplicationContext(),"Stop Sniff", Toast.LENGTH_SHORT);
                toast.show();

                // stop live pcap
                if(tcpdump.isStarted() || tcpdump.isStartedProm())
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

                listView.setSelection(listView.getAdapter().getCount()-1);
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
        private boolean isStartedProm;

        /***tcpdump***/
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

        private Timer psTimer;

        private TimerTask psTimerTask;

        private Timer nexutilTimer;

        private TimerTask nexutilTimerTask;

        private Timer pcbinTimer;

        private TimerTask pcbinTimerTask;

        private String filterAddress;

        public TCPDump(Context context){
            super();

            this.context = context;
            this.isStarted = false;
            this.isStartedProm = false;
            counter = 0;
            tempData = "";
            filterAddress = null;
            init();
        }

        // initializes threads, process and timer task used for scanning
        private void init() {

            nexutilTimerTask = new TimerTask() {
                @Override
                public void run() {
                    try {
                        Process process1 = Runtime.getRuntime().exec("su");
                        DataOutputStream dos = new DataOutputStream(process1.getOutputStream());
                        dos.writeBytes("/data/data/com.example.yuxuan.netsniffer/nexutil -m2\n");
                        dos.flush();
                        dos.writeBytes("exit\n");
                        dos.close();

                        process1.destroy();
                    } catch (IOException io) {
                    } //showToast(io.getMessage());
                }
            };

            pcbinTimerTask = new TimerTask() {
                public void run() {
                    try {
                        process = Runtime.getRuntime().exec("su");
                        DataOutputStream os = new DataOutputStream(process.getOutputStream());
                        os.writeBytes("./data/data/com.example.yuxuan.netsniffer/pcbin -i wlan0 > /sdcard/Download/output.txt\n");
                        os.flush();
                        os.writeBytes("exit\n");
                        os.flush();
                        os.close();

                    } catch (Exception e) {
                    } //showToast(e.getMessage());
                }
            };

            // init tcpdump timer task and launch tcpdump on it
            tcpdump = new TimerTask() {
                public void run() {
                    try {
                        // create a process with root privilege
                        process = Runtime.getRuntime().exec("su");
                        DataOutputStream os = new DataOutputStream(process.getOutputStream());
                        os.writeBytes("/data/data/com.example.yuxuan.netsniffer/nexutil -m2\n");
                        os.flush();
                        os.writeBytes("./data/data/com.example.yuxuan.netsniffer/pcmon -i wlan0 > /sdcard/Download/output.txt\n");
                        os.flush();
                        os.writeBytes("exit\n");
                        os.flush();
                        os.close();


                    } catch (Exception e) {
                    } //showToast(e.getMessage());
                }
            };

            psTimerTask = new TimerTask() {
                @Override
                public void run() {
                    try {
                        // get pid of process that exec tcpdump with ps command
                        Process psProcess = Runtime.getRuntime().exec("su");
                        DataOutputStream dos = new DataOutputStream(psProcess.getOutputStream());
                        dos.writeBytes("ps | grep -e tcpdump -e pcbin  -e pcmon > /sdcard/Download/ps.txt\n");
                        dos.flush();
                        dos.writeBytes("exit\n");
                        dos.flush();
                        dos.close();

                        process.destroy();
                    } catch (IOException io) {
                    } //showToast(io.getMessage());
                }
            };

            // init timer task that displays data to UI
            displayThread = new TimerTask() {
                public void run() {

                    try {
                        File dumpedFile = new File("/sdcard/Download/output.txt");

                        reader = new BufferedReader(new FileReader(dumpedFile));
                        String temp;

                        int counter = 1;
                        while ((temp = reader.readLine()) != null) {
                            Log.d("READ DATA: ", temp);

                            if(isStarted) {
                                if (!temp.contains("0x")) {
                                    if (filterAddress != null) {
                                        if (temp.contains(filterAddress))
                                            tempData += counter+". " + temp + "\n";
                                    } else {
                                        tempData += counter + ". " + temp + "\n";
                                    }
                                    counter++;
                                }
                            }
                            if(isStartedProm){
                                if (filterAddress != null) {
                                    if (temp.contains(filterAddress))
                                        tempData += counter+". " + temp + "\n";
                                } else {
                                    tempData += counter + ". " + temp + "\n";
                                }
                                counter++;
                            }

                        }

                    } catch (IOException io) {
                    } //showToast(io.getMessage());

                    updateDisplay(tempData, context);
                    tempData = "";
                    if (reader != null)
                        try {
                            reader.close();
                        } catch (IOException io) {
                        } //showToast(io.getMessage());

                }
            };

            pcapTimerTask = new TimerTask() {
                public void run() {
                    if (isStarted) {
                        try {
                            // create a process with root privilege
                            pcapProcess = Runtime.getRuntime().exec("su");
                            DataOutputStream os = new DataOutputStream(pcapProcess.getOutputStream());
                            os.writeBytes("LD_PRELOAD=/data/data/com.example.yuxuan.netsniffer/libfakeioctl.so ./data/data/com.example.yuxuan.netsniffer/pcmon -w /sdcard/Download/output-" + counter + ".pcap  -i wlan0\n");
                            os.flush();
                            os.writeBytes("exit\n");
                            os.flush();
                            os.close();

                        } catch (Exception e) {
                        } //showToast(e.getMessage());
                    }
                    if (isStartedProm) {
                        try {
                            pcapProcess = Runtime.getRuntime().exec("su");
                            DataOutputStream os = new DataOutputStream(pcapProcess.getOutputStream());
                            os.writeBytes("./data/data/com.example.yuxuan.netsniffer/pcbin -w /sdcard/Download/output-" + counter + ".pcap -i wlan0\n");
                            os.flush();
                            os.writeBytes("exit\n");
                            os.flush();
                            os.close();

                        } catch (Exception e) {
                        } //showToast(e.getMessage());
                    }
                }
            };
        }


        // start scanning process
        public void start(){
            isStarted = true;
            filterAddress = null;

            init();

            // set nic to monitor mode
            nexutilTimer = new Timer();
            nexutilTimer.schedule(nexutilTimerTask, 0);

            // launch tcpdump process
            tcpdumpTimer = new Timer();
            tcpdumpTimer.schedule(tcpdump,2000);

            // sniff to pcap
            pcapTimer = new Timer();
            pcapTimer.schedule(pcapTimerTask,2500);

            // launch ps process
            psTimer = new Timer();
            psTimer.schedule(psTimerTask, 4000);

            // send updates to UI every 3s
            displayTimer = new Timer(true);
            displayTimer.schedule(displayThread,3000,2000);

            showToast("Sniffing to PCAP ... ");
        }

        public void startProm(){
            isStartedProm = true;
            filterAddress = null;

            init();

            // launch pcbin process
            pcbinTimer = new Timer();
            pcbinTimer.schedule(pcbinTimerTask, 2000);

            // sniff to pcap
            pcapTimer = new Timer();
            pcapTimer.schedule(pcapTimerTask, 2500);

            // launch ps process
            psTimer = new Timer();
            psTimer.schedule(psTimerTask, 4000);

            // send updates to UI
            displayTimer = new Timer(true);
            displayTimer.schedule(displayThread, 3000,2000);

            showToast("Sniffing to PCAP ... ");
        }

        public void start(String filterAddress){
            isStarted = true;
            this.filterAddress = filterAddress;

            init();

            // set nic to monitor mode
            nexutilTimer = new Timer();
            nexutilTimer.schedule(nexutilTimerTask, 0);

            // launch tcpdump process
            tcpdumpTimer = new Timer();
            tcpdumpTimer.schedule(tcpdump,2000);

            // sniff to pcap
            pcapTimer = new Timer();
            pcapTimer.schedule(pcapTimerTask, 2500);

            // launch ps process
            psTimer = new Timer();
            psTimer.schedule(psTimerTask, 4000);

            // send updates to UI every 3s
            displayTimer = new Timer(true);
            displayTimer.schedule(displayThread,3000,2000);
        }

        public void startProm(String filterAddress){
            isStartedProm = true;
            this.filterAddress = filterAddress;

            init();

            // launch pcbin process
            pcbinTimer = new Timer();
            pcbinTimer.schedule(pcbinTimerTask, 2000);

            // sniff to pcap
            pcapTimer = new Timer();
            pcapTimer.schedule(pcapTimerTask, 2500);

            // launch ps process
            psTimer = new Timer();
            psTimer.schedule(psTimerTask, 4000);

            // send updates to UI
            displayTimer = new Timer(true);
            displayTimer.schedule(displayThread, 3000, 2000);
        }

        // stop scanning process
        public void stop(){

            if(isStarted){
                // stop display thread
                displayTimer.cancel();

                // stop ps thread
                psTimer.cancel();

                // stop the tcpdump process
                nexutilTimer.cancel();
                tcpdumpTimer.cancel();
                process.destroy();
                //buffer.setLength(0);
                tempData = "";

                // pcap
                counter += 1;
                pcapTimer.cancel();
                pcapProcess.destroy();

                showToast("PCAP saved as "+getFileName());
            }

            if(isStartedProm){
                // stop display thread
                displayTimer.cancel();

                // stop ps thread
                psTimer.cancel();

                // stop pcbin process
                pcbinTimer.cancel();
                process.destroy();
                // clear buffer
                tempData = "";

                // pcap
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
            } catch(IOException io){  }

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
            } catch(IOException io){ }

            // set nexutil back to -m0
            try{
                Process process2 = Runtime.getRuntime().exec("su");
                DataOutputStream os = new DataOutputStream(process2.getOutputStream());
                os.writeBytes("/data/data/com.example.yuxuan.netsniffer/nexutil -m0\n");
                os.flush();
                os.writeBytes("exit\n");
                os.flush();
                os.close();
            } catch(IOException io){ }


            // to restart the process, re init threads and timers
            isStarted = false;
            isStartedProm = false;
            init();
        }


        public boolean isStarted(){ return isStarted; }

        public boolean isStartedProm(){return isStartedProm; }

        public String getFileName(){ return "output-"+(counter-1)+".pcap"; }

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