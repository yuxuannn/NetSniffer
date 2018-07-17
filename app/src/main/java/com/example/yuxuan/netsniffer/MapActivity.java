package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

public class MapActivity extends AppCompatActivity {

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    private Nmap nmap;
    ItemAdapter itemAdapter;
    ListView listView;
    String[] dataArray;
    Context context;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_map);
        verifyStoragePermissions(this);
        context = this;
        nmap = new Nmap(context);
        listView = (ListView)findViewById(R.id.mapList);
        updateDisplay("To start, enter an address, then choose a option from the menu on the top right",this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.map_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        Toast toast;
        switch (item.getItemId()) {
            case R.id.start_map:
                toast = Toast.makeText(getApplicationContext(),"Start Map",Toast.LENGTH_SHORT);
                toast.show();

                // call nmap to start (pass in command chosen via options)
                if(!nmap.isStarted)
                    nmap.start("/data/data/com.example.yuxuan.netsniffer/nmap -sP "+getAddress()+" --datadir /data/data/com.example.yuxuan.netsniffer/ > /sdcard/Download/nmap.txt\n",1);
                else
                    Toast.makeText(getApplicationContext(),"Map already started",Toast.LENGTH_SHORT).show();


                return true;

            case R.id.start_OS:
                toast = Toast.makeText(getApplicationContext(), "Start OS Map",Toast.LENGTH_SHORT);
                toast.show();

                // call nmap to start
                if(!nmap.isStarted)
                    nmap.start("/data/data/com.example.yuxuan.netsniffer/nmap -O "+getAddress()+" --datadir /data/data/com.example.yuxuan.netsniffer/ > /sdcard/Download/nmap.txt\n",2);
                else
                    Toast.makeText(getApplicationContext(),"Map already started",Toast.LENGTH_SHORT).show();

                return true;

            case R.id.stop_map:
                toast = Toast.makeText(getApplicationContext(), "Stop Map", Toast.LENGTH_SHORT);
                toast.show();

                // call nmap to stop
                if(nmap.isStarted)
                    nmap.stop();
                else
                    Toast.makeText(getApplicationContext(),"Map not started",Toast.LENGTH_SHORT).show();

                return true;

            case R.id.clear_map:
                toast = Toast.makeText(getApplicationContext(), "Clear List", Toast.LENGTH_SHORT);
                toast.show();

                //clear list view
                updateDisplay("To start, enter an address, then choose a option from the menu on the top right",this);

                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    public String getAddress(){
        TextView tv = findViewById(R.id.addressBox);
        return tv.getText().toString();
    }

    public void updateDisplay(String data, final Context context){
        final String content = data;
        runOnUiThread(new Runnable(){
            @Override
            public void run(){

                listView = (ListView)findViewById(R.id.mapList);
                dataArray = content.split("\\n");

                itemAdapter = new ItemAdapter(context,dataArray);
                listView.setAdapter(itemAdapter);
            }
        });
    }


    public class Nmap{

        // is started variable
        private boolean isStarted;

        // nmap timer
        private Timer nmapTimer;

        // nmap timer task
        private TimerTask nmapTimerTask;

        // display timer
        private Timer displayTimer;

        // display timer task
        private TimerTask displayTimerTask;

        // empty command - receive from switch case
        private String command;

        // nmap process
        private Process nmapProcess;

        // buffered reader
        private BufferedReader reader;

        // nmap process pid
        private int pid;

        // output string
        private String tempData;

        // temporary context
        private Context context;

        // mode
        private int mode;

        public Nmap(Context context){
            isStarted = false;
            tempData = "";
            command = "";
            this.context = context;
        }

        private void init(){
            nmapTimerTask = new TimerTask() {
                public void run() {
                 try{

                     nmapProcess = Runtime.getRuntime().exec("su");
                     DataOutputStream os = new DataOutputStream(nmapProcess.getOutputStream());
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
                     dos.writeBytes("ps | grep /data/data/com.example.yuxuan.netsniffer/nmap > /sdcard/Download/ps.txt\n");
                     dos.flush();
                     dos.writeBytes("exit\n");
                     dos.flush();
                     dos.close();

                 } catch (Exception e) { }
                }
            };

            // init timer task that displays data to UI
            displayTimerTask = new TimerTask() {
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
                            Log.d("READ MAP:", temp);

                            if(mode == 1) {
                                if (temp.contains("Starting")) {
                                    tempData += temp;
                                } else if (temp.contains("scan report")) {
                                    tempData += "\n" + temp;
                                } else if (temp.contains("Note")) {
                                    tempData += "\n" + temp;
                                } else if (temp.contains("done")) {
                                    tempData += "\n" + temp;
                                    stop = true;
                                } else
                                    tempData += "   " + temp;
                            }
                            else if (mode == 2) {
                                if (temp.contains("Starting")){
                                    tempData += temp;
                                } else if (temp.contains("scan report")) {
                                    tempData += "\n" + temp;
                                } else if (temp.contains("Device type")){
                                    tempData += " - "+temp;
                                } else if (temp.contains("Running")){
                                    tempData += " , "+temp;
                                } else if (temp.contains("OS details")){
                                    tempData += "   " + temp;
                                }  else if (temp.contains("done")) {
                                    tempData += "\n" + temp;
                                    stop = true;
                                }
                            }

                        }

                    } catch(IOException io){
                        Log.d("IOEX",io.getMessage());
                        //Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show();
                    }

                    //String temp = buffer.toString();
                    updateDisplay(tempData,context);
                    tempData = "";
                    if(reader != null)
                        try { reader.close(); } catch(IOException io) { }//Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show(); }
                    //Log.d("Display Thread : ",temp);
                    if(stop)
                        stop();
                }
            };
        }


        public void start(String arg, int mode){
            command = arg;
            this.mode = mode;
            init();
            isStarted = true;

            nmapTimer = new Timer();
            nmapTimer.schedule(nmapTimerTask,0);

            displayTimer = new Timer(true);
            displayTimer.schedule(displayTimerTask,3000, 1000);
        }

        public void stop(){

            nmapTimerTask.cancel();
            nmapTimer.cancel();
            nmapProcess.destroy();
            displayTimerTask.cancel();
            displayTimer.cancel();
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

            command = "";
            init();
            isStarted = false;
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
