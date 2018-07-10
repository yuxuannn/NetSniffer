package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_map);

        TextView display;
        display = findViewById(R.id.mapDisplay);
        display.setKeyListener(null);
        display.setText("To start, type in an address and choose an option from the menu on the top right");

        verifyStoragePermissions(this);
        // initialize new nmap object
        nmap = new Nmap();
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

                TextView address = (TextView) findViewById(R.id.addressBox);
                String message = address.getText().toString();

                // call nmap to start (pass in command chosen via options)
                if(!nmap.isStarted)
                    nmap.start("/data/data/com.example.yuxuan.netsniffer/nmap -sP "+message+" --datadir /data/data/com.example.yuxuan.netsniffer/ > /sdcard/Download/nmap.txt\n"); // Nmap command

                return true;

            case R.id.stop_map:
                toast = Toast.makeText(getApplicationContext(), "Stop Map", Toast.LENGTH_SHORT);
                toast.show();

                // call nmap to stop
                if(nmap.isStarted)
                    nmap.stop();

                return true;

            case R.id.clear_map:
                toast = Toast.makeText(getApplicationContext(), "Clear List", Toast.LENGTH_SHORT);
                toast.show();

                getDisplay().setText("To start, type in an address and choose an option from the menu on the top right");

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
                TextView tv = (TextView)findViewById(R.id.mapDisplay); tv.setText(data);
            }
        });
    }

    public TextView getDisplay(){
        TextView tv = (TextView)findViewById(R.id.mapDisplay);
        return tv;
    }

    public class Nmap{

        private boolean isStarted;

        private Timer nmapTimer;

        private TimerTask nmapTimerTask;

        private Timer displayTimer;

        private TimerTask displayTimerTask;

        private String command;

        private Process nmapProcess;

        private BufferedReader reader;

        private int pid;

        private String tempData;

        public Nmap(){
            isStarted = false;
            tempData = "";
            command = "";
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

            displayTimerTask = new TimerTask() {
                public void run() {

                    try {
                        File dumpedFile = new File("/sdcard/Download/nmap.txt");

                        reader = new BufferedReader(new FileReader(dumpedFile));
                        String temp;

                        while ((temp = reader.readLine())!= null) {
                            Log.d("READ DATA:", temp);
                            tempData += temp;
                            tempData += "\n";
                        }

                    } catch(IOException io){
                        Log.d("IOEX",io.getMessage());
                    }

                    updateDisplay(tempData);
                    tempData = "";
                    if(reader != null)
                        try { reader.close(); } catch(IOException io) { }

                }
            };
        }

        public void start(String arg){
            command = arg;
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
