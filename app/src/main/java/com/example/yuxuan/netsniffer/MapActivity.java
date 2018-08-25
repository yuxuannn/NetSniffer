package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
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
import java.util.Vector;
import java.util.regex.Pattern;

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
    private TextView addressText;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_map);
        verifyStoragePermissions(this);
        context = this;
        nmap = new Nmap(context);
        listView = findViewById(R.id.mapList);
        updateDisplay("To start, enter an address, then choose a option from the menu on the top right",1,this);

        addressText = findViewById(R.id.addressBox);
        addressText.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                addressText.setText("");
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.map_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        switch (item.getItemId()) {
            case R.id.start_map:
                Toast.makeText(getApplicationContext(),"Start Map",Toast.LENGTH_SHORT).show();

                // call nmap to start (pass in command chosen via options)
                if(!nmap.isStarted)
                    nmap.start("/data/data/com.example.yuxuan.netsniffer/nmap -sP "+getAddress()+" --datadir /data/data/com.example.yuxuan.netsniffer/ > /sdcard/Download/nmap.txt\n",1);
                else
                    Toast.makeText(getApplicationContext(),"Map already started",Toast.LENGTH_SHORT).show();

                return true;

            case R.id.start_OS:
                Toast.makeText(getApplicationContext(), "Start OS Map",Toast.LENGTH_SHORT).show();

                // call nmap to start
                if(!nmap.isStarted)
                    nmap.start("/data/data/com.example.yuxuan.netsniffer/nmap -O "+getAddress()+" --datadir /data/data/com.example.yuxuan.netsniffer/ > /sdcard/Download/nmap.txt\n",2);
                else
                    Toast.makeText(getApplicationContext(),"Map already started",Toast.LENGTH_SHORT).show();

                return true;

            case R.id.stop_map:
                Toast.makeText(getApplicationContext(), "Stop Map", Toast.LENGTH_SHORT).show();

                // call nmap to stop
                if(nmap.isStarted)
                    nmap.stop();
                else
                    Toast.makeText(getApplicationContext(),"Map not started",Toast.LENGTH_SHORT).show();

                return true;

            case R.id.clear_map:
                Toast.makeText(getApplicationContext(), "Clear List", Toast.LENGTH_SHORT).show();

                //clear list view
                updateDisplay("To start, enter an address, then choose a option from the menu on the top right",1,this);

                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    public String getAddress(){
        TextView tv = findViewById(R.id.addressBox);
        return tv.getText().toString();
    }

    public void updateDisplay(final String data, int mode, final Context context){
        final String content = data;
        final int setClick = mode;
        runOnUiThread(new Runnable(){
            @Override
            public void run() {

                listView = (ListView) findViewById(R.id.mapList);
                dataArray = content.split("\\n");

                itemAdapter = new ItemAdapter(context, dataArray);
                listView.setAdapter(itemAdapter);

                listView.setSelection(listView.getAdapter().getCount() - 1);

                if (setClick == 1) {
                    // copy MAC address to clipboard
                    listView.setClickable(true);
                    listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                        @Override
                        public void onItemClick(AdapterView<?> parent, View view, int position, long id) {

                            //String manipulation, get device MAC address
                            String dataAtPos = (String) itemAdapter.getItem(position);
                            if (dataAtPos.contains("MAC Address: ")) {
                                String[] macAddressArray = dataAtPos.split("MAC Address: ");    // macAddress[1] = " MAC Address: 58:40:4E:DE:A9:DF (UNKNOWN)"
                                String macAddress = macAddressArray[1];

                                String[] removeUnknown = macAddress.split("\\(");               // mac[0] = "58:40:4E:DE:A9:DF"

                                String mac = removeUnknown[0].replaceAll("\\s", "");

                                //save to clipboard
                                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                                ClipData clip = ClipData.newPlainText("MAC Address", mac);
                                clipboard.setPrimaryClip(clip);
                                showToast("MAC copied to clipboard");
                            }

                            //Generate report, nmap done onclick
                            else if (dataAtPos.contains("done")) {
                                showToast("Comparison Report");

                                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                                intent.addCategory(Intent.CATEGORY_OPENABLE);
                                intent.setType("text/plain");

                                try {
                                    int OPEN_REQUEST_CODE = 41;
                                    startActivityForResult(intent, OPEN_REQUEST_CODE);
                                } catch (android.content.ActivityNotFoundException ex) {
                                    showToast("Please install a file manager");
                                }
                            }

                        }
                    });
                }

                if (setClick == 2) {
                    // link to OSActivity
                    listView.setClickable(true);
                    listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                        @Override
                        public void onItemClick(AdapterView<?> parent, View view, int position, long id) {

                            String dataAtPos = (String) itemAdapter.getItem(position);
                            Log.d("StrMan1", dataAtPos);

                            if(!dataAtPos.contains("Running")){
                                showToast("No exact OS matches for host");
                            } else {

                                String[] dataAtPosArray = dataAtPos.split(Pattern.quote(" , "));
                                Log.d("StrMan2", dataAtPosArray[1]);

                                // split again to get just the running part, removing 'OS details'

                                String[] part = dataAtPosArray[1].split(Pattern.quote("   "));
                                String runningPart = part[0];                                       // part[0] == "Running (JUST GUESSING): Oracle Virtualbox(96%) QEMU(92%) // no OS details"
                                Log.d("StrMan3", runningPart);
                                String osInfoArray[] = runningPart.split(":");
                                String osInfo;

                                // make sure not out of bounds
                                if (osInfoArray.length > 1) {
                                    osInfo = osInfoArray[1];                                        // osInfo == "Oracle Virtualbox(96%) QEMU(92%)"
                                } else {
                                    osInfo = "No exact OS matches for host";
                                }

                                Log.d("StrMan4", osInfo);

                                String substrArray[] = osInfo.split("[,\\-\\|\\(]");          // split by  ","  "("  "-"

                                String substr = substrArray[0];                                     // first OS that appears "Oracle Virtualbox"
                                Log.d("StrMan5", substr);
                                String OS = substr;

                                Log.d("StrManOS", OS);
                                if (OS.contains("No exact OS matches for host")) {                  // split might not happen if no 'OS Details: ' substr exists
                                    OS = "No exact OS matches for host";

                                } else {
                                    OS = OS.replaceAll("//s", "+");
                                    Intent intent;
                                    intent = new Intent(context, OSActivity.class);
                                    intent.putExtra("OS", OS);
                                    Log.d("StrManOSIntent", OS);
                                    startActivity(intent);
                                }

                                showToast(dataAtPos);
                            }
                        }
                    });
                }
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

                    } catch(IOException io){ showToast(io.getMessage()); }

                    updateDisplay(tempData,mode,context);
                    tempData = "";
                    if(reader != null)
                        try { reader.close(); } catch(IOException io) { showToast(io.getMessage());}
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
                File psFile = new File("/sdcard/Download/ps.txt");
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
            } catch(IOException io){ showToast(io.getMessage()); }

            // delete temporary ps file
            try{
                Process process2 = Runtime.getRuntime().exec("su");
                DataOutputStream os = new DataOutputStream(process2.getOutputStream());
                os.writeBytes("rm /sdcard/Download/ps.txt\n");
                os.flush();
                os.writeBytes("exit\n");
                os.flush();
                os.close();
            } catch(IOException io){ showToast(io.getMessage()); }

            // delete the temporary output file
            try{
                Process process2 = Runtime.getRuntime().exec("su");
                DataOutputStream os = new DataOutputStream(process2.getOutputStream());
                os.writeBytes("rm /sdcard/Download/nmap.txt\n");
                os.flush();
                os.writeBytes("exit\n");
                os.flush();
                os.close();
            } catch(IOException io){ showToast(io.getMessage()); }

            command = "";
            init();
            isStarted = false;
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent resultData) {

        Uri currentUri;
        String path;

        if (resultData == null) {
            return;
        }

        if (resultCode == Activity.RESULT_OK) {
            if (requestCode == 41) {
                if (resultData != null) {
                    currentUri = resultData.getData();
                    path = currentUri.getPath();


                    /*** PATH MAY REQUIRE CHANGES DEPENDING ON APPLICATION & DEVICE ***/
                    String[] str;
                    if (path.contains("primary")) {                                         // sdcard -> /storage/self/primary
                        str = path.split(":");
                        path = str[1];                                                      // Download/list.txt
                        path = "/sdcard/" + path;                                           // /sdcard/ short for "storage/emulated/0/"

                    }
                    /*** ***/

                    Toast.makeText(this, path, Toast.LENGTH_SHORT).show();

                    Vector<String> list = new Vector<String>(0);
                    Vector<String> found = new Vector<String>(0);
                    Vector<String> missing = new Vector<String>(0);
                    Vector<String> unauthorized = new Vector<String>(0);
                    Vector<String> nmapInfo = new Vector<String>();
                    int match = 0;

                    File listFile = new File(path);
                    boolean listFileExists = listFile.isFile();
                    if(listFileExists) {

                        // read nmap output into a vector List[]
                        try {

                            BufferedReader reader = new BufferedReader(new FileReader(listFile));
                            String temp;

                            while ((temp = reader.readLine()) != null) {
                                Log.d("READ_NMAP:", temp);
                                if(temp.contains("MAC Address")) {
                                    // string manipulation
                                    String[] macAddressArray = temp.split("MAC Address:");          // macAddress[1] = " MAC Address: 58:40:4E:DE:A9:DF (UNKNOWN)"
                                    String macAddress = macAddressArray[1];
                                    String[] removeUnknown = macAddress.split("\\(");               // mac[0] = "58:40:4E:DE:A9:DF"
                                    String mac = removeUnknown[0].replaceAll("\\s", "");


                                    Log.d("READ_NMAP1",mac);
                                    list.add(mac);
                                }else{
                                    Log.d("READ_NMAP1",temp);
                                    list.add(temp);
                                }
                            }


                            reader.close();

                        } catch (IOException io) {
                            Log.d("IOEX", io.getMessage());
                        }

                    }// end if listFile exists

                    // get List view MAC addr into a vector Found[]
                    for(int i=0; i<itemAdapter.getCount();++i){
                        String temp = (String)itemAdapter.getItem(i);
                        Log.d("IADAPTER",temp);
                        if(temp.contains("MAC Address")) {
                            // string manipulation
                            String[] macAddressArray = temp.split("MAC Address:");          // macAddress[1] = " MAC Address: 58:40:4E:DE:A9:DF (UNKNOWN)"
                            String macAddress = macAddressArray[1];
                            String[] removeUnknown = macAddress.split("\\(");               // mac[0] = "58:40:4E:DE:A9:DF"
                            String mac = removeUnknown[0].replaceAll("\\s", "");
                            Log.d("IADAPTERMAC",mac);
                            // add to vector
                            found.add(mac);
                        }else{// other output info from nmap
                            nmapInfo.add(temp);
                        }
                    }

                    if(listFileExists) {
                        // check for missing MACs. for every List[i] if == Found [i]
                        boolean isMissing;
                        for (int i = 0; i < list.size(); ++i) {
                            isMissing = true;
                            for (int j = 0; j < found.size(); ++j) {
                                if (list.get(i).equals(found.get(j))) {
                                    isMissing = false;
                                    Log.d("MISSING_MATCH","false,"+list.get(i)+","+found.get(j));
                                    break;
                                }// end if
                            }//end for

                            if (isMissing) {// if match found, doesn't run this code
                                missing.add(list.get(i));
                                Log.d("MISSING",list.get(i));
                            }
                        }

                        // check for unauthorized MACs. for every
                        boolean isUnauthorized;
                        for (int i = 0; i < found.size(); ++i) {
                            isUnauthorized = true;
                            for (int j = 0; j < list.size(); ++j) {
                                if (found.get(i).equals(list.get(j))) {
                                    isUnauthorized = false;
                                    Log.d("UNAUTH_MATCH","false,"+found.get(i)+","+list.get(j));
                                    ++match;
                                    break;
                                }// end if
                            }// end for

                            if (isUnauthorized) {
                                unauthorized.add(found.get(i));
                                Log.d("UNAUTH",found.get(i));
                            }
                        }// end for
                    }// end if listFile exist

                    //----------------- Organize data for report -----------------
                    // Starting Nmap 6.47( http://nmap.org ) at 2018-12-22 19:44 SGT
                    // Done: 256 IP Addresses (8 hosts up) scanned in 14.20 seconds

                    // string manipulation for nmapInfo vector

                    String noOfIpAddr = "";
                    String noOfHostUp = "";
                    String dateOfScan = "";
                    String timeOfScan = "";
                    String scanTime = "";
                    String noOfMatch = "";
                    String noOfMissing = "";
                    String noOfUnauthorized = "";

                    noOfMatch = Integer.toString(match);

                    for (int i = 0; i < nmapInfo.size(); ++i) {
                        if(nmapInfo.get(i).contains("Done")){
                            // string manipulation
                            String done[] = nmapInfo.elementAt(i).split("[:\\(\\)]");
                            // [0]done, [1]256 IP Addresses, [2]8 hosts up, [3] scanned in 14.20 seconds

                            noOfIpAddr = done[1];
                            noOfHostUp = done[2];
                            String scannedIn = done[3];
                            String scannedTime[] = scannedIn.split("in ");
                            scanTime = scannedTime[1];


                        }else if(nmapInfo.get(i).contains("Starting Nmap")){
                            // string manipulation

                            String starting[] = nmapInfo.elementAt(i).split("at ");
                            String dateAndTime[] = starting[1].split("\\s",2);// "2018-12-22 15:46 SGT"
                            dateOfScan = dateAndTime[0];
                            timeOfScan = dateAndTime[1];
                        }
                    }


                    if(listFileExists) {
                        noOfMissing = Integer.toString(missing.size());
                        noOfUnauthorized = Integer.toString(unauthorized.size());
                    }

                    // generate report
                    String report = "" +
                            "Report Nmap Scan\n\n" +
                            "No of IP Addresses found:  " + noOfIpAddr + "\n"+
                            "No of Hosts up:            " + noOfHostUp + "\n"+
                            "Date of Scan:              " + dateOfScan + "\n"+
                            "Time of Scan:              " + timeOfScan + "\n"+
                            "Scan Time:                 " + scanTime + "\n\n";

                    String macStr = "";
                    String missingStr = "\n\t\t\t\t\t\t\t";
                    String unauthorizedStr = "\n\t\t\t\t\t\t\t";

                    // Output vector of missing/unauthorized
                    if(listFileExists){
                        if(missing.size() > 0) {
                            for(int i = 0; i < missing.size(); ++i) {
                                missingStr += missing.get(i) + "\n\t\t\t\t\t\t\t";
                            }
                        }else{
                            missingStr = "-\n";
                        }

                        if(unauthorized.size() > 0){
                            for(int i=0; i<unauthorized.size(); ++i){
                                unauthorizedStr += unauthorized.get(i) + "\n\t\t\t\t\t\t\t";
                            }
                        }else{
                            unauthorizedStr = "-\n";
                        }

                        macStr = "" +
                                "Total MACs found:      " + found.size() + " MAC(s) found.\n" +
                                "No of Matches:         " + noOfMatch + " MAC(s) matched.\n\n" +
                                "No of Missing:         " + missing.size() + " MAC(s) missing.\n\n" +
                                "Missing MACs:          " + missingStr + "\n" +
                                "No of Unauthorized:    " + unauthorized.size() + " MAC(s) unauthorized.\n\n" +
                                "Unauthorized MACs:     " + unauthorizedStr + "\n";

                        report+=macStr;
                    }

                    Log.d("Report",report);

                    AlertDialog.Builder builderReport;
                    builderReport = new AlertDialog.Builder(context);
                    builderReport.setMessage(report);
                    builderReport.show();

                }
            }
        }
    }


    public static void verifyStoragePermissions(Activity activity) {
        // Check if write permission allowed
        int permission = ActivityCompat.checkSelfPermission(activity, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            // Prompt user for permission
            ActivityCompat.requestPermissions(
                    activity,
                    PERMISSIONS_STORAGE,
                    REQUEST_EXTERNAL_STORAGE
            );
        }
    }
}
