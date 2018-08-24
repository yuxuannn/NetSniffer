package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
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
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;
import java.text.DateFormat;

public class GraphActivity extends AppCompatActivity {

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };
    private Context context;
    private TimerTask graphTimerTask;
    private TimerTask rmTimerTask;

    //private String filename;
    private float[] values;
    private String[] verticalLabels;
    private String[] horizontalLabels;

    private boolean type;                       // 0 - SRC / 1 - DST

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        context = this;
        verifyStoragePermissions(this);
        setContentView(R.layout.activity_graph);
        TextView tv = findViewById(R.id.textView);
        tv.setKeyListener(null);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.graph_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        switch (item.getItemId()){
            case R.id.graph_pcap_src:
                Toast.makeText(getApplicationContext(),"Graph PCAP (SRC)",Toast.LENGTH_SHORT).show();

                // open pcap with tcpdump -r > textfile, manipulate data then pass to GraphView
                type = false;

                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                /*** REQUIRES MIME TYPE FOR PCAP FILES ***/
                intent.setType("*/*");

                try {
                    int OPEN_REQUEST_CODE = 41;
                    startActivityForResult(intent, OPEN_REQUEST_CODE);
                } catch (android.content.ActivityNotFoundException ex) {
                    // Potentially direct the user to the Market with a Dialog
                    Toast.makeText(this, "Please install a File Manager.", Toast.LENGTH_SHORT).show();
                }
                return true;


            case R.id.graph_pcap_dst:
                Toast.makeText(getApplicationContext(),"Graph PCAP (DST)",Toast.LENGTH_SHORT).show();

                // open pcap with tcpdump -r > textfile, manipulate data then pass to GraphView
                type = true;

                Intent intent1 = new Intent(Intent.ACTION_GET_CONTENT);
                intent1.addCategory(Intent.CATEGORY_OPENABLE);
                /*** REQUIRES MIME TYPE FOR PCAP FILES (IN ANDROIDMANIFEST) ***/
                intent1.setType("*/*");

                try {
                    int OPEN_REQUEST_CODE = 41;
                    startActivityForResult(intent1, OPEN_REQUEST_CODE);
                } catch (android.content.ActivityNotFoundException ex) {
                    // Potentially direct the user to the Market with a Dialog
                    Toast.makeText(this, "Please install a file manager", Toast.LENGTH_SHORT).show();
                }
                return true;


            default:
                return super.onOptionsItemSelected(item);
        }
    }

    public void init(String input){

        final String filename = input;
        showToast("Analyze "+filename);
        graphTimerTask = new TimerTask() {
            @Override
            public void run() {
                try{
                    Process process = Runtime.getRuntime().exec("su");
                    DataOutputStream os = new DataOutputStream(process.getOutputStream());
                    os.writeBytes("/data/data/com.example.yuxuan.netsniffer/tcpdump -ttttnnr "+filename+" > /sdcard/Download/graph.txt\n");
                    os.flush();
                    os.writeBytes("exit\n");
                    os.flush();
                    os.close();

                } catch (IOException io){
                }
            }
        };

        rmTimerTask = new TimerTask() {
            @Override
            public void run() {
                try{
                    Process process = Runtime.getRuntime().exec("su");
                    DataOutputStream os = new DataOutputStream(process.getOutputStream());
                    os.writeBytes("rm /sdcard/Download/graph.txt\n");
                    os.flush();
                    os.writeBytes("exit\n");
                    os.flush();
                    os.close();
                } catch (IOException io){
                }
            }
        };
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

    public void onActivityResult(int requestCode, int resultCode, Intent resultData) {
        Uri currentUri;
        String path;

        if(resultData == null){
            return;
        }

        if (resultCode == Activity.RESULT_OK)
        {
            if (requestCode == 41) {
                if (resultData != null) {
                    currentUri = resultData.getData();
                    path = currentUri.getPath();

                    /*** FILE PATH MANIPULATION ***/
                    String[] str;
                    if (path.contains("primary")) { // sdcard -> /storage/self/primary
                        str = path.split(":");
                        path = str[1];      // Download/list.txt
                        path = "/sdcard/" + path; // /sdcard/ short for "storage/emulated/0/"

                        // The only time you'll see items (sub folders) there are after you "pin" them as "available offline" from the Drive app.

                        //if(path.contains("com.google.android.apps.docs")){

                        //    path = sdcard/android/data/com.google.android.apps.docs/+path;

                        //}
                    }

                    else if(path.contains("/file")){
                        str = path.split("file");
                        path = str[1];                      // /file/sdcard/Download/output.pcap
                    }

                    /*** ERROR HANDLING FOR BAD PATH / INVALID FILE ***/
                    showToast(path);

                    Vector<AddressPair> srcVec = new Vector<AddressPair>();
                    Vector<AddressPair> dscVec = new Vector<AddressPair>();

                    init(path);
                    Timer readPCAP = new Timer();
                    readPCAP.schedule(graphTimerTask,0);

                    try {
                        Thread.sleep(3500);
                    }catch (InterruptedException ie){
                    }

                    try{
                        File dumpedFile = new File("/sdcard/Download/graph.txt");

                        BufferedReader br = new BufferedReader(new FileReader(dumpedFile));

                        String temp;
                        int srcNo = 2;  // number when split
                        int destNo = 4; // number when split


                        int count = 0;
                        while((temp = br.readLine()) != null){

                            if(count == 0){
                                // if promiscuous
                                String split[] = temp.split(" ");
                                if(!split[3].contains(">")){
                                    ++srcNo;
                                    ++destNo;
                                }
                                ++count;
                            }

                            if(!temp.contains("0x")){
                                String[] line = temp.split(" ");

                                int srcPos = srcNo;
                                int destPos = destNo;

                                if(line[2].contains("ARP")){
                                    srcPos = srcNo + 1;
                                    destPos = destNo + 1;

                                    if(line[3].contains("Request")){
                                        srcPos = srcNo + 2;
                                        destPos = destNo + 2;
                                    }
                                }


                                String src = line[srcPos];
                                String dest = line[destPos];

                                if(line[3].contains("Unknown")){
                                    dest = line[destPos + 3];
                                }

                                boolean isFirstEntry = false;
                                boolean srcFound = false;
                                boolean destFound = false;
                                int index = 0;

                                if(srcVec.size() < 1){
                                    isFirstEntry = true;
                                }

                                //if src vector empty
                                if(isFirstEntry){
                                    //add to vector
                                    AddressPair pair = new AddressPair(src,1);
                                    srcVec.add(pair);
                                }else{
                                    //check if in srcVector
                                    for(int j=0; j<srcVec.size(); ++j){
                                        if(srcVec.get(j).addrEquals(src)){
                                            srcFound = true;
                                            index = j;
                                            break;
                                        }
                                    }
                                }// end if

                                if(srcFound){
                                    //increment value by 1
                                    srcVec.get(index).incrementByOne();
                                }else{
                                    if(!isFirstEntry){
                                        //add to vector
                                        AddressPair pair = new AddressPair(src,1);
                                        srcVec.add(pair);
                                    }
                                }

                                isFirstEntry = false;

                                if(dscVec.size() < 1){
                                    isFirstEntry = true;
                                }

                                //if dest vector empty
                                if(isFirstEntry){
                                    //add to vector
                                    AddressPair pair = new AddressPair(dest,1);
                                    dscVec.add(pair);
                                }else{
                                    //check if in destVector
                                    for(int j=0; j<dscVec.size(); ++j){
                                        if(dscVec.get(j).addrEquals(dest)){
                                            destFound = true;
                                            index = j;
                                            break;
                                        }
                                    }
                                }// end if

                                if(destFound){
                                    //increment value by 1
                                    dscVec.get(index).incrementByOne();
                                }else{
                                    if(!isFirstEntry){
                                        //add to vector
                                        AddressPair pair = new AddressPair(dest,1);
                                        dscVec.add(pair);
                                    }
                                }
                            }}// end while, readline by line

                        if(br != null){
                            try{
                                br.close();
                            }catch(IOException io){
                                //System.out.println(io.getMessage());
                            }
                        }// end if


                        if(!type) {
                            values = new float[srcVec.size()];
                            verticalLabels = new String[7];
                            horizontalLabels = new String[srcVec.size()];

                            float max = -1;
                            for (int i = 0; i < srcVec.size(); i++) {
                                horizontalLabels[i] = srcVec.get(i).getAddr();
                                values[i] = srcVec.get(i).getValue();
                                if (values[i] > max)
                                    max = values[i];
                            }

                            for (int i = 0; i < 6; i++)
                                verticalLabels[i] = Float.toString(max * ((6.0f - i) / 6.0f));

                            verticalLabels[6] = "0";

                        } else {
                            values = new float[dscVec.size()];
                            verticalLabels = new String[7];
                            horizontalLabels = new String[dscVec.size()];

                            float max = -1;
                            for (int i = 0; i < dscVec.size(); i++) {
                                horizontalLabels[i] = dscVec.get(i).getAddr();
                                values[i] = dscVec.get(i).getValue();
                                if (values[i] > max)
                                    max = values[i];
                            }

                            for (int i = 0; i < 6; i++)
                                verticalLabels[i] = Float.toString(max * ((6.0f - i) / 6.0f));

                            verticalLabels[6] = "0";
                        }
/*
                        float[] testValues;
                        String[] testHorizLabels;
                        String[] testVertLabels;
                        testValues = new float [] {1200f, 5f, 12f, 54f, 430f, 731f, 1000f, 5f, 72f, 43f, 64f, 74f, 234f, 235f, 455f, 123f};
                        testHorizLabels = new String [] {"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p"};
                        testVertLabels = new String[] {"1200","1000","800","600","400","200","0"};

                        GraphView graphView = new GraphView(context ,testValues,"Analysis - "+filename+" @ "+DateFormat.getDateTimeInstance().format(new Date()),testHorizLabels,testVertLabels,false);
                        setContentView(graphView);
  */
                        String mode;
                        if(!type)
                            mode = "SRC";
                        else
                            mode = "DST";

                        GraphView graphView = new GraphView(context, values, "Analysis ("+mode+") - "+path+" @ "+DateFormat.getDateTimeInstance().format(new Date()), horizontalLabels, verticalLabels, false);
                        setContentView(graphView);

                        Timer rmGraph = new Timer();
                        rmGraph.schedule(rmTimerTask,0);

                    }catch(Exception e){
                        //showToast(e.getMessage());
                    }// end try-catch

                }
            }}}

    public static void verifyStoragePermissions(Activity activity) {
        // Check if write permissions allowed
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
