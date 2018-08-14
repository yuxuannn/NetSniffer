package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.provider.Telephony;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputType;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.EditText;
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

    private String filename;
    private float[] values;
    private String[] verticalLabels;
    private String[] horizontalLabels;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        context = this;
        verifyStoragePermissions(this);
        setContentView(R.layout.activity_graph);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.graph_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        AlertDialog.Builder builder;
        switch (item.getItemId()){
            case R.id.graph_pcap:
                Toast.makeText(getApplicationContext(),"Graph PCAP",Toast.LENGTH_SHORT).show();

                // open pcap with tcpdump -r > textfile, manipulate data then pass to GraphView

                builder = new AlertDialog.Builder(context);
                builder.setTitle("Enter PCAP file");

                final EditText inputFilename = new EditText(context);
                inputFilename.setInputType(InputType.TYPE_CLASS_TEXT);
                builder.setView(inputFilename);

                builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {

                        filename = inputFilename.getText().toString();
                        if (filename.equals(""))
                            showToast("Invalid filename");
                        else{

                                File file = new File("/sdcard/Download/"+filename);
                                if(!file.exists()){
                                    //showToast("Invalid filename");
                                } else{
                                    // read from file - extract data to vectors

                                    Vector<AddressPair> srcVec = new Vector<AddressPair>();
                                    Vector<AddressPair> dscVec = new Vector<AddressPair>();

                                    init(filename);
                                    Timer readPCAP = new Timer();
                                    readPCAP.schedule(graphTimerTask,0);

                                    int mode = 1;
                                    int monitor = 1;
                                    int promiscuous = 2;

                                    try{
                                        File dumpedFile = new File("/sdcard/Download/graph.txt");

                                        BufferedReader br = new BufferedReader(new FileReader(dumpedFile));

                                        int count = 1;
                                        String temp;
                                        int srcNo = 2;// number when split
                                        int destNo = 4;// number when split

                                        if(mode == promiscuous){
                                            ++srcNo;
                                            ++destNo;
                                        }

                                        while((temp = br.readLine()) != null){

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

                                            ++count;

                                        }// end while, readline by line


                                        if(br != null){
                                            try{
                                                br.close();
                                            }catch(IOException io){
                                                //System.out.println(io.getMessage());
                                            }
                                        }// end if

                                        //showToast("dscVec size: "+Integer.toString(dscVec.size()));
                                        values = new float[srcVec.size()];
                                        verticalLabels = new String[7];
                                        horizontalLabels = new String[srcVec.size()];

                                        float max = -1;
                                        for(int i=0; i<srcVec.size(); i++){
                                            horizontalLabels[i] = srcVec.get(i).getAddr();
                                            values[i] = srcVec.get(i).getValue();
                                            if(values[i] > max)
                                                max = values[i];
                                        }

                                        for(int i=0; i<6; i++){
                                            float index = 6;
                                            verticalLabels[i] = Float.toString(max * ((index-i)/index));
                                        }
                                        verticalLabels[6] = "0";
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
                                        GraphView graphView = new GraphView(context, values, "Analysis - "+filename+" @ "+DateFormat.getDateTimeInstance().format(new Date()), horizontalLabels, verticalLabels, false);
                                        setContentView(graphView);

                                        Timer rmGraph = new Timer();
                                        rmGraph.schedule(rmTimerTask,0);

                                    }catch(Exception e){
                                        //showToast(e.getMessage());
                                    }// end try-catch

                                }
                        }
                    }
                });

                builder.show();

                // vertical labels take max, fixed intervals calculated from max
                //values = new float[] {2.0f,1.5f,0.1f,0.7f,0.2f,1.7f,1.6f,0.3f,2.0f,0.5f};
                //verticalLabels = new String[] {">2K","1.75K","1.5K","1.25K","1K","0.75K","0.5K","0.25K","0"};
                //horizontalLabels = new String[] {"ID1","ID2","ID3","ID4","ID5","ID6","ID7","ID8","ID9","ID10"};

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
                    os.writeBytes("/data/data/com.example.yuxuan.netsniffer/tcpdump -ttttnnr /sdcard/Download/"+filename+" > /sdcard/Download/graph.txt\n");
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
