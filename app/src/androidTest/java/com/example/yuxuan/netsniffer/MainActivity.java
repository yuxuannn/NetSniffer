package com.example.tim.mylist;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {

    private static final String COMMAND = "getprop /sdcard/Download/output.txt";
    private ListView myListView;
    private String items[];
    private BufferedReader reader;
    private String tempData;

    // user permission
    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        verifyStoragePermissions(this);
        tempData = "";

        //-------------------------------- Start ----------------------------------

        // Read from file 'output.txt'
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
        updateDisplay(tempData, this);

        /*
        myListView = (ListView)findViewById(R.id.myListView);
        String[] tempDataArray = tempData.toString().split("\\n");

        ItemAdapter itemAdapter = new ItemAdapter(this,tempDataArray);
        myListView.setAdapter(itemAdapter);
        */
        try { reader.close(); } catch(IOException io) { Toast.makeText(getApplicationContext(),io.getMessage(),Toast.LENGTH_SHORT).show(); }
        //Log.d("Display Thread : ",temp);




    }// end onCreate


    public void updateDisplay(String content, final Context context){
        final String data = content;
        runOnUiThread(new Runnable(){
            @Override
            public void run(){
                myListView = (ListView)findViewById(R.id.myListView);
                String[] tempDataArray = tempData.toString().split("\\n");

                ItemAdapter itemAdapter = new ItemAdapter(context,tempDataArray);
                myListView.setAdapter(itemAdapter);
            }
        });
    }


    public static void verifyStoragePermissions(Activity activity) {
        // Check if we have write permission
        int permission = ActivityCompat.checkSelfPermission(activity, android.Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            // We don't have permission so prompt the user
            ActivityCompat.requestPermissions(
                    activity,
                    PERMISSIONS_STORAGE,
                    REQUEST_EXTERNAL_STORAGE
            );
        }
    }


}// end class
