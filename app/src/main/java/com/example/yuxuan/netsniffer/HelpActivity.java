package com.example.yuxuan.netsniffer;

import android.content.DialogInterface;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;

public class HelpActivity extends AppCompatActivity {


    ArrayAdapter<String> itemsAdapter;
    ArrayList<String> dataBuffer;
    ListView listView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_help);

        dataBuffer = new ArrayList<String>();
        dataBuffer.add("Packet Information");
        itemsAdapter = new ArrayAdapter<String>(this,android.R.layout.simple_list_item_1,dataBuffer);
        listView = (ListView)findViewById(R.id.list);
        listView.setAdapter(itemsAdapter);

        init();
   }

   public void init(){
        itemsAdapter.clear();
        dataBuffer.add("Packet 1");
        dataBuffer.add("Packet 2");
        dataBuffer.add("Packet 3");

        itemsAdapter.notifyDataSetChanged();
   }

}
