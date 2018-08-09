package com.example.yuxuan.netsniffer;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

public class GraphActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // open pcap with tcpdump -r > textfile, manipulate data then pass to GraphView

        float[] values = new float[] {2.0f,1.5f,2.5f,1.0f,3.0f};
        String[] verticalLabels = new String[] {"1000","500","250"};
        String[] horizontalLabels = new String[] {"ID1","ID2","ID3","ID4"};
        GraphView graphView = new GraphView(this,values,"PCAP Filename - Analysis",horizontalLabels,verticalLabels,false);

        setContentView(graphView);
    }
}
