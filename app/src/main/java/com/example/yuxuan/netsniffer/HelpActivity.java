package com.example.yuxuan.netsniffer;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.widget.TextView;

public class HelpActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_help);
        TextView tv = findViewById(R.id.helpTextView);
        tv.setMovementMethod(new ScrollingMovementMethod());
        //tv.setKeyListener(null);
    }

}
