package com.example.yuxuan.netsniffer;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.Toast;

public class SettingActivity extends AppCompatActivity {

    private Switch dimSwitch;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setting);

        dimSwitch = findViewById(R.id.screenOnSwitch);
        dimSwitch.setChecked(false);
        dimSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if(dimSwitch.isChecked()){
                    getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                    Toast.makeText(getApplicationContext(),"Screen sleep disabled",Toast.LENGTH_SHORT).show();
                }
                else{
                    getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                    Toast.makeText(getApplicationContext(),"Screen sleep enabled",Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    /*** MIGHT REQUIRE SEPARATE CLASS TO STORE APP WIDE SETTINGS - ALL OTHER CLASSES EXTEND SETTINGS CLASS ***/
}
