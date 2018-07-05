package com.example.yuxuan.netsniffer;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

public class MapActivity extends AppCompatActivity {

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_map);

        TextView display;
        display = findViewById(R.id.mapDisplay);
        display.setKeyListener(null);
        display.setText("To start, choose an option from the menu on the top right");

        verifyStoragePermissions(this);
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

                return true;

            case R.id.stop_map:
                toast = Toast.makeText(getApplicationContext(), "Stop Live", Toast.LENGTH_SHORT);
                toast.show();

                return true;

            case R.id.clear_map:
                toast = Toast.makeText(getApplicationContext(), "Clear List", Toast.LENGTH_SHORT);
                toast.show();

                getDisplay().setText("To start, choose an option from the menu on the top right");

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
