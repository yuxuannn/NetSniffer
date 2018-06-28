package com.example.tim.mylist;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;


public class ItemAdapter extends BaseAdapter {

    LayoutInflater mInFlater;
    String[] items;


    public ItemAdapter(Context c, String[] i){
        items = i;
        mInFlater = (LayoutInflater) c.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
    }



    @Override
    public int getCount() {
        return items.length;
    }

    @Override
    public Object getItem(int i) {
        return items[i];
    }

    @Override
    public long getItemId(int i) {
        return i;
    }

    // How to
    @Override
    public View getView(int i, View view, ViewGroup viewGroup) {

        View v = mInFlater.inflate(R.layout.my_listview_detail,null);
        TextView packetText = (TextView) v.findViewById(R.id.packetText);

        String item = items[i];

        packetText.setText(item);

        return v;
    }

}
