package com.example.yuxuan.netsniffer;

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

    @Override
    public View getView(int i, View view, ViewGroup viewGroup) {

        View v = mInFlater.inflate(R.layout.item_layout,null);
        TextView packetText = (TextView) v.findViewById(R.id.item);

        String item = items[i];

        packetText.setText(item);

        return v;
    }

}