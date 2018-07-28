package com.example.yuxuan.netsniffer;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;


public class OSActivity extends AppCompatActivity {

    private WebView webview;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_os);

        Intent intent = getIntent();
        String OS = intent.getExtras().getString("OS");

        webview = (WebView)findViewById(R.id.webView);

        webview.setWebViewClient(new WebViewClient());
        webview.getSettings().setJavaScriptEnabled(true);
        webview.getSettings().setDomStorageEnabled(true);
        webview.setOverScrollMode(WebView.OVER_SCROLL_NEVER);
        webview.loadUrl("https://www.rapid7.com/db/search?utf8=%E2%9C%93&q="+OS+"&t=a"); // pass OS details into 'search'+'term'

    }

}
