package com.example.lxl;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button button= findViewById(R.id.bdssl); // baidu ssl cert demo
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                TextView mTextResult = findViewById(R.id.bdView);
                onRequestNet(mTextResult);
            }
        });

        Button bt1 = findViewById(R.id.sMs);
        bt1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                setText();
            }
        });

    }

    /**
     * toast 示例
     */
    public void toastdemo(){
        EditText s = findViewById(R.id.et1);
        String Tostring = s.getText().toString();
        if (!Tostring.equals(""))
            Toast.makeText(this, Tostring, Toast.LENGTH_SHORT).show();
        Toast.makeText(this,"No data",Toast.LENGTH_LONG).show();
    }

    /**
     * TextView 设置值
     */
    public void setText(){
        TextView tv = findViewById(R.id.bdView);
        tv.setText("What's a Fuck");
        toastdemo();
    }


    public void onRequestNet(View view) {
        //创建请求链接
        Request request = new Request.Builder().get().url("https://www.baidu.com").build();
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        try {
            //添加SSL证书验证
            builder.sslSocketFactory(getSSLSocketFactory(), new MyX509TrustManager());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        //请求网络
        OkHttpClient client = builder.build();
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, final IOException e) {
                MainActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        TextView mTextResult = findViewById(R.id.bdView);
                        mTextResult.setText("请求失败：\n" + e.getLocalizedMessage());
                    }
                });
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                final String result = response.body().string();
                MainActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        TextView mTextResult = findViewById(R.id.bdView);
                        mTextResult.setText("请求成功：\n" + result);
                    }
                });
            }
        });
    }

    private SSLSocketFactory getSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManager[] trustManagers = {new MyX509TrustManager()};
        context.init(null, trustManagers, new SecureRandom());
        return context.getSocketFactory();
    }

    private class MyX509TrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null) {
                throw new CertificateException("checkServerTrusted: X509Certificate array is null");
            }
            if (chain.length < 1) {
                throw new CertificateException("checkServerTrusted: X509Certificate is empty");
            }
            if (!(null != authType && authType.equals("ECDHE_RSA"))) {
                throw new CertificateException("checkServerTrusted: AuthType is not ECDHE_RSA");
            }

            //检查所有证书
            try {
                TrustManagerFactory factory = TrustManagerFactory.getInstance("X509");
                factory.init((KeyStore) null);
                for (TrustManager trustManager : factory.getTrustManagers()) {
                    ((X509TrustManager) trustManager).checkServerTrusted(chain, authType);
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }

            //获取本地证书中的信息
            String clientEncoded = "";
            String clientSubject = "";
            String clientIssUser = "";
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//                InputStream inputStream = getAssets().open("baidu.com.cer");
                InputStream inputStream = getAssets().open("baidu.cer");
                X509Certificate clientCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
                clientEncoded = new BigInteger(1, clientCertificate.getPublicKey().getEncoded()).toString(16);
                clientSubject = clientCertificate.getSubjectDN().getName();
                clientIssUser = clientCertificate.getIssuerDN().getName();
            } catch (IOException e) {
                e.printStackTrace();
            }

            //获取网络中的证书信息
            X509Certificate certificate = chain[0];
            PublicKey publicKey = certificate.getPublicKey();
            String serverEncoded = new BigInteger(1, publicKey.getEncoded()).toString(16);

            if (!clientEncoded.equals(serverEncoded)) {
                throw new CertificateException("server's PublicKey is not equals to client's PublicKey");
            }
            String subject = certificate.getSubjectDN().getName();
            if (!clientSubject.equals(subject)) {
                throw new CertificateException("server's subject is not equals to client's subject");
            }
            String issuser = certificate.getIssuerDN().getName();
            if (!clientIssUser.equals(issuser)) {
                throw new CertificateException("server's issuser is not equals to client's issuser");
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

}



/*
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button b = findViewById(R.id.button);
        b.setOnClickListener(new View.OnClickListener() {
            */
/*            @Override
                        public void onClick(View v) {
                            Intent  intent = new Intent(MainActivity.this,second.class);
                            EditText editText = findViewById(R.id.editText);
                            String name = editText.getText().toString();
                            intent.putExtra("name",name);
            //                startActivity(intent);
                            startActivityForResult(intent,1);
                        }*//*

            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this,second.class);
                EditText editText = findViewById(R.id.editText);
                String name = editText.getText().toString();

                Bundle bundle= new Bundle();
                bundle.putString("name",name);
                intent.putExtras(bundle);
                startActivityForResult(intent,1);
//                startActivity(intent);
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
*/
/*        switch (requestCode) {
            case 1:
                if (resultCode == RESULT_OK) {
                    String retinfo = data.getStringExtra("sex");
                    TextView textView1 = findViewById(R.id.textView);
                    textView1.setText(retinfo);
                    //Log.d(TAG,retinfo);
                }
                break;
            default:
        }*//*

*/
/*
        if(requestCode == 0 && resultCode == 0){
            Bundle data = intent.getExtras();
            System.out.println(data.getString("test4"));
        }*//*

//        if (requestCode==RESULT_OK){
////            if (resultCode==ResultActivity.ResultCode){
//                Bundle bundle = data.getExtras();
//                String result = bundle.getString("sex");//通过key值进行获取返回的参数
//            TextView textView1 = findViewById(R.id.textView);
//            textView1.setText(result);
////            }
//        }

//        switch (requestCode) {
//            case 1:
//                if (resultCode == RESULT_OK) {
//                    Bundle bundle = data.getExtras();
//                    String result = bundle.getString("sex");
//                    TextView textView1 = findViewById(R.id.textView);
//                    textView1.setText(result);
//                    //Log.d(TAG,retinfo);
//                }
//                break;
//            default:
//        }
//        Intent intent = getIntent();
        Bundle bundle = data.getExtras();
////        String fs = bundle.getString("sex");
////        System.out.println(fs);
//
//        Log.d("TAG","newPwd"+ data.getExtras().getString("sex"));
//        System.out.println(requestCode);
//        System.out.println(resultCode);
//        Toast.makeText(MainActivity.this,data.getExtras().getString("sex"),Toast.LENGTH_LONG).show();
    }
}*/
