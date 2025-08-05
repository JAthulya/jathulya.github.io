---
layout: post
title: "Three Basic Certificate Pinning in Android"
date: 2025-08-05
categories: [blog]
toc: |
  <ul>
    <li><a href="#introduction">Introduction</a></li>
    <li><a href="#custom_trustmanager_pinning">Custom TrustManager Pinning</a></li>
    <li><a href="#okhttp">Custom Certificate Pinning using OkHttp's CertificatePinner</a></li>
    <li><a href="#nsc">Certificate Pinning via Network Security Configuration</a></li>
  </ul>
---

 
# Introduction {#introduction} 

In this article, I explore the three main approaches to implementing Certificate pinning in Android applications. 
Below listed the main Certificate Pinning techniques in Android:
1. Custom TrustManager Pinning
2. Pinning with OkHttp or HttpClient
3. Network Security Configuration

<span style="color:#d05dfc">What is Certificate Pinning</span><br>
Certificate pinning is a security technique used in Android apps to ensure the app only trusts a specific server certificate. It works by embedding the expected server's X.509 certificate or its fingerprint directly into the app. During a TLS handshake, the app compares the server’s certificate with the pinned certificate. If they don’t match, the connection is rejected, even if the certificate is otherwise valid and trusted by the system. 

This article covers three popular certificate pinning methods in Android apps. 

# Custom TrustManager Pinning {#custom_trustmanager_pinning}

to implement this i have used this <a href="https://stackoverflow.com/questions/53637121/use-a-certificate-in-an-okhttp-request-with-android"> stackoverflow </a> code which uses custom trustmanager with OkHttpClient. 

i was using this command to generate the .pem file for the certification validation. 

{% highlight c# %}
openssl s_client -connect android.com:443 -showcerts </dev/null | awk '/BEGIN/,/END/{ print $0; }' > my_cert1.pem
{% endhighlight %}



then added it into the <b>AndroidStudioProjects/{project name}/app/src/main/res/raw/</b> path. (I'm using Linux distro)

this is the full code to the application.

<span style="color:yellow">MainActivity.java</span><br>

{% highlight c# %}

{% endhighlight %}

{% highlight java %}
package com.broken.trustmanager1;

import android.os.Bundle;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    private TextView textViewResponse;
    private OkHttpClient client;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        textViewResponse = findViewById(R.id.textViewResponse);
        Button btnFetch = findViewById(R.id.btnFetch);

        CustomTrust customTrust = new CustomTrust(getApplicationContext());
        OkHttpClient client = customTrust.getClient();



        btnFetch.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Request request = new Request.Builder()
                        .url("https://www.android.com")  // Replace with your target URL
                        .build();

                client.newCall(request).enqueue(new Callback() {
                    @Override
                    public void onFailure(Call call, IOException e) {
                        runOnUiThread(() ->
                                textViewResponse.setText("Request Failed: " + e.getMessage()));
                    }

                    @Override
                    public void onResponse(Call call, Response response) throws IOException {
                        final String body = response.body().string();
                        runOnUiThread(() ->
                                textViewResponse.setText(body));
                    }
                });
            }
        });
    }

}
{% endhighlight %}

<span style="color:yellow">CustomTrust.java</span><br>

{% highlight c# %}
package com.broken.trustmanager1;

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;

public final class CustomTrust {

    private final OkHttpClient client;
    private final Context context;

    public CustomTrust(Context context) {

        this.context = context;
        X509TrustManager trustManager;
        SSLSocketFactory sslSocketFactory;
        try {
            trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            sslSocketFactory = sslContext.getSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        client = new OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, trustManager)
                .connectTimeout(45, TimeUnit.SECONDS)
                .readTimeout(45, TimeUnit.SECONDS)
                .protocols(Arrays.asList(Protocol.HTTP_1_1))
                .build();
    }

    public OkHttpClient getClient() {
        return client;
    }

    /**
     * Returns an input stream containing one or more certificate PEM files. This implementation just
     * embeds the PEM files in Java strings; most applications will instead read this from a resource
     * file that gets bundled with the application.
     */
    private InputStream trustedCertificatesInputStream() {
        return context.getResources().openRawResource(R.raw.my_cert1);
    }

    /**
     * Returns a trust manager that trusts {@code certificates} and none other. HTTPS services whose
     * certificates have not been signed by these certificates will fail with a {@code
     * SSLHandshakeException}.
     *
     * <p>This can be used to replace the host platform's built-in trusted certificates with a custom
     * set. This is useful in development where certificate authority-trusted certificates aren't
     * available. Or in production, to avoid reliance on third-party certificate authorities.
     *
     * <p>See also {@link CertificatePinner}, which can limit trusted certificates while still using
     * the host platform's built-in trust store.
     *
     * <h3>Warning: Customizing Trusted Certificates is Dangerous!</h3>
     *
     * <p>Relying on your own trusted certificates limits your server team's ability to update their
     * TLS certificates. By installing a specific set of trusted certificates, you take on additional
     * operational complexity and limit your ability to migrate between certificate authorities. Do
     * not use custom trusted certificates in production without the blessing of your server's TLS
     * administrator.
     */
    private X509TrustManager trustManagerForCertificates(InputStream in)
            throws GeneralSecurityException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("expected non-empty set of trusted certificates");
        }

        // Put the certificates a key store.
        char[] password = "password".toCharArray(); // Any password will work.
        KeyStore keyStore = newEmptyKeyStore(password);
        int index = 0;
        for (Certificate certificate : certificates) {
            String certificateAlias = Integer.toString(index++);
            keyStore.setCertificateEntry(certificateAlias, certificate);
        }

        // Use it to build an X509 trust manager.
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
            throw new IllegalStateException("Unexpected default trust managers:"
                    + Arrays.toString(trustManagers));
        }
        return (X509TrustManager) trustManagers[0];
    }

    private KeyStore newEmptyKeyStore(char[] password) throws GeneralSecurityException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream in = null; // By convention, 'null' creates an empty key store.
            keyStore.load(in, password);
            return keyStore;
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

}
{% endhighlight %}

# Custom Certificate Pinning using OkHttp's CertificatePinner {#okhttp}

OkHttp is a HTTP client library for java and android. below implementation explicitly enforces certificate pinning by hardcoding a known SHA-256 fingerprint of the expected certificate for android.com. It creates a custom CertificatePinner object and attaches it to an OkHttpClient, which will only trust the pinned certificate, even if the certificate is otherwise valid and signed by a trusted Certificate Authority (CA).

If the server presents a different certificate, the request will fail improving security against attacks like man-in-the-middle (MITM).

MainActivity.java

{% highlight java %}

package com.broken.ssltest;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.CertificatePinner;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.IOException;

public class MainActivity extends AppCompatActivity {
    private TextView textView;
    private Button button;
    private OkHttpClient client = new OkHttpClient.Builder()
            .build();
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        textView = findViewById(R.id.textView);
        button = findViewById(R.id.button);
        button.setOnClickListener(v -> fetchData());

    }

    private void fetchData(){
        textView.setText("is this working");
        String url = "https://android.com";
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add("android.com", "sha256/py9B85M56Dx4rvrrkL07wi3rYIg4ug/qZwwPRbC1Q8I=")
                .build();
        OkHttpClient client = new OkHttpClient.Builder()
                .certificatePinner(certificatePinner)
                .build();
        Request request = new Request.Builder()
                .url(url)
                .build();

        client.newCall(request).enqueue(new Callback(){
            @Override
            public void onFailure(Call call, IOException e){
                runOnUiThread(() -> textView.setText("Request Failed: " + e.getMessage()));
            }
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful() && response.body() != null) {
                    String responseData = response.body().string();
                    runOnUiThread(() -> textView.setText(responseData));
                } else {
                    runOnUiThread(() -> textView.setText("Response Failed"));
                }
            }
        });

    }
}

{% endhighlight %}

Generating Certificate Hash:

{% highlight c# %}

openssl s_client -connect android.com:443 </dev/null 2>/dev/null | \
  openssl x509 -pubkey | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -binary | \
  base64


{% endhighlight %}

# Certificate Pinning via Network Security Configuration {#nsc}

Certificate pinning using Android’s Network Security Configuration allows you to pin specific certificates or public keys of your trusted servers inside an XML file. This ensures your app will only connect to servers that match the pinned certificate – helping to prevent Man-in-the-Middle (MITM) attacks, even if a malicious root certificate is installed on the device. this method is very easy to implement and also only available for API level 24 or higher

1. create the XML configuration file
File Path -> /res/xml/network_security_config 

{% highlight java %}
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">www.android.com</domain>
        <pin-set>
            <pin digest="SHA-256">js++oMHZaMnLx4F/zy2Ze/kqQqe9Z1elKyLjlxyOS0I=</pin>
        </pin-set>
    </domain-config>
</network-security-config>

{% endhighlight %}

2. Link the XML in AndroidManifest.xml

{% highlight java %}
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ... >

{% endhighlight %}

3. Get the SHA-256 public key hash

{% highlight bash %}

echo | openssl s_client -connect www.android.com:443 | openssl x509 -outform DER > android_cert.der
openssl x509 -inform DER -in android_cert.der -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64


{% endhighlight %}

4. Normal Network request using OkHttp

MainActivity.java

{% highlight c# %}
package com.broken.network_security_config1;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    private Button mbutton;
    private TextView mtextview;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        mbutton = findViewById(R.id.button);
        mtextview = findViewById(R.id.textView);

        mbutton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                OkHttpClient client = new OkHttpClient();
                Request request = new Request.Builder()
                        .url("https://www.android.com")
                        .build();

               
                mtextview.setText("Loading...");

                client.newCall(request).enqueue(new Callback() {
                    @Override
                    public void onFailure(Call call, IOException e) {
                        runOnUiThread(() -> mtextview.setText("Error: " + e.getMessage()));
                    }

                    @Override
                    public void onResponse(Call call, Response response) throws IOException {
                        if (response.isSuccessful()) {
                            String responseBody = response.body().string();
                            runOnUiThread(() -> mtextview.setText("Worked: " + responseBody));
                        } else {
                            runOnUiThread(() -> mtextview.setText("Didn't work. Code: " + response.code()));
                        }
                    }
                });
            }
        });
    }
}
{% endhighlight %}