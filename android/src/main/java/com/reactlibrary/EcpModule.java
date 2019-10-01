package com.reactlibrary;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import android.util.Log;
import android.os.Environment;
import android.os.Bundle;
import android.util.Base64;
import android.database.Cursor;
import android.net.Uri;
import java.io.File;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import android.content.Context;
import java.util.Arrays;
import android.provider.MediaStore;
import dbt.cryptomanager.core.ProviderManager;
import dbt.cryptomanager.core.generators.DefaultSignatureGenerator;
import dbt.cryptomanager.core.generators.SignatureGenerator;
import dbt.cryptomanager.core.keys.KeyLoaderImpl;
import dbt.cryptomanager.core.utils.CertificateConverter;
import org.apache.commons.io.FileUtils;


public class EcpModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;

    private static final int BUFFER_SIZE = 1024 * 2;

    public EcpModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    public int copyStream(InputStream input, OutputStream output) throws Exception, IOException {
        byte[] buffer = new byte[BUFFER_SIZE];

        BufferedInputStream in = new BufferedInputStream(input, BUFFER_SIZE);
        BufferedOutputStream out = new BufferedOutputStream(output, BUFFER_SIZE);
        int count = 0, n = 0;
        try {
            while ((n = in.read(buffer, 0, BUFFER_SIZE)) != -1) {
                out.write(buffer, 0, n);
                count += n;
            }
            out.flush();
        } finally {
            try {
                out.close();
            } catch (IOException e) {
                Log.e("Everflow",e.getMessage());
            }
            try {
                in.close();
            } catch (IOException e) {
                Log.e("Everflow",e.getMessage());
            }
        }
        return count;
    }

    public String getFilePathFromURI(Context context, Uri contentUri) {
        try {
            //copy file and send new file path
            String fileName = getFileName(contentUri);
            File outputDir = context.getCacheDir(); // context being the Activity pointer
            File copyFile = File.createTempFile("prefix", "extension", outputDir);
            copy(context, contentUri, copyFile);
            return copyFile.getAbsolutePath();
        } catch (IOException e) {
            Log.e("Everflow",e.getMessage());
            return null;
        }
    }

    public String getFileName(Uri uri) {
        if (uri == null) return null;
        String fileName = null;
        String path = uri.getPath();
        int cut = path.lastIndexOf('/');
        if (cut != -1) {
            fileName = path.substring(cut + 1);
        }
        return fileName;
    }

    public void copy(Context context, Uri srcUri, File dstFile) {
        try {
            InputStream inputStream = context.getContentResolver().openInputStream(srcUri);
            if (inputStream == null) return;
            OutputStream outputStream = new FileOutputStream(dstFile);
            copyStream(inputStream, outputStream);
            inputStream.close();
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getRealPathFromURI(Uri contentUri) {
        Cursor cursor = null;
        try {
            String[] proj = { "document_id" };
            Log.e("Everflow", "contentUri : " + contentUri);
            cursor = reactContext.getApplicationContext().getContentResolver().query(contentUri,  proj, null, null, null);
            Log.e("Everflow", "cursor : " + cursor);
            int column_index = cursor.getColumnIndexOrThrow("document_id");
            cursor.moveToFirst();

            Log.e("Everflow", "column_index : " + column_index);
            return cursor.getString(column_index);
        } catch (Exception e) {
            Log.e("Everflow", "getRealPathFromURI Exception : " + e.toString());
            return "";
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    @Override
    public String getName() {
        return "Ecp";
    }

    @ReactMethod
    public void sampleMethod(String stringArgument, String password, String data, Callback errorCallback,
                             Callback successCallback) {
        // TODO: Implement some actually useful functionality


        String externalStorage = Environment.getExternalStorageDirectory().getAbsolutePath();

        String myDirectory = "Everflow";

        Uri contentUri = Uri.parse(stringArgument);

        Log.d("Everflow", contentUri.getPath());

        String realpaths = getFilePathFromURI(reactContext.getApplicationContext() ,contentUri);
        Log.d("Everflow", "REALPATH:"+realpaths);
        File file = new File(realpaths);
//
//        File outputDirectory = new File(externalStorage + File.separator + myDirectory );
//
//        if(!outputDirectory.exist()){
//            outputDirectory.mkDir();
//        }
//
//
//        Log.d("Everflow", outputDirectory);
        try {

            ProviderManager.init();

//            byte[] array = reactContext.getContentResolver().openInputStream(contentUri).readBytes();

              byte[] array = FileUtils.readFileToByteArray(file);
//            ByteArrayInputStream key = new ByteArrayInputStream(FileUtils.readFileToByteArray(file));
//
//            byte[] array = new byte[key.available()];
//            key.read(array);
            KeyLoaderImpl keyFile = new KeyLoaderImpl(array, password.toCharArray());
            SignatureGenerator generator = new DefaultSignatureGenerator();
//
            Log.d("Everflow", "DATA: "+ data);
//
//            Charset var7 = Charset.UTF_8;

//            byte[] buffer = data.getBytes("UTF-8");

//            Base64.decode(dataForSign, Base64.DEFAULT)

            Log.d("Everflow", "keyFile : " + keyFile);

            Log.d("Everflow", "BUFFER UTF8: " + Base64.decode(data, Base64.DEFAULT));

            String signature = generator.sign(keyFile, Base64.decode(data, Base64.DEFAULT));
            Log.d("Everflow", "Signature " + signature);

//
//        File outputFile = new File(externalStorage + File.separator + myDirectory + File.separator + "RSA123123123.p12");
////
//        outputFile.createFile();
//
//        Log.d("Everflow", outputFile);


           successCallback.invoke(signature.toString());
        } catch (Exception e) {
            errorCallback.invoke( e.getMessage() );
        }
    }
}
