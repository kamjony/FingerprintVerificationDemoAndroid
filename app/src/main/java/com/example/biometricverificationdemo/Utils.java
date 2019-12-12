package com.example.biometricverificationdemo;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;

class Utils {
    static void saveStringInSp(Context c, String key, String val){
        SharedPreferences.Editor editor = c.getSharedPreferences("SP", Activity.MODE_PRIVATE).edit();
        editor.putString(key, val);
        editor.apply();
    }

    static String getStringFromSp(Context c, String key){
        SharedPreferences sharedPreferences = c.getSharedPreferences("SP", Activity.MODE_PRIVATE);
        return sharedPreferences.getString(key,null);
    }
}
