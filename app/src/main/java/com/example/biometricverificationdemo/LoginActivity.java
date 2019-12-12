package com.example.biometricverificationdemo;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class LoginActivity extends AppCompatActivity {

    FingerprintManager fingerprintManager;
    KeyguardManager keyguardManager;
    EditText password;
    private static int STORE_CREDENTIALS = 1000;
    private static int LOGIN_WITH_FINGERPRINT = 1;
    ImageButton imgBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        fingerprintManager = (FingerprintManager) getSystemService(Context.FINGERPRINT_SERVICE);
        password = (EditText) findViewById(R.id.password);
        imgBtn = (ImageButton) findViewById(R.id.btn_fingerprint);

        String checkPassword = Utils.getStringFromSp(this, "password");
        if (checkPassword == null){
            imgBtn.setVisibility(View.GONE);
        } else {
            imgBtn.setVisibility(View.VISIBLE);
        }

        initFingerprintSettings();

        findViewById(R.id.loginbutton).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                storePasswordAndLogin();
            }
        });
        
        imgBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (checkFingerprintSettings()){
                    Toast.makeText(LoginActivity.this, "Place your finger on the magic place ;)", Toast.LENGTH_SHORT).show();
                    Authenticator auth = Authenticator.getInstance();
                    if (auth.cipherInit()){
                        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(auth.getCipher());
                        FingerprintHandler handler = new FingerprintHandler();
                        handler.startAuthentication(cryptoObject);

                    }
                }
            }
        });
    }

    private void initFingerprintSettings() {
        keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        if (!keyguardManager.isKeyguardSecure()){
            Toast.makeText(this,"Secure lock", Toast.LENGTH_SHORT).show();
        }
    }

    private void loginWithFingerprint() {
        try {
            String base64EncryptedPassword = Utils.getStringFromSp(this, "password");
            String base64EncryptionIv = Utils.getStringFromSp(this, "encryptionIv");

            if (base64EncryptedPassword != null) {

                byte[] encryptionIv = Base64.decode(base64EncryptionIv, Base64.DEFAULT);
                byte[] encryptedPassword = Base64.decode(base64EncryptedPassword, Base64.DEFAULT);

                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                SecretKey secretKey = (SecretKey) keyStore.getKey("Key", null);
                Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionIv));
                byte[] passwordBytes = cipher.doFinal(encryptedPassword);
                String password = new String(passwordBytes, "UTF-8");

                Toast.makeText(this, "Password: " + password, Toast.LENGTH_SHORT).show();
                startActivity(new Intent(LoginActivity.this, MainActivity.class));
            }
        } catch (UserNotAuthenticatedException e){
            displayAuthScreen(LOGIN_WITH_FINGERPRINT);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException |
                UnrecoverableKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    private void storePasswordAndLogin() {
        try {
            String passwordSting = password.getText().toString();
            SecretKey secretKey = createKey();
            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptionIv = cipher.getIV();
            byte[] passwordBytes = passwordSting.getBytes("UTF-8");
            byte[] encryptedPasswordBytes = cipher.doFinal(passwordBytes);
            String encryptedPassword = Base64.encodeToString(encryptedPasswordBytes, Base64.DEFAULT);

            Utils.saveStringInSp(this, "password", encryptedPassword);
            Utils.saveStringInSp(this, "encryptionIv", Base64.encodeToString(encryptionIv, Base64.DEFAULT));

            password.setText(null);

            startActivity(new Intent(LoginActivity.this, MainActivity.class));
        } catch (UserNotAuthenticatedException e){
            displayAuthScreen(STORE_CREDENTIALS);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    private void displayAuthScreen(int requestCode){
        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, requestCode);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == Activity.RESULT_OK) {
            if (requestCode == STORE_CREDENTIALS) {
                storePasswordAndLogin();
            } else if (requestCode == LOGIN_WITH_FINGERPRINT) {
                loginWithFingerprint();
            }
        }
    }

    private SecretKey createKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(new KeyGenParameterSpec.Builder("Key",
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(false)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to create key", e);
        }
    }


    private class FingerprintHandler extends FingerprintManager.AuthenticationCallback{

        CancellationSignal signal;
        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            Toast.makeText(LoginActivity.this, "Error Authentication", Toast.LENGTH_SHORT).show();
        }

        @Override
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            super.onAuthenticationHelp(helpCode, helpString);
            Toast.makeText(LoginActivity.this, "Authentication Help ", Toast.LENGTH_SHORT).show();
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            Toast.makeText(LoginActivity.this, "Failed Auth", Toast.LENGTH_SHORT).show();
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
//            Toast.makeText(LoginActivity.this, "Successful Authentication", Toast.LENGTH_SHORT).show();

            loginWithFingerprint();

        }

        void startAuthentication(FingerprintManager.CryptoObject cryptoObject) {
            signal = new CancellationSignal();

            if (ActivityCompat.checkSelfPermission(LoginActivity.this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                return;
            }

            fingerprintManager.authenticate(cryptoObject, signal, 0, this, null);

        }

        void cancelFingerprint(){
            signal.cancel();
        }
    }

    private boolean checkFingerprintSettings() {
        if (fingerprintManager.isHardwareDetected()) {
            if (fingerprintManager.hasEnrolledFingerprints()){
                if (keyguardManager.isKeyguardSecure()){
                    return true;
                }
            }   else {
                Toast.makeText(this, "Give some finger!!", Toast.LENGTH_SHORT).show();
                startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
            }
        }

        return false;
    }
}
