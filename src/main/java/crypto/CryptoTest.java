package crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


/**
 * Created by qxw121 on 5/16/16.
 */

public class CryptoTest {

    public static final String[] keys = {"xxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"};

    private byte[] key;

    private static final String ALGORITHM = "AES";

    public CryptoTest(String encryptionKey) {

        key = encryptionKey.getBytes();
    }

    public String encrypt(String data) {

        byte[] dataToSend = data.getBytes();
        Cipher c = null;
        try {
            c = Cipher.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AesEncryption: NoSuchAlgorithmException",e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("AesEncryption: NoSuchPaddingException",e);
        }
        SecretKeySpec k = new SecretKeySpec(key, ALGORITHM);
        try {
            c.init(Cipher.ENCRYPT_MODE, k);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AesEncryption: InvalidKeyException",e);
        }
        byte[] encryptedData = "".getBytes();
        try {
            encryptedData = c.doFinal(dataToSend);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("AesEncryption: illegalBlockException", e);

        } catch (BadPaddingException e) {
            throw new RuntimeException("AesEncryption: BadPaddingException", e);
        }
        byte[] encryptedByteValue = new Base64().encode(encryptedData);
        return new String(encryptedByteValue);// .toString();
    }

    public String decrypt(String data) {

        byte[] encryptedData = new Base64().decode(data);
        Cipher c = null;
        try {
            c = Cipher.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AesEncryption: NoSuchAlgorithmException", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("AesEncryption: NoSuchPaddingException", e);
        }
        SecretKeySpec k = new SecretKeySpec(key, ALGORITHM);
        try {
            c.init(Cipher.DECRYPT_MODE, k);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AesEncryption: InvalidKeyException", e);
        }
        byte[] decrypted = null;
        try {
            decrypted = c.doFinal(encryptedData);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("AesEncryption: illegalBlockException", e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("AesEncryption: BadPaddingException", e);
        }
        return new String(decrypted);
    }

    public static void main(String[] args){
        test();
    }
    public static void test(){
        try {
            CryptoTest cryptoTest128 = new CryptoTest(keys[0]);
            CryptoTest cryptoTest256 = new CryptoTest(keys[1]);
            String plainText = "test";

            System.out.println("Testing 128 bit ...");
            String encryptedText128 = cryptoTest128.encrypt(plainText);
            String decryptedText128 = cryptoTest128.decrypt(encryptedText128);
            System.out.println("128 bit success:" + decryptedText128.equals(plainText));

            System.out.println("Testing 256 bit ...");
            String encryptedText256 = cryptoTest256.encrypt(plainText);
            String decryptedText256 = cryptoTest256.decrypt(encryptedText256);
            System.out.println("256 bit success:" + decryptedText256.equals(plainText));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
