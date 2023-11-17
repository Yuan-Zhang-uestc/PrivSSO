package tools;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

public class AES {
    public static byte[] rand=new byte[16];
    public static Random r=new Random();
    public static IvParameterSpec IV=new IvParameterSpec(rand);



    //AES symmetric algorithm
    public static String encryptAES(String plaintext,byte[] key) throws Exception{
        Cipher c=Cipher.getInstance("AES/CTR/PKCS5Padding");
        SecretKeySpec secretKeySpec=new SecretKeySpec(key,"AES");
        c.init(Cipher.ENCRYPT_MODE,secretKeySpec, IV);
        byte[] bytes=c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        String ciphertext= Base64.getEncoder().encodeToString(bytes);
        return ciphertext;

    }
    public static String decryptAES(String ciphertext,byte[] key) throws Exception{
        Cipher c=Cipher.getInstance("AES/CTR/PKCS5Padding");
        SecretKeySpec secretKeySpec=new SecretKeySpec(key,"AES");
        c.init(Cipher.DECRYPT_MODE,secretKeySpec,IV);
        byte[] bytes=c.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(bytes);
    }





}
