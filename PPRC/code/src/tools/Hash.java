package tools;

import algorithm.Setup;
import it.unisa.dia.gas.jpbc.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {




    //SHA256
    public static byte[] getSHA256(String str) throws Exception{

        Setup.messageDigest.update(str.getBytes("UTF-8"));
        String encodestr = byte2Hex(Setup.messageDigest.digest());
        byte[] encode = encodestr.getBytes();
        return encode;
    }

    private static String byte2Hex(byte[] bytes) throws Exception{
        StringBuffer stringBuffer = new StringBuffer();
        for (int i=0;i<bytes.length;i++){
            String temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length()==1){
                stringBuffer.append("0");
            }
            stringBuffer.append(temp);
        }
        return stringBuffer.toString();
    }

    public static Element hash(String a) throws Exception {

        Element Hash_to_Z= Setup.pairing.getG1().newElement().setFromHash(getSHA256(a), 0, getSHA256(a).length);

        return Hash_to_Z;
    }

    public static Element hash2(String b) throws Exception {
        Element Hash_to_G= Setup.pairing.getZr().newElement().setFromHash(getSHA256(b), 0, getSHA256(b).length);

        return Hash_to_G;
    }

}
