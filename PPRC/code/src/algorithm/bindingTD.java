package algorithm;

import entity.CA;
import entity.SmartDevice;
import entity.cert_td;
import jdk.nashorn.internal.ir.debug.ObjectSizeCalculator;
import tools.AES;
import tools.BLS;
import tools.Hash;
import tools.HexToBytes;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

import static algorithm.Setup.pairing;
import static algorithm.Setup.user;


public class bindingTD {

    public static cert_td cert_td_TD;
    public static float ca_bind = 0;
    public static float TD_bind = 0;
    public static float user_bind = 0;

    public static float user_bind_com = 0;
    public static float td_bind_com = 0;

    public static void bindingTD() throws Exception {
        long TD_bind_0 = System.nanoTime();
        cert_td_TD = new cert_td();
        long TD_bind_1 = System.nanoTime();
        TD_bind = TD_bind_1-TD_bind_0;


        //User send CSR_TD to CA
        long user_bind_0 = System.nanoTime();
        String cs_request_td = Setup.user.user_ID + "||" +
                Setup.smartDevice.TD_ID + "||" + Setup.smartDevice.td_pk;
        user_bind_com+=cs_request_td.getBytes().length;

        long user_bind_1 = System.nanoTime();
        user_bind = user_bind_1-user_bind_0;

        //CA sends Cert_td to User

        long ca_bind_0 = System.nanoTime();

        cert_td_TD.smartDevice = new SmartDevice();
        cert_td_TD.ca = new CA();
        cert_td_TD.serial_2 = String.valueOf(pairing.getZr().newRandomElement().getImmutable());

        SimpleDateFormat tempDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        cert_td_TD.validity_2 = tempDate.format(new Date(System.currentTimeMillis()));

        cert_td_TD.hash_cert = Hash.hash(cert_td_TD.serial_2 + cert_td_TD.validity_2);
        cert_td_TD.inject = Setup.smartDevice.TD_ID + "||" + Setup.smartDevice.td_pk;
        cert_td_TD.hash_inject = Hash.hash(Setup.smartDevice.TD_ID + "||" + Setup.smartDevice.td_pk);
        cert_td_TD.Sig = BLS.Signature(cert_td_TD.serial_2 + cert_td_TD.validity_2,Setup.smartDevice.td_sk);

        long ca_bind_1 = System.nanoTime();
        ca_bind = ca_bind_1-ca_bind_0;
//        long num_cert1 = 0;
//        for (int num = 0;num<1000;num++){
//            num_cert1+= ObjectSizeCalculator.getObjectSize(cert_td_TD);
//        }
//        System.out.println("cert  td: "+num_cert1 + "bit");

        user_bind_com+=149.93*1024;
        td_bind_com+=149.93*1024;
        for (int k=0;k<Setup.number_SP;k++){
            String user_K = new String(Hash.getSHA256(String.valueOf(user.user_K)), StandardCharsets.UTF_8);
            user.user_K = HexToBytes.hexStringToByteArray(user_K);
            user.recover_i[k] = AES.encryptAES(user.account_i[k], user.user_K);
            String mid = AES.decryptAES(user.recover_i[k], user.user_K);
            user_bind_com+=user.recover_i[k].getBytes().length;
            td_bind_com+=mid.getBytes().length;

        }

    }




}
