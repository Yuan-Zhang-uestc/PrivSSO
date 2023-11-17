package algorithm;

import entity.CA;
import entity.ServiceProvider;
import it.unisa.dia.gas.jpbc.Element;
import jdk.nashorn.internal.ir.debug.ObjectSizeCalculator;

import entity.cert_acc_rg;
import javafx.beans.binding.Bindings;
import tools.AES;
import tools.BLS;
import tools.Hash;
import tools.HexToBytes;

import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

import static algorithm.Setup.*;


public class Registration {


    public static float ca_reg = 0;
    public static float sp_reg = 0;
    public static float user_reg = 0;

    public static float user_reg_com = 0;


    public static void registration() throws Exception {


        user.user_ID_acc_s = new Element[Setup.number_SP];
        user.user_pk_acc_s = new Element[Setup.number_SP];
        user.user_sk_acc_s = new Element[Setup.number_SP];
        user.account_i = new String[number_SP];
        user.recover_i = new String[number_SP];

        for (int i=0;i<Setup.number_SP;i++){
            user.user_ID_acc_s[i] =  pairing.getZr().newRandomElement().getImmutable();
            user.user_sk_acc_s[i] =  pairing.getZr().newRandomElement().getImmutable();
            user.user_pk_acc_s[i] = Setup.G_generator.powZn(user.user_sk_acc_s[i]);
        }


        //User send CSR to CA
        long user_reg_0 = System.nanoTime();
        for (int j=0;j<Setup.number_SP;j++){
            String cs_request_acc = user.user_ID_acc_s[j]+"||"+user.user_pk_acc_s[j];
            user_reg_com+=cs_request_acc.getBytes().length;
        }
        long user_reg_1 = System.nanoTime();
        user_reg = user_reg_1-user_reg_0;

        //CA sends Cert_acc_i to User
        for (int k=0;k<Setup.number_SP;k++){

            long ca_reg_0 = System.nanoTime();

            cert_acc_rg cert_acc_rg_k = new cert_acc_rg();
            cert_acc_rg_k.serviceProvider = new ServiceProvider();
            cert_acc_rg_k.ca = new CA();
            cert_acc_rg_k.serial_1 = String.valueOf(pairing.getZr().newRandomElement().getImmutable());
            //time
            SimpleDateFormat tempDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            cert_acc_rg_k.validity_1 = tempDate.format(new Date(System.currentTimeMillis()));


//            long cert_1_1 = 0;
//            cert_1_1+=ObjectSizeCalculator.getObjectSize(cert_acc_rg_k.serviceProvider);
//            cert_1_1+=ObjectSizeCalculator.getObjectSize(cert_acc_rg_k.ca);
//            cert_1_1+=ObjectSizeCalculator.getObjectSize(cert_acc_rg_k.serial_1);
//            cert_1_1+=ObjectSizeCalculator.getObjectSize(cert_acc_rg_k.validity_1);
            user_reg_com+=149.64*1024;


            cert_acc_rg_k.hash_cert = Hash.hash(cert_acc_rg_k.serial_1+cert_acc_rg_k.validity_1);

            cert_acc_rg_k.inject = user.user_ID_acc_s[k] + "||" +user.user_pk_acc_s[k];
            cert_acc_rg_k.hash_inject = Hash.hash(user.user_ID_acc_s[k] + "||" +user.user_pk_acc_s[k]);


            //System.out.println("cert  1  _3:"+cert_1_3+"bit");
            //BLS Signature

            cert_acc_rg_k.Sig = BLS.Signature(cert_acc_rg_k.serial_1+cert_acc_rg_k.validity_1,user.user_sk);

            long ca_reg_1 = System.nanoTime();

//            time_mid=ca_reg_1-ca_reg_0;
//
            ca_reg=ca_reg_1-ca_reg_0;


            long sp_reg_0 = System.nanoTime();
            //User sends Cert_acc_i to SP and SP verify the validity of the cert
            boolean verify_result = BLS.Verify(cert_acc_rg_k.Sig,user.user_pk,cert_acc_rg_k.serial_1+cert_acc_rg_k.validity_1);
            long sp_reg_1 = System.nanoTime();
            sp_reg = sp_reg_1-sp_reg_0;



            long user_reg_9 = System.nanoTime();
            if(verify_result ==true){
                serviceProviders[k].register_user_pk = user.user_pk_acc_s[k];
                //System.out.println("registered successfully");
                user.account_i[k] = user.user_ID + "||" + user.user_ID_acc_s[k] + "||"
                        + user.user_pk_acc_s[k] + "||" + user.user_sk_acc_s[k];
                String user_K = new String(Hash.getSHA256(String.valueOf(user.user_K)), StandardCharsets.UTF_8);
                user.user_K = HexToBytes.hexStringToByteArray(user_K);
                user.recover_i[k] = AES.encryptAES(user.account_i[k], user.user_K);
                user_reg_com +=user.recover_i[k].getBytes().length;
                //CA store recover_i safely
            }
            long user_reg_10 = System.nanoTime();
            user_reg+=user_reg_10-user_reg_9;


        }






    }

}
