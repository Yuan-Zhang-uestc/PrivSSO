package algorithm;

import entity.*;
import it.unisa.dia.gas.jpbc.Element;
import tools.BLS;
import tools.Hash;

import java.text.SimpleDateFormat;
import java.util.Date;

import static algorithm.Setup.*;


public class Authentication {

    public static float ca_login = 0;
    public static float TD_login = 0;
    public static float sp_login = 0;

    public static float td_login_com = 0;


    public static cert_acc[] cert_acc_s = new cert_acc[number_SP];



    public static Element[] authentication_1() throws Exception {

        //User send request to SP


        Element[] m_s = new Element[number_SP];
        Element[] final_m_s = new Element[number_SP];
        //Group server request
        String CSR_group_acc = "start";
        String id_ss = String.valueOf(pairing.getZr().newRandomElement().getImmutable());
        td_login_com += CSR_group_acc.getBytes().length;
        td_login_com += id_ss.getBytes().length;
        long td_login_0 = System.nanoTime();
        for (int i = 0; i < Setup.number_SP; i++) {
            CSR_group_acc = CSR_group_acc + user.user_ID_acc_s[i] +
                    serviceProviders[i].register_user_pk +
                    BLS.Signature(user.user_ID_acc_s[i] + "||" + user.user_pk_acc_s[i], user.user_sk_acc_s[i]);
        }
        td_login_com += CSR_group_acc.getBytes().length;
        Element Sig_1 = BLS.Signature(CSR_group_acc, smartDevice.td_sk);
        long td_login_1 = System.nanoTime();
        TD_login = td_login_1 - td_login_0;


        //CA verifies the validity
//        long ca_login_0 = System.nanoTime();
        boolean verify1 = false;
        for (int j = 0; j < number_SP; j++) {
            boolean verify_1 = BLS.Verify(BLS.Signature(user.user_ID_acc_s[j] + "||" + user.user_pk_acc_s[j],
                            user.user_sk_acc_s[j]), user.user_pk_acc_s[j],
                    user.user_ID_acc_s[j] + "||" + user.user_pk_acc_s[j]);
            if (verify_1 == true) {
                verify1 = true;
            }
        }
        boolean verify_2 = BLS.Verify(bindingTD.cert_td_TD.Sig,
                smartDevice.td_pk, bindingTD.cert_td_TD.serial_2 + bindingTD.cert_td_TD.validity_2);
        boolean verify_3 = BLS.Verify(Sig_1, smartDevice.td_pk, CSR_group_acc);

        for (int j = 0; j < number_SP; j++) {

            if (verify1 == true && verify_2 == true && verify_3 == true) {
                System.out.println("successful");
                //generate Cert_acc
                cert_acc_s[j] = new cert_acc();
                cert_acc_s[j].serviceProvider = new ServiceProvider();
                cert_acc_s[j].ca = new CA();
                cert_acc_s[j].serial_3 = String.valueOf(pairing.getZr().newRandomElement().getImmutable());
                //time
                //SimpleDateFormat tempDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                //cert_acc_s[j].validity_3 = tempDate.format(new Date(System.currentTimeMillis()));
                m_s[j] = Hash.hash2(cert_acc_s[j].serial_3) ;

                final_m_s[j] = m_s[j];

                System.out.println("aaaaaa:"+m_s[j]);
                td_login_com += 149.81 * 1024;
            }
        }




        return final_m_s;
    }



    public static void authentication_2(Element[] m_s) throws Exception {

        Element[] m_s_copy = new Element[number_SP];
         for (int i=0;i<number_SP;i++){
             m_s_copy[i] = m_s[i].duplicate();
         }
        //一
        Element Sig_1_Re = G_generator;
        Element Sig_2_Re = G_generator_1;
        Element Sig_1_Re_ba = pairing.getG2().newRandomElement().getImmutable();




        Element middle_num = ca.CA_sk_X;
        System.out.println("middle::"+middle_num);

        for (int iii = 0; iii < number_SP; iii++) {
            Element middle_num_a = m_s_copy[iii].mul(ca.CA_sk[iii]);
            middle_num = middle_num.add(middle_num_a);
        }
        System.out.println("middle22::"+middle_num);
        Element Sig_2_Re_ba = Sig_1_Re_ba.powZn(middle_num);


        //ca
        cert_ss_s cert_ss_ss = new cert_ss_s();
        cert_ss_ss.serviceProvider = new ServiceProvider[number_SP];
        for (int i=0;i< number_SP;i++){
            cert_ss_ss.serviceProvider[i] = Setup.serviceProviders[i];
        }
        cert_ss_ss.ca = ca;
        cert_ss_ss.serial_5 = String.valueOf(pairing.getZr().newRandomElement().getImmutable());
        //time
        SimpleDateFormat tempDate5 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        cert_ss_ss.validity_5 = tempDate5.format(new Date(System.currentTimeMillis()));
        cert_ss_ss.hash_cert = new Element[number_SP+1];
        cert_ss_ss.hash_cert[0] = Hash.hash2(cert_ss_ss.serial_5 + "||" + cert_ss_ss.validity_5);
        for (int i=1;i< number_SP;i++){
            cert_ss_ss.hash_cert[i] = Hash.hash2(String.valueOf(cert_acc_s[i-1]));
        }
        cert_ss_ss.inject = new String[number_SP];
        for (int i=0;i< number_SP;i++){
            cert_ss_ss.inject[i] = user.user_ID_acc_s[i] + "||" + user.user_pk_acc_s[i];
        }
        cert_ss_ss.hash_inject = new Element[number_SP];
        for (int i=0;i<number_SP;i++){
            cert_ss_ss.hash_inject[i] = Hash.hash2(cert_ss_ss.inject[i]);
        }
        cert_ss_ss.Sig[0] = Sig_1_Re;
        cert_ss_ss.Sig[1] = Sig_2_Re;
        cert_ss_ss.Sig[2] = Sig_1_Re_ba;
        cert_ss_ss.Sig[3] = Sig_2_Re_ba;
//        double num_cert1 = 0;
//        for (int num = 0;num<1000;num++){
//            num_cert1+= ObjectSizeCalculator.getObjectSize(cert_ss_ss);
//        }
//        System.out.println("cert  acc: "+String.format("%.2f",num_cert1/4096000)+ "KB");

        long ca_login_1 = System.nanoTime();
//        ca_login = ca_login_1-ca_login_0;

        td_login_com+= 185*1024;
        //
        //TD retrieve Signature
        //二
        long td_login_4 = System.nanoTime();
        Element Re_r = pairing.getZr().newRandomElement().getImmutable();
        Element Re_t = pairing.getZr().newRandomElement().getImmutable();
        Element Sig_1_Re_ba_p = Sig_1_Re_ba.powZn(Re_r);
        Element middle_mix = Sig_1_Re_ba_p.powZn(Re_t);
        Element Sig_2_Re_ba_p = Sig_2_Re_ba.powZn(Re_r).mul(middle_mix);
        Element Sig_1_Re_p_s = G_generator.powZn(Re_t);
//        Element useless1 = one_G;
        for (int i_1 = 1; i_1 < ca.CA_pk_Y_1.length; i_1++) {
            Sig_1_Re_p_s = Sig_1_Re_p_s.mul(ca.CA_pk_Y_1[i_1].powZn(m_s[i_1]));
//            useless1.mul(ca.CA_pk_Y_1[i_1].powZn(m_s[i_1]));
        }

        Element Sig_2_Re_p_s = ca.CA_pk_Y_1[0].powZn(Re_t);
        for (int i_2 = 1; i_2 < ca.CA_pk_Z[0].length; i_2++) {
            Sig_2_Re_p_s = Sig_2_Re_p_s.mul(ca.CA_pk_Z[0][i_2].powZn(m_s[i_2]));
        }

        //cert_ss initial
        cert_ss cert_ss_s = new cert_ss();
        cert_ss_s.serviceProvider = new ServiceProvider();
        cert_ss_s.smartDevice = new SmartDevice();
        cert_ss_s.serial_4 = String.valueOf(pairing.getZr().newRandomElement().getImmutable());

        SimpleDateFormat tempDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        cert_ss_s.validity_4 = tempDate.format(new Date(System.currentTimeMillis()));

        cert_ss_s.hash_cert = Hash.hash(cert_ss_s.serial_4 + cert_ss_s.validity_4);
        cert_ss_s.inject = smartDevice.ss_ID + "||" + Setup.smartDevice.ss_pk;
        cert_ss_s.hash_inject = Hash.hash(Setup.smartDevice.TD_ID + "||" + Setup.smartDevice.ss_pk);
        cert_ss_s.Sig = BLS.Signature(cert_ss_s.serial_4 + cert_ss_s.validity_4, user.user_sk_acc_s[0]);

        Element Sig_2_ss = BLS.Signature(String.valueOf(smartDevice.ss_ID),smartDevice.ss_sk);



        td_login_com+=149.19*1024;
        td_login_com+=String.valueOf(Sig_2_ss).getBytes().length;
//        long num_cert2 = 0;
//        for (int num = 0;num<1000;num++){
//            num_cert2+=ObjectSizeCalculator.getObjectSize(cert_ss_s);
//        }
//        System.out.println("cert  ss: "+num_cert2 + "bit");
        long td_login_5 = System.nanoTime();
        TD_login +=td_login_5-td_login_4;




        for (int i=0;i<number_SP;i++){
            System.out.println("why::"+m_s[i]);
        }



        long sp_login_0 = System.nanoTime();
        //verify
        boolean result_Sig_2_ss = BLS.Verify(Sig_2_ss,smartDevice.ss_pk, String.valueOf(smartDevice.ss_ID));
        boolean result_Sig_ss = BLS.Verify(cert_ss_s.Sig,user.user_pk_acc_s[0],cert_ss_s.serial_4 + cert_ss_s.validity_4);
        if (result_Sig_ss==true && result_Sig_2_ss==true){
            Element middle_4 = ca.CA_pk_X.mul(Sig_1_Re_p_s);
            Element middle_2 = ca.CA_pk_Y_1[0].powZn(m_s[0]);
            Element middle_3 = middle_4.mul(middle_2);
//            Element test1 = pairing.pairing(G_generator.powZn(Re_r.mul(middle_test)),Sig_1_Re_ba);
//            Element test2 = pairing.pairing(G_generator.powZn(middle_test),Sig_1_Re_ba_p);
            Element left1 = pairing.pairing(middle_3,Sig_1_Re_ba_p);
            Element right1 = pairing.pairing(G_generator,Sig_2_Re_ba_p);
            Element left2 = pairing.pairing(Sig_1_Re_p_s,ca.CA_pk_Y_2[0]);
            Element right2 = pairing.pairing(Sig_2_Re_p_s, G_generator_1);
//            System.out.println(test1);
//            System.out.println(test2);
            System.out.println(left1);
            System.out.println(right1);
            System.out.println(left2);
            System.out.println(right2);


            Element exam_final = Re_t.add(ca.CA_sk_X);
            for (int i=0;i<number_SP;i++){
                exam_final = exam_final.add(m_s[i].mul(ca.CA_sk[i]));
            }
            exam_final = exam_final.mul(Re_r);
//            System.out.println("pairing_test"+pairing.pairing(G_generator,Sig_1_Re_ba.powZn(exam_final)));
//            System.out.println("pairing_test"+pairing.pairing(G_generator.powZn(exam_final),Sig_1_Re_ba));

//            System.out.println("gg:::"+Sig_2_Re_ba_p);
//            System.out.println("gg:::"+Sig_2_Re_ba.powZn(Re_r).mul(Sig_1_Re_ba.powZn(Re_t.mul(Re_r))));
//            System.out.println("please"+useless1);
//            System.out.println("please"+G_generator.powZn(useless2));
            if( left2.isEqual(right2) == true && left1.isEqual(right1) == true ){
                System.out.println(" verify pass");
            }
            else System.out.println("keep checking");
        }
        long sp_login_1 = System.nanoTime();
        sp_login = sp_login_1-sp_login_0;

    }
}
