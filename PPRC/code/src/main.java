import algorithm.*;
import entity.CA;
import entity.ServiceProvider;
import entity.SmartDevice;
import entity.User;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import jdk.nashorn.internal.ir.debug.ObjectSizeCalculator;
import org.apache.poi.xssf.usermodel.XSSFPivotTable;
import tools.AES;
import tools.BLS;
import tools.Hash;

import java.lang.instrument.Instrumentation;
import java.text.SimpleDateFormat;
import java.util.Date;

import static algorithm.Setup.number_SP;
import static algorithm.Setup.pairing;

public class main {
    //security Parameter








    public static ServiceProvider[] serviceProviders= new ServiceProvider[Setup.number_SP];
    public static User user;

    static {
        try {
            user = new User();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static CA ca = new CA();
    public static SmartDevice smartDevice = new SmartDevice();

    public static Element[] m_s = new Element[number_SP];


    public static void main(String[] args) throws Exception {



        Setup.setup();
        Registration.registration();
        bindingTD.bindingTD();
        m_s = Authentication.authentication_1();
        Authentication.authentication_2(m_s);
        unbindingTD.unbindingTD();


//
//        long Setup_0=System.nanoTime();
//        Setup.setup();
//        long Setup_1=System.nanoTime();
//        System.out.println("time_Setup:"+(Setup_1-Setup_0));
//
//
//        long Registration_0 = System.nanoTime();
//        Registration.registration();
//        long Registration_1 = System.nanoTime();
//        System.out.println("time_Reg:"+(Registration_1-Registration_0));
//
//
//        long binding_0 = System.nanoTime();
//        bindingTD.bindingTD();
//        long binding_1 = System.nanoTime();
//        System.out.println("time_binding:"+(binding_1-binding_0));
//
//
//
//        long Auth_0 = System.nanoTime();
//        Authentication.authentication();
//        long Auth_1 = System.nanoTime();
//        System.out.println("time_Auth:"+(Auth_1-Auth_0));
//
//
//
//        long un_0 = System.nanoTime();
//        unbindingTD.unbindingTD();
//        long un_1 = System.nanoTime();
//        System.out.println("time_un:"+(un_1-un_0));



//        Object ServiceProvider = new ServiceProvider();
//        Element b = Hash.hash2("dd");
//        String serial_3 = String.valueOf(pairing.getZr().newRandomElement().getImmutable());
//        Element m = pairing.getZr().newRandomElement().getImmutable();
//        //time
//        SimpleDateFormat tempDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
//        String validity_3 = tempDate.format(new Date(System.currentTimeMillis()));
//        String a = "006136";
//        String inject = pairing.getZr().newRandomElement().getImmutable() + "||" + pairing.getZr().newRandomElement().getImmutable();
//        Element test = Hash.hash2(inject);
//        Element text_1 = BLS.Signature(inject,m);
//
//        System.out.println(text_1.getLengthInBytes());

//        Setup.setup();
//        System.out.println("ca:Setup:"+Setup.ca_setup/1000000000);
//
//        Registration.registration();
//        System.out.println("ca:Reg:"+Registration.ca_reg/1000000000);
//        System.out.println("sp_reg:"+Registration.sp_reg/1000000000);
//        System.out.println("user_reg:"+Registration.user_reg/1000000000);
//
//        System.out.println("user_reg_com:"+Registration.user_reg_com/(1024*1024)+"  MB");
//
//        bindingTD.bindingTD();
//        System.out.println("ca_bind:"+bindingTD.ca_bind/1000000000);
//        System.out.println("TD_bing:"+bindingTD.TD_bind);
//        System.out.println("user_bind:"+bindingTD.user_bind);
//
//        System.out.println("user_bind_com:"+bindingTD.user_bind_com/(1024*1024)+"  MB");
//        System.out.println("td_bind_com:"+bindingTD.td_bind_com/(1024*1024)+"  MB");
//
//
//        Authentication.authentication();
//        System.out.println("ca_login:"+Authentication.ca_login/1000000000);
//        System.out.println("TD_login:"+Authentication.TD_login/1000000000);
//        System.out.println("sp_login:"+Authentication.sp_login/1000000000);
//
//        System.out.println("td_login_com:"+Authentication.td_login_com/(1024*1024)+"  MB");
//
//        unbindingTD.unbindingTD();
//        System.out.println("ca_unbind:"+unbindingTD.ca_unbind/1000000000);
//        System.out.println("user_unbind:"+unbindingTD.user_unbind/1000000000);
//
//        System.out.println("user_unbind_com:"+unbindingTD.user_unbind_com/(1024*1024)+"  MB");





    }
}
