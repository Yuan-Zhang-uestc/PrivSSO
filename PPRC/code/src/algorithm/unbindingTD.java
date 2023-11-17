package algorithm;

import it.unisa.dia.gas.jpbc.Element;
import jdk.nashorn.internal.ir.debug.ObjectSizeCalculator;
import tools.BLS;

/**
 * @author emilio
 * @date 2023-06-05 23:41
 */
public class unbindingTD {

    public static float ca_unbind = 0;
    public static float user_unbind = 0;

    public static float user_unbind_com = 0;

    public static void unbindingTD() throws Exception {

        long user_unbind_0 = System.nanoTime();
        String CRS_unbinding = Setup.user.user_ID + "||" + Setup.smartDevice.TD_ID;
        user_unbind_com+=CRS_unbinding.getBytes().length;
        Element Sig_unbinding = BLS.Signature(CRS_unbinding,Setup.user.user_sk);
        String Sig = String.valueOf(Sig_unbinding);
        user_unbind_com+= Sig.getBytes().length;
        long user_unbind_1 = System.nanoTime();

        user_unbind = user_unbind_1-user_unbind_0;
        //send to CA
        long ca_unbind_0=System.nanoTime();

        boolean result_unbinding = BLS.Verify(Sig_unbinding, Setup.user.user_pk,Setup.user.user_ID + "||" + Setup.smartDevice.TD_ID);

        if(result_unbinding==true){
            System.out.println("unbinding successfully");
        }

        long ca_unbind_1 = System.nanoTime();
        ca_unbind = ca_unbind_1-ca_unbind_0;


    }
}
