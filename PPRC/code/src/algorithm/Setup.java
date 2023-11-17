package algorithm;

import entity.CA;
import entity.ServiceProvider;
import entity.SmartDevice;
import entity.User;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import javafx.beans.binding.Bindings;

import java.lang.instrument.Instrumentation;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;


public class Setup {
    //security Parameter

    public static int security_para=128;

    public static int number_SP = 30;
    public static int k=number_SP;


    public static TypeACurveGenerator pg=new TypeACurveGenerator(256,512);
    public static PairingParameters typeAParams = pg.generate();
    public static Pairing pairing = PairingFactory.getPairing(typeAParams);


    public static Element G_generator = pairing.getG1().newRandomElement().getImmutable();
    public static Element G_generator_1 = pairing.getG2().newRandomElement().getImmutable();
    public static Element zero = pairing.getZr().newElement(0).getImmutable();
    public static Element one = pairing.getZr().newElement(1).getImmutable();
    public static Element one_G = pairing.getG1().newElement(1).getImmutable();
    public static Element zero_point=pairing.getG1().newElement(0).getImmutable();

    public static MessageDigest messageDigest;

    static {
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    ;


    public static ServiceProvider[] serviceProviders= new ServiceProvider[k];
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
    public static float ca_setup = 0;

    public static void setup(){

        long ca_setup_0 = System.nanoTime();

        ca.CA_sk = new Element[k];
        ca.CA_sk_X = pairing.getZr().newRandomElement().getImmutable();
        ca.CA_pk_X = G_generator.powZn(ca.CA_sk_X);
        ca.CA_pk_Y_1 = new Element[k];
        ca.CA_pk_Y_2 = new Element[k];
        ca.CA_pk_Z = new Element[k][k];



        for (int kk=0;kk<number_SP;kk++){
            serviceProviders[kk] = new ServiceProvider();
            serviceProviders[kk].register_user_pk = zero;
        }

        // sk of Redactable Sig
        for (int i=0;i<k;i++){
            ca.CA_sk[i]=pairing.getZr().newRandomElement().getImmutable();
        }



        for (int j=0;j<k;j++){
            ca.CA_pk_Y_1[j]=G_generator.powZn(ca.CA_sk[j]);
        }

        for (int ii=0;ii<k;ii++){
            ca.CA_pk_Y_2[ii]=G_generator_1.powZn(ca.CA_sk[ii]);
        }

        for (int jj=0;jj<k;jj++){
            for (int ii=0;ii<k;ii++){
                if(ii!=jj){
                    ca.CA_pk_Z[jj][ii]=G_generator.
                            powZn(ca.CA_sk[jj].mul(ca.CA_sk[ii]));
                }
                else {
                    ca.CA_pk_Z[ii][ii]=zero_point;
                }
            }

        }

        long ca_setup_1 = System.nanoTime();
        ca_setup=ca_setup_1-ca_setup_0;



    }
}
