package tools;

import algorithm.Setup;
import it.unisa.dia.gas.jpbc.Element;


public class BLS {

    public static Element Signature(String plain, Element Sig_sk) throws Exception {

        Element Sig = Hash.hash(plain).powZn(Sig_sk);

        return Sig;


    }

    public static boolean Verify(Element Signature, Element Sig_pk, String plain) throws Exception {

        Element left = Setup.pairing.pairing(Signature,Setup.G_generator);
        Element right = Setup.pairing.pairing(Hash.hash(plain),Sig_pk);

        return left.isEqual(right);
    }

}
