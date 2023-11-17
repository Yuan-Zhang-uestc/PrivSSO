package entity;

import algorithm.Setup;
import it.unisa.dia.gas.jpbc.Element;

import static algorithm.Setup.pairing;


public class CA {

    public Element ca_sk_Sig = pairing.getZr().newRandomElement().getImmutable();
    public Element ca_pk_Sig = Setup.G_generator.powZn(ca_sk_Sig);

    public Element CA_sk_X;
    public Element[] CA_sk;


    public Element CA_pk_X;

    public Element[] CA_pk_Y_1;

    public Element[] CA_pk_Y_2;

    public Element[][] CA_pk_Z;


}
