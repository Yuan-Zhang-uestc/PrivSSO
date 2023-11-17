package entity;

import algorithm.Setup;
import it.unisa.dia.gas.jpbc.Element;
import tools.Hash;
import tools.HexToBytes;

import static algorithm.Setup.pairing;

/**
 * @author emilio
 * @date 2023-05-18 16:24
 */
public class User {
    public Element user_sk = pairing.getZr().newRandomElement().getImmutable();
    public Element user_pk = Setup.G_generator.powZn(user_sk);
    public Element user_ID = pairing.getZr().newRandomElement().getImmutable();
    public byte[] user_K = Hash.getSHA256(pairing.getZr().newRandomElement().getImmutable().toString());

    public User() throws Exception {
    }

    public Element[] user_ID_acc_s;
    public Element[] user_sk_acc_s;
    public Element[] user_pk_acc_s;

    //account_i
    public String[] account_i;
    //recover_i
    public String[] recover_i;
}
