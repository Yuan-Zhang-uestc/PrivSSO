package entity;


import algorithm.Setup;
import it.unisa.dia.gas.jpbc.Element;

import static algorithm.Setup.pairing;

/**
 * @author emilio
 * @date 2023-05-18 15:17
 */
public class SmartDevice {
    public Element TD_ID = pairing.getZr().newRandomElement().getImmutable();
    public Element td_sk = pairing.getZr().newRandomElement().getImmutable();
    public Element td_pk = Setup.G_generator.powZn(td_sk);

    public Element ss_ID = pairing.getZr().newRandomElement().getImmutable();
    public Element ss_sk = pairing.getZr().newRandomElement().getImmutable();
    public Element ss_pk = Setup.G_generator.powZn(ss_sk);
}
