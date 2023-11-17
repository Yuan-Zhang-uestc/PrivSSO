package entity;

import it.unisa.dia.gas.jpbc.Element;

/**
 * @author emilio
 * @date 2023-06-05 18:41
 */
public class cert_ss_s {
    public ServiceProvider[] serviceProvider; //16*k
    public CA ca; //16*k
    public String serial_5; //194
    public String validity_5; //78

    public Element[] hash_cert;

    public String[] inject;
    public Element[] hash_inject;

    public Element[] Sig = new Element[4];
}
