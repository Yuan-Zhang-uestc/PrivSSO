package entity;

import it.unisa.dia.gas.jpbc.Element;

/**
 * @author emilio
 * @date 2023-05-29 16:47
 */
public class cert_acc_rg {
    public ServiceProvider serviceProvider; //16
    public CA ca; //16
    public String serial_1; //194
    public String validity_1; //78

    public Element hash_cert; //32

    public String inject; //352
    public Element hash_inject; //32

    public Element Sig; //128
}
