/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package practicafirmadigital;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author mayteEcheverry
 */
public final class ParClaves {
    private KeyPairGenerator parkey;
    KeyPair kp;
    
    ParClaves(KeyPairGenerator kg) {
        parkey=kg;
        getParkey().initialize(2048);
        kp=getParkey().generateKeyPair();
    }
            
    public KeyPairGenerator getParkey() {
        return parkey;
    }
    
    //OBTENGO CLAVE PUBLICA Y PRIVADA A PARTIR DE KEYPAIRGENERATOR Y KEYPAIR / CONVIERTO LAS CLAVES EN BYTES PARA GUARDAR EN FICHERO
    public byte[] clavePublica(){  
        PublicKey kpu=kp.getPublic();
        return  kpu.getEncoded();   
    }
    
    public byte[] clavePrivada(){
        PrivateKey kpr=kp.getPrivate();
        return kpr.getEncoded();
    }
     
}
