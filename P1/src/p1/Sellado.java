/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package p1;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 *
 * @author Dani
 */
public class Sellado {
    public static void main(String[] args) throws Exception {
    /*
    PrivateKey clavePr;
    Files.readAllBytes(Paths.get(args[0]));
    
    PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
    PrivateKey clavePrivada2 = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

    if (clavePrivada.equals(clavePrivada2)) {
        	System.out.println("OK: clave privada guardada y recuperada");
    }
    clavePr = args[0];
    Signature dsa = Signature.getInstance("SHA256withDSA");
    dsa.initSign(clavePr);

   /* Update and sign the data
    dsa.update();
    
    byte[] sig = dsa.sign();
 */
    }
    
   
}
