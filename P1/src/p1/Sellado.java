/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package p1;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.time.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 *
 * @author Dani
 */
public class Sellado {
    public static void main(String[] args) throws Exception {
        // Anadir provider  (el provider por defecto no soporta RSA)
        Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        Paquete p = new Paquete();
        p.leerPaquete(args[0]);
        
        //Recuperamos las variables del paquete.
        byte[] examen = p.getContenidoBloque("examenCifrado");
        byte[] claveSecreta = p.getContenidoBloque("claveSecreta");
        byte[] firma = p.getContenidoBloque("firma");

        // Crear cifrador RSA
        //Cipher cifradorRSA = Cipher.getInstance("RSA", "BC");
        byte[] clavePublicaAlumno = Files.readAllBytes(Paths.get(args[1]));

        // Crear KeyFactory usado para las transformaciones de claves*/
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC

        // Nos generamos la clave Publica que vamos a descifrar.
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(clavePublicaAlumno);
        PublicKey clavePublicaAlumno2 = keyFactoryRSA.generatePublic(clavePublicaSpec);

        // Creamos signature
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(clavePublicaAlumno2);

        //Lo alimentamos con los 2 valores.
        rsa.update(examen);
        rsa.update(claveSecreta);

        // Firma correcta ¿?
        boolean coinciden = rsa.verify(firma);
        LocalDateTime ahora = LocalDateTime.now();
        
        byte [] fecha = ahora.toString().getBytes(); //new string(bytes)
        p.anadirBloque("fecha", fecha);
        
        if(coinciden){
            byte[] clavePrivadaAutoridad = Files.readAllBytes(Paths.get(args[2]));
            
             PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(clavePrivadaAutoridad);
             PrivateKey clavePrivadaAutoridad2 = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
             
             Signature rsa2 = Signature.getInstance("SHA256withRSA");
             rsa2.initSign(clavePrivadaAutoridad2);
             
             rsa2.update(examen);
             rsa2.update(claveSecreta);
             rsa2.update(firma);
             rsa2.update(fecha);
             
             byte [] sello = rsa2.sign();
             p.anadirBloque("sello", sello);
             p.escribirPaquete("paquete");
             
        } else {
            System.out.println("erroor...");
        }
        
       
    }
    
   
}
