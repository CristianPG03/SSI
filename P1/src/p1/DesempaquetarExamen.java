/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package p1;

import java.io.FileOutputStream;
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
import java.util.Arrays;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Dani
 */
public class DesempaquetarExamen {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException, SignatureException {
        // Anadir provider  (el provider por defecto no soporta RSA)
        Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        Paquete p = new Paquete();
        p.leerPaquete(args[0]);
        List<String> nombres = p.getNombresBloque();
        
        //Recuperamos las variables del paquete.
        byte[] examen = p.getContenidoBloque("examenCifrado");
        byte[] claveSecreta = p.getContenidoBloque("claveSecreta");
        byte[] firma = p.getContenidoBloque("firma");
       // byte[] fecha = p.getContenidoBloque(nombres.get(3));
       // byte[] sello = p.getContenidoBloque(nombres.get(4));

        // Crear cifrador RSA
        Cipher cifradorRSA = Cipher.getInstance("RSA", "BC");
        byte[] clavePublicaAlumno = Files.readAllBytes(Paths.get(args[2]));

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

        // Firma correcta¿?
        boolean coinciden = rsa.verify(firma);

        if (coinciden) {
            byte[] clavePrivadaProfesor = Files.readAllBytes(Paths.get(args[3]));

            // clave Privada que vamos a usar para descifrar con RSA.
            PKCS8EncodedKeySpec clavePrivadaSpec2 = new PKCS8EncodedKeySpec(clavePrivadaProfesor);
            PrivateKey clavePrivadaProfesor2 = keyFactoryRSA.generatePrivate(clavePrivadaSpec2);

            // Ponemos el cifrador en modo DESCIFRADO y obtenemos la KS que habiamos cifrado con RSA. 
            cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaProfesor2); // Descifra con la clave privada
            byte[] claveSecretaDes = cifradorRSA.doFinal(claveSecreta);

            //Des para obtener la KS original
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
            
            DESKeySpec DESspec = new DESKeySpec(claveSecretaDes);
            SecretKey claveSecretaDES2 = secretKeyFactoryDES.generateSecret(DESspec);
            
            //Desciframos el examen con la KS y DES
            cifradorDES.init(Cipher.DECRYPT_MODE, claveSecretaDES2); 
            byte[] examenDescifrado = cifradorDES.doFinal(examen);// Ciframos el examen con el cifrador.
            FileOutputStream out = new FileOutputStream(args[1]);
            out.write(examenDescifrado);
            
         } else {
            System.out.println("No coinciden...");
        }
    }
}
