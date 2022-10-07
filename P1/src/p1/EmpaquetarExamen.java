/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package p1;

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
public class EmpaquetarExamen {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException, SignatureException {
        // Anadir provider  (el provider por defecto no soporta RSA)
        Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        //Paso 1: Examen Cifrado.
        //Creamos KS
        byte[] examenClaro = Files.readAllBytes(Paths.get(args[0])); // Leemos el examen.
        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        generadorDES.init(56); // clave de 56 bits
        SecretKey clave = generadorDES.generateKey();// Generamos clave DES - KS

        /* Crear cifrador DES*/
        Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifradorDES.init(Cipher.ENCRYPT_MODE, clave);

        byte[] examenCifrado = cifradorDES.doFinal(examenClaro);// Ciframos el examen con el cifrador.

        Paquete p = new Paquete(); // Primera Flecha del Esquema.
        p.anadirBloque("examenCifrado", examenCifrado);

        // Paso 2: Clave Secreta. 
        // 2.1 Leemos la clave publica del profesor de linea de comandos.
        byte[] clavePublicaProfesor = Files.readAllBytes(Paths.get(args[2]));

        // 2.2 Crear KeyFactory usado para las transformaciones de claves*/
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC

        // 2.3 Nos generamos la clave Publica que vamos a cifrar con RSA.
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(clavePublicaProfesor);
        PublicKey clavePublicaProfesor2 = keyFactoryRSA.generatePublic(clavePublicaSpec);

        // 2.4 Crear cifrador RSA*/
        Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC   

        // 2.5  Ponemos el cifrador en modo CIFRADO 
        cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaProfesor2);  // Cifra con la clave publica

        byte[] claveSecreta = cifradorRSA.doFinal(clave.getEncoded());
        p.anadirBloque("claveSecreta", claveSecreta);

        // Paso 3: Firma
        // 3.1 Leemos la clave privada de alumno de linea de comandos.
        byte[] clavePrivadaAlumno = Files.readAllBytes(Paths.get(args[3]));

        // 3.2 Nos generamos la clave Privada que vamos a cifrar con RSA.
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(clavePrivadaAlumno);
        PrivateKey clavePrivadaAlumno2 = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

        // 3.3 Creamos signature
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(clavePrivadaAlumno2);

        //3.4 Lo alimentamos con los 2 valores que queremos firmar. IMPORTANTE mantener el orden.
        rsa.update(examenCifrado);
        rsa.update(claveSecreta);

        byte[] firma = rsa.sign();
        p.anadirBloque("firma", firma);

        p.escribirPaquete(args[1]);

    }
}
