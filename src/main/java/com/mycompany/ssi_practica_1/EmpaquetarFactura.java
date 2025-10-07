package com.mycompany.ssi_practica_1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * EmpaquetarFactura
 *
 * Uso:
 *   mvn exec:java -Dexec.mainClass="com.mycompany.ssi_practica_1.EmpaquetarFactura" \
 *       -Dexec.args="<factura.json> <salida.paquete> <Empresa.privada> <Hacienda.publica>"
 *
 * Flujo (Empresa):
 *   1) Lee factura JSON como bytes
 *   2) Genera K (AES-128) + IV (12 bytes) y cifra con AES/GCM/NoPadding
 *   3) Envuelve K con la pública de Hacienda (RSA/ECB/PKCS1Padding)
 *   4) Firma (SHA256withRSA) el material aportado por Empresa
 *   5) Construye el Paquete con bloques normalizados y lo escribe a disco
 */
public class EmpaquetarFactura {

    // ========= Configuración =========
    private static final String AES_TRANSFORM = "AES/GCM/NoPadding";
    private static final int AES_KEY_BITS = 128;           // suficiente para la práctica
    private static final int GCM_TAG_BITS = 128;           // tamaño del tag de autenticación
    private static final int GCM_IV_BYTES = 12;            // 96 bits recomendado para GCM
    private static final String RSA_TRANSFORM = "RSA/ECB/PKCS1Padding";
    private static final String SIG_ALGO = "SHA256withRSA";

    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Uso: EmpaquetarFactura <factura.json> <paquete> <Empresa.privada> <Hacienda.publica>");
            System.exit(1);
        }

        final String facturaPath = args[0];
        final String paqueteOut = args[1];
        final String empresaPrivPath = args[2];
        final String haciendaPubPath = args[3];

        try {
            // 0) Provider BC
            Security.addProvider(new BouncyCastleProvider());

            // 1) Cargar factura
            byte[] facturaBytes = Files.readAllBytes(Path.of(facturaPath));

            // 2) Generar clave AES y IV
            KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
            kg.init(AES_KEY_BITS, SecureRandom.getInstanceStrong());
            SecretKey k = kg.generateKey();
            byte[] iv = new byte[GCM_IV_BYTES];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            // 3) Cifrar factura con AES/GCM
            Cipher aes = Cipher.getInstance(AES_TRANSFORM, "BC");
            GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_BITS, iv);
            aes.init(Cipher.ENCRYPT_MODE, k, gcm);
            byte[] facturaCifrada = aes.doFinal(facturaBytes);

            // 4) Envolver K con pública de Hacienda (RSA)
            PublicKey pubHacienda = loadPublicKey(haciendaPubPath);
            Cipher rsa = Cipher.getInstance(RSA_TRANSFORM, "BC");
            rsa.init(Cipher.WRAP_MODE, pubHacienda);
            byte[] claveEnvuelta = rsa.wrap(k);

            // 5) Firmar con privada de Empresa (firma de ALGOS || IV || FACTURA_CIFRADA)
            PrivateKey privEmpresa = loadPrivateKey(empresaPrivPath);
            Signature sig = Signature.getInstance(SIG_ALGO, "BC");
            sig.initSign(privEmpresa);
            byte[] algosBytes = (AES_TRANSFORM + " | " + RSA_TRANSFORM).getBytes(StandardCharsets.UTF_8);
            sig.update(algosBytes);
            sig.update(iv);
            sig.update(facturaCifrada);
            byte[] firmaEmpresa = sig.sign();

            // 6) Construir paquete usando EXPLÍCITAMENTE la clase Paquete del enunciado
            Paquete p = new Paquete();
            p.anadirBloque("ALGOS", algosBytes);                 // nombres normalizados por Paquete
            p.anadirBloque("IV_O_NONCE", iv);
            p.anadirBloque("FACTURA_CIFRADA", facturaCifrada);
            p.anadirBloque("CLAVE_ENVUELTA", claveEnvuelta);
            p.anadirBloque("FIRMA_EMPRESA", firmaEmpresa);

            // 7) Escribir paquete
            p.escribirPaquete(paqueteOut);
            System.out.println("[OK] Factura empaquetada en: " + paqueteOut);

            // 8) (Opcional de depuración) Releer el paquete con la MISMA clase Paquete para listar los bloques
            Paquete comprobacion = new Paquete(paqueteOut);
            System.out.println("Bloques escritos en el paquete:");
            for (String nombre : comprobacion.getNombresBloque()) {
                byte[] cont = comprobacion.getContenidoBloque(nombre);
                System.out.println(" - " + nombre + " (" + (cont==null?0:cont.length) + " bytes)");
            }

        } catch (Exception e) {
            System.err.println("[ERROR] EmpaquetarFactura: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }

    // ========= Utilidades de carga de claves (PEM) =========

private static PublicKey loadPublicKey(String path) throws Exception {
    byte[] keyBytes = Files.readAllBytes(Path.of(path)); // lee binario
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
}

private static PrivateKey loadPrivateKey(String path) throws Exception {
    byte[] keyBytes = Files.readAllBytes(Path.of(path)); // lee binario
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
}


    /**
     * Convierte un PEM a DER eliminando cabeceras/rodapié y espacios.
     * Acepta: PUBLIC KEY / PRIVATE KEY
     */
    private static byte[] readPemStripHeaders(String pem) throws IOException {
        String s = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\s", "");
        return Base64.getDecoder().decode(s);
    }
}

