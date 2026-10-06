package crypto.test;

import org.junit.jupiter.api.Test;
import crypto.AeadChaCha20Poly1305;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Classe de tests séparés pour évaluer la performance du streaming (byte-par-byte).
 */
class AeadPerformanceTest {
	//Test généré par Google Gemini

    // Clé et nonce fixes pour les tests de performance
    private final byte[] key = new byte[] {
        (byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87,
        (byte)0x88, (byte)0x89, (byte)0x8a, (byte)0x8b, (byte)0x8c, (byte)0x8d, (byte)0x8e, (byte)0x8f,
        (byte)0x90, (byte)0x91, (byte)0x92, (byte)0x93, (byte)0x94, (byte)0x95, (byte)0x96, (byte)0x97,
        (byte)0x98, (byte)0x99, (byte)0x9a, (byte)0x9b, (byte)0x9c, (byte)0x9d, (byte)0x9e, (byte)0x9f
    };

    private final byte[] nonce = new byte[] {
        (byte)0x07, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43,
        (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47
    };

    // Le nombre de fois qu'on va envoyer 1 octet (100 000 est un bon standard pour voir la différence)
    private final int ITERATIONS = 100000;
    private final byte[] UN_OCTET = new byte[]{ 0x42 }; // Un octet arbitraire

    @Test
    public void testPerformanceJavaNative() throws Exception {
        System.out.println("--- Début du test de performance : Java Native ---");
        
        // Initialisation de la librairie Java
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        // Démarrage du chrono
        long startTime = System.currentTimeMillis();
        
        // Boucle d'envoi byte par byte
        for (int i = 0; i < ITERATIONS; i++) {
            javaCipher.update(UN_OCTET);
        }
        javaCipher.doFinal(new byte[0]); // Finalisation
        
        // Arrêt du chrono
        long endTime = System.currentTimeMillis();
        long executionTime = endTime - startTime;
        
        System.out.println("Temps d'exécution Java Native : " + executionTime + " ms");
        System.out.println("--------------------------------------------------\n");
    }

    @Test
    public void testPerformanceMonImplementation() throws Exception {
        System.out.println("--- Début du test de performance : Mon Implémentation ---");
        
        // Initialisation de ton code
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        // Démarrage du chrono
        long startTime = System.currentTimeMillis();
        
        // Boucle d'envoi byte par byte
        for (int i = 0; i < ITERATIONS; i++) {
            customAead.update(UN_OCTET);
        }
        customAead.doFinal(new byte[0]); // Finalisation
        
        // Arrêt du chrono
        long endTime = System.currentTimeMillis();
        long executionTime = endTime - startTime;
        
        System.out.println("Temps d'exécution Mon Code : " + executionTime + " ms");
        System.out.println("--------------------------------------------------\n");
    }
    
    @Test
    public void testStressExtremeFichier1Mo() throws Exception {
        System.out.println("=== DEBUT DU STRESS TEST : 1 Mégaoctet (Byte par Byte) ===");
        
        int iterations = 1_000_000; // L'équivalent d'un fichier de 1 Mo
        byte[] unOctet = new byte[]{ 0x7F };
        
        // 1. JAVA NATIVE
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        System.out.print("En cours pour Java Native... ");
        long startJava = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            javaCipher.update(unOctet);
        }
        javaCipher.doFinal(new byte[0]);
        long timeJava = System.currentTimeMillis() - startJava;
        System.out.println("Terminé en " + timeJava + " ms");

        // 2. TON CODE (Prépare-toi à attendre !)
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        System.out.print("En cours pour ton code (ça peut prendre des minutes... patience !) -> ");
        long startCustom = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            customAead.update(unOctet); // C'est ici que l'ordinateur souffre
        }
        customAead.doFinal(new byte[0]);
        long timeCustom = System.currentTimeMillis() - startCustom;
        System.out.println("Terminé en " + timeCustom + " ms");
        
        System.out.println("==========================================================");
    }
    
    @Test
    public void testStressReseauInstable() throws Exception {
        System.out.println("=== DEBUT DU STRESS TEST : Réseau Instable (Chunks aléatoires) ===");
        
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        SecureRandom random = new SecureRandom();
        int totalBytesSent = 0;
        int targetBytes = 5_000_000; // On va simuler un fichier de 5 Mo
        
        long startCustom = System.currentTimeMillis();
        
        while (totalBytesSent < targetBytes) {
            // Le réseau envoie un paquet d'une taille aléatoire entre 1 et 8192 octets (8 Ko)
            int chunkSize = random.nextInt(8192) + 1;
            
            // On s'assure de ne pas dépasser la taille cible à la toute fin
            if (totalBytesSent + chunkSize > targetBytes) {
                chunkSize = targetBytes - totalBytesSent;
            }
            
            byte[] chunk = new byte[chunkSize];
            customAead.update(chunk); // Injection du paquet
            
            totalBytesSent += chunkSize;
        }
        
        customAead.doFinal(new byte[0]);
        long timeCustom = System.currentTimeMillis() - startCustom;
        
        System.out.println("5 Mo traités par paquets aléatoires en : " + timeCustom + " ms");
        System.out.println("==================================================================");
    }
}