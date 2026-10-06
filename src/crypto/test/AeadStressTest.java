package crypto.test;

import org.junit.jupiter.api.Test;
import crypto.AeadChaCha20Poly1305;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Classe de tests extrêmes (Stress Tests) séparés pour évaluer la charge mémoire
 * et le temps d'exécution sur de gros volumes de données.
 */
class AeadStressTest {
	//Test généré par Google Gemini

    // Clés et nonces partagés pour tous les tests
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

    // =========================================================================
    // SCÉNARIO 1 : LE FICHIER DE 1 Mo (Envoyé octet par octet)
    // =========================================================================
    
    private final int ITERATIONS_1MO = 1_000_000;
    private final byte[] UN_OCTET = new byte[]{ 0x7F };

    @Test
    public void testStress1Mo_JavaNative() throws Exception {
        System.out.println("-> Lancement 1 Mo (Byte par Byte) : JAVA NATIVE");
        
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        long start = System.currentTimeMillis();
        
        for (int i = 0; i < ITERATIONS_1MO; i++) {
            javaCipher.update(UN_OCTET);
        }
        javaCipher.doFinal(new byte[0]);
        
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }

    @Test
    public void testStress1Mo_MonImplementation() throws Exception {
        System.out.println("-> Lancement 1 Mo (Byte par Byte) : MON CODE (Attention, risque d'attente longue !)");
        
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        long start = System.currentTimeMillis();
        
        for (int i = 0; i < ITERATIONS_1MO; i++) {
            customAead.update(UN_OCTET);
        }
        customAead.doFinal(new byte[0]);
        
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }

    // =========================================================================
    // SCÉNARIO 2 : LE RÉSEAU INSTABLE (5 Mo envoyés par paquets aléatoires)
    // =========================================================================

    private final int CIBLE_5MO = 5_000_000;

    @Test
    public void testStressReseauInstable_JavaNative() throws Exception {
        System.out.println("-> Lancement 5 Mo (Paquets Aléatoires) : JAVA NATIVE");
        
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        SecureRandom random = new SecureRandom();
        int totalBytesSent = 0;
        
        long start = System.currentTimeMillis();
        
        while (totalBytesSent < CIBLE_5MO) {
            int chunkSize = random.nextInt(8192) + 1; // Entre 1 et 8192 octets
            if (totalBytesSent + chunkSize > CIBLE_5MO) {
                chunkSize = CIBLE_5MO - totalBytesSent;
            }
            javaCipher.update(new byte[chunkSize]);
            totalBytesSent += chunkSize;
        }
        javaCipher.doFinal(new byte[0]);
        
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }

    @Test
    public void testStressReseauInstable_MonImplementation() throws Exception {
        System.out.println("-> Lancement 5 Mo (Paquets Aléatoires) : MON CODE");
        
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        SecureRandom random = new SecureRandom();
        int totalBytesSent = 0;
        
        long start = System.currentTimeMillis();
        
        while (totalBytesSent < CIBLE_5MO) {
            int chunkSize = random.nextInt(8192) + 1;
            if (totalBytesSent + chunkSize > CIBLE_5MO) {
                chunkSize = CIBLE_5MO - totalBytesSent;
            }
            customAead.update(new byte[chunkSize]);
            totalBytesSent += chunkSize;
        }
        customAead.doFinal(new byte[0]);
        
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }
    
 // =========================================================================
    // SCÉNARIO 3 : LE "ONE-SHOT" MASSIF (50 Mo en un seul bloc)
    // =========================================================================
    
    private final int TAILLE_50MO = 50_000_000;

    @Test
    public void testStressBlocMassif_JavaNative() throws Exception {
        System.out.println("-> Lancement Bloc Massif (50 Mo One-Shot) : JAVA NATIVE");
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        byte[] grosBloc = new byte[TAILLE_50MO]; 
        
        long start = System.currentTimeMillis();
        javaCipher.doFinal(grosBloc); // Tout en une seule fois
        long time = System.currentTimeMillis() - start;
        
        System.out.println("   Terminé en : " + time + " ms\n");
    }

    @Test
    public void testStressBlocMassif_MonImplementation() throws Exception {
        System.out.println("-> Lancement Bloc Massif (50 Mo One-Shot) : MON CODE");
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        byte[] grosBloc = new byte[TAILLE_50MO]; 
        
        long start = System.currentTimeMillis();
        customAead.doFinal(grosBloc); // Tout en une seule fois
        long time = System.currentTimeMillis() - start;
        
        System.out.println("   Terminé en : " + time + " ms\n");
    }
    
 // =========================================================================
    // SCÉNARIO 4 : LE MITRAILLAGE (100 000 chiffrements complets de petits messages)
    // =========================================================================
    
    private final int NB_MESSAGES = 100_000;
    private final byte[] PETIT_MESSAGE = "Message de test.".getBytes(); // 16 octets

    @Test
    public void testStressMitraillage_JavaNative() throws Exception {
        System.out.println("-> Lancement Mitraillage (100 000 messages complets) : JAVA NATIVE");
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        
        // On clone le nonce pour ne pas modifier l'original utilisé par les autres tests
        byte[] localNonce = nonce.clone(); 
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < NB_MESSAGES; i++) {
            
            // L'ASTUCE : On incrémente le premier octet du nonce pour qu'il soit unique à chaque tour
            localNonce[0]++; 
            
            javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(localNonce));
            javaCipher.doFinal(PETIT_MESSAGE);
        }
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }

    @Test
    public void testStressMitraillage_MonImplementation() throws Exception {
        System.out.println("-> Lancement Mitraillage (100 000 messages complets) : MON CODE");
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        
        byte[] localNonce = nonce.clone();
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < NB_MESSAGES; i++) {
            
            localNonce[0]++; // On fait la même chose ici pour que la comparaison soit parfaitement équitable
            
            customAead.init(Cipher.ENCRYPT_MODE, key, localNonce);
            customAead.doFinal(PETIT_MESSAGE);
        }
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }
    
 // =========================================================================
    // SCÉNARIO 5 : LE STRESS TEST AAD (10 Mo d'en-tête, octet par octet)
    // =========================================================================
    
    private final int ITERATIONS_AAD = 10_000_000;

    @Test
    public void testStressAAD_JavaNative() throws Exception {
        System.out.println("-> Lancement Stress Test AAD (10 Mo Byte-par-Byte) : JAVA NATIVE");
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < ITERATIONS_AAD; i++) {
            javaCipher.updateAAD(UN_OCTET);
        }
        javaCipher.doFinal(new byte[0]); // Message vide, seul l'AAD compte ici
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }

    @Test
    public void testStressAAD_MonImplementation() throws Exception {
        System.out.println("-> Lancement Stress Test AAD (10 Mo Byte-par-Byte) : MON CODE");
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < ITERATIONS_AAD; i++) {
            customAead.updateAAD(UN_OCTET);
        }
        customAead.doFinal(new byte[0]);
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }
    
 // =========================================================================
    // SCÉNARIO 6 : LA TEMPÊTE DE VIDE (10 Millions d'updates vides)
    // =========================================================================
    
    private final int ITERATIONS_VIDES = 10_000_000;
    private final byte[] TABLEAU_VIDE = new byte[0];

    @Test
    public void testStressVide_JavaNative() throws Exception {
        System.out.println("-> Lancement Tempête de Vide (10 Millions updates de 0 octet) : JAVA NATIVE");
        Cipher javaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        javaCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < ITERATIONS_VIDES; i++) {
            javaCipher.update(TABLEAU_VIDE);
        }
        javaCipher.doFinal(TABLEAU_VIDE);
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }

    @Test
    public void testStressVide_MonImplementation() throws Exception {
        System.out.println("-> Lancement Tempête de Vide (10 Millions updates de 0 octet) : MON CODE");
        AeadChaCha20Poly1305 customAead = new AeadChaCha20Poly1305();
        customAead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        long start = System.currentTimeMillis();
        for (int i = 0; i < ITERATIONS_VIDES; i++) {
            customAead.update(TABLEAU_VIDE);
        }
        customAead.doFinal(TABLEAU_VIDE);
        long time = System.currentTimeMillis() - start;
        System.out.println("   Terminé en : " + time + " ms\n");
    }
}