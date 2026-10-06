package crypto.test;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import crypto.AeadChaCha20Poly1305;
import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * Classe de tests unitaires pour AeadChaCha20Poly1305.
 * Utilise les vecteurs de test officiels de la RFC 7539 (Section 2.8.2).
 */
class AeadChaCha20Poly1305Test {
	//Test généré par Google Gemini

    // ==========================================
    // VECTEURS DE TEST OFFICIELS (RFC 7539)
    // ==========================================
    
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

    private final byte[] aad = new byte[] {
        (byte)0x50, (byte)0x51, (byte)0x52, (byte)0x53, (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
        (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7
    };

    private final String plainTextStr = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    
    // Le Tag attendu selon la RFC 7539
    private final String expectedTagHex = "1ae10b594f09e26a7e902ecbd0600691";

    @Test
    public void testEncryptionRFC7539() throws Exception {
        // Préparation
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        aead.init(Cipher.ENCRYPT_MODE, key, nonce);
        aead.updateAAD(aad);
        
        // Exécution
        byte[] cipherTextWithTag = aead.doFinal(plainTextStr.getBytes("UTF-8"));
        
        // Vérification
        assertNotNull(cipherTextWithTag, "Le résultat du chiffrement ne doit pas être null");
        
        // Extraction du tag généré (les 16 derniers octets)
        byte[] generatedTag = new byte[16];
        System.arraycopy(cipherTextWithTag, cipherTextWithTag.length - 16, generatedTag, 0, 16);
        
        String generatedTagHex = convertBytesToHex(generatedTag);
        
        // Le test réussit si notre Tag est identique à celui du document de l'IETF
        assertEquals(expectedTagHex, generatedTagHex, "Le Tag généré ne correspond pas à la RFC 7539 !");
    }

    @Test
    public void testDecryptionRFC7539() throws Exception {
        // 1. On chiffre d'abord pour avoir une donnée valide
        AeadChaCha20Poly1305 encryptor = new AeadChaCha20Poly1305();
        encryptor.init(Cipher.ENCRYPT_MODE, key, nonce);
        encryptor.updateAAD(aad);
        byte[] cipherTextWithTag = encryptor.doFinal(plainTextStr.getBytes("UTF-8"));
        
        // 2. On teste le déchiffrement
        AeadChaCha20Poly1305 decryptor = new AeadChaCha20Poly1305();
        decryptor.init(Cipher.DECRYPT_MODE, key, nonce);
        decryptor.updateAAD(aad);
        
        byte[] decryptedBytes = decryptor.doFinal(cipherTextWithTag);
        String decryptedString = new String(decryptedBytes, "UTF-8");
        
        // Vérification
        assertEquals(plainTextStr, decryptedString, "Le texte déchiffré doit être identique au texte clair d'origine.");
    }

    @Test
    public void testDecryptionFailsWithBadTag() throws Exception {
        // 1. Création d'un message chiffré valide
        AeadChaCha20Poly1305 encryptor = new AeadChaCha20Poly1305();
        encryptor.init(Cipher.ENCRYPT_MODE, key, nonce);
        encryptor.updateAAD(aad);
        byte[] cipherTextWithTag = encryptor.doFinal(plainTextStr.getBytes("UTF-8"));
        
        // 2. CORRUPTION DU MESSAGE : On modifie intentionnellement un octet du tag
        cipherTextWithTag[cipherTextWithTag.length - 1] ^= 0x01;
        
        // 3. Tentative de déchiffrement du message corrompu
        AeadChaCha20Poly1305 decryptor = new AeadChaCha20Poly1305();
        decryptor.init(Cipher.DECRYPT_MODE, key, nonce);
        decryptor.updateAAD(aad);
        
        // L'appel à doFinal DOIT lever une AEADBadTagException
        assertThrows(AEADBadTagException.class, () -> {
            decryptor.doFinal(cipherTextWithTag);
        }, "Le système doit bloquer le déchiffrement si le Tag est corrompu (AEADBadTagException attendue).");
    }

    @Test
    public void testInitWithInvalidKeyThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        byte[] badKey = new byte[15]; // Trop court, doit faire 32 octets
        
        assertThrows(InvalidKeyException.class, () -> {
            aead.init(Cipher.ENCRYPT_MODE, badKey, nonce);
        }, "Une InvalidKeyException doit être levée si la clé n'est pas de 32 octets.");
    }

    @Test
    public void testInitWithInvalidNonceThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        byte[] badNonce = new byte[8]; // Trop court, doit faire 12 octets
        
        assertThrows(IllegalArgumentException.class, () -> {
            aead.init(Cipher.ENCRYPT_MODE, key, badNonce);
        }, "Une IllegalArgumentException doit être levée si le nonce n'est pas de 12 octets.");
    }
    
    @Test
    public void testStateResetAfterBadTag() throws Exception {
        // 1. Préparation d'un message valide
        AeadChaCha20Poly1305 encryptor = new AeadChaCha20Poly1305();
        encryptor.init(Cipher.ENCRYPT_MODE, key, nonce);
        encryptor.updateAAD(aad);
        byte[] validCipherText = encryptor.doFinal(plainTextStr.getBytes("UTF-8"));
        
        // 2. Création d'une copie corrompue
        byte[] corruptedCipherText = validCipherText.clone();
        corruptedCipherText[corruptedCipherText.length - 1] ^= 0x01; // On casse le tag
        
        // 3. Initialisation du déchiffreur
        AeadChaCha20Poly1305 decryptor = new AeadChaCha20Poly1305();
        decryptor.init(Cipher.DECRYPT_MODE, key, nonce);
        decryptor.updateAAD(aad);
        
        // 4. PREMIÈRE TENTATIVE (Le message corrompu)
        try {
            decryptor.doFinal(corruptedCipherText);
            fail("Aurait dû lancer AEADBadTagException");
        } catch (AEADBadTagException e) {
            // L'attaque est bloquée. C'est normal.
            // Mais est-ce que les buffers ont été vidés par le try-finally ?
        }
        
        // 5. DEUXIÈME TENTATIVE (Le message valide, avec le MÊME objet decryptor)
        // Si le try-finally n'a pas marché, les buffers contiennent encore les déchets 
        // de l'étape 4, et le déchiffrement d'un message pourtant valide va échouer !
        decryptor.updateAAD(aad);
        byte[] decryptedBytes = decryptor.doFinal(validCipherText);
        String decryptedString = new String(decryptedBytes, "UTF-8");
        
        // Vérification
        assertEquals(plainTextStr, decryptedString, "L'objet AEAD doit pouvoir déchiffrer un message valide juste après avoir bloqué une attaque (Le try-finally fonctionne).");
    }
    
    @Test
    public void testInitWithUnsupportedModeThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        // Le prof teste un mode valide en Java, mais interdit par ton implémentation
        assertThrows(UnsupportedOperationException.class, () -> {
            aead.init(Cipher.WRAP_MODE, key, nonce);
        }, "Le mode WRAP doit lever une UnsupportedOperationException.");
    }

    @Test
    public void testInitWithInvalidModeThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        // Le prof teste un chiffre au hasard pour le mode
        assertThrows(InvalidAlgorithmParameterException.class, () -> {
            aead.init(999, key, nonce);
        }, "Un mode inexistant doit lever une InvalidAlgorithmParameterException.");
    }

    @Test
    public void testInitWithNullKeyThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        // Le prof envoie une clé null
        assertThrows(InvalidKeyException.class, () -> {
            aead.init(Cipher.ENCRYPT_MODE, null, nonce);
        }, "Une clé null doit lever une InvalidKeyException.");
    }

    @Test
    public void testInitWithNullNonceThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        // Le prof envoie un nonce null
        assertThrows(NullPointerException.class, () -> {
            aead.init(Cipher.ENCRYPT_MODE, key, null);
        }, "Un nonce null doit lever une NullPointerException.");
    }
    
    //NULL
    
    @Test
    public void testDoFinalWithNullInputThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        try {
            aead.init(Cipher.ENCRYPT_MODE, key, nonce);
        } catch (Exception e) {
            fail("L'initialisation ne devrait pas échouer ici.");
        }
        
        assertThrows(IllegalArgumentException.class, () -> {
            aead.doFinal(null);
        }, "Passer null à doFinal doit lever une IllegalArgumentException.");
    }

    @Test
    public void testUpdateAADWithNullInputThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        try {
            aead.init(Cipher.ENCRYPT_MODE, key, nonce);
        } catch (Exception e) {
            fail("L'initialisation ne devrait pas échouer ici.");
        }
        
        // Le prof teste l'injection de null dans l'AAD
        assertThrows(IllegalArgumentException.class, () -> {
            aead.updateAAD(null);
        }, "Passer null à updateAAD doit lever une IllegalArgumentException.");
    }

    @Test
    public void testMethodCallsBeforeInitThrowIllegalStateException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        byte[] dummyData = new byte[]{0x01, 0x02};
        
        // Le prof essaie d'utiliser l'objet avant de l'avoir initialisé
        assertThrows(IllegalStateException.class, () -> {
            aead.doFinal(dummyData);
        }, "Appeler doFinal avant init doit lever une IllegalStateException.");
        
        assertThrows(IllegalStateException.class, () -> {
            aead.updateAAD(dummyData);
        }, "Appeler updateAAD avant init doit lever une IllegalStateException.");
    }
    
    //try-catch
    @Test
    public void testStateResetAfterBadTagAttack() throws Exception {
        // 1. Préparation d'un message valide
        AeadChaCha20Poly1305 encryptor = new AeadChaCha20Poly1305();
        encryptor.init(Cipher.ENCRYPT_MODE, key, nonce);
        encryptor.updateAAD(aad);
        byte[] validCipherText = encryptor.doFinal(plainTextStr.getBytes("UTF-8"));
        
        // 2. Création d'une copie corrompue (Attaque)
        byte[] corruptedCipherText = validCipherText.clone();
        corruptedCipherText[corruptedCipherText.length - 1] ^= 0x01; // On casse le tag
        
        // 3. Initialisation du déchiffreur
        AeadChaCha20Poly1305 decryptor = new AeadChaCha20Poly1305();
        decryptor.init(Cipher.DECRYPT_MODE, key, nonce);
        decryptor.updateAAD(aad);
        
        // 4. PREMIÈRE TENTATIVE (Le message corrompu)
        try {
            decryptor.doFinal(corruptedCipherText);
            fail("Le déchiffrement aurait dû être bloqué et lancer AEADBadTagException");
        } catch (AEADBadTagException e) {
            // C'est le comportement attendu. L'attaque est bloquée.
        }
        
        // 5. DEUXIÈME TENTATIVE (Le message valide, avec le MÊME objet decryptor)
        // C'est ici que l'on vérifie si ton "try-finally" a bien vidé la mémoire !
        decryptor.updateAAD(aad);
        byte[] decryptedBytes = decryptor.doFinal(validCipherText);
        String decryptedString = new String(decryptedBytes, "UTF-8");
        
        // Vérification
        assertEquals(plainTextStr, decryptedString, "L'objet AEAD doit pouvoir déchiffrer un message valide juste après avoir subi une attaque. Le try-finally fonctionne !");
    }
    
    @Test
    public void testDecryptionFailsWithTooShortMessage() {
        AeadChaCha20Poly1305 decryptor = new AeadChaCha20Poly1305();
        try {
            decryptor.init(Cipher.DECRYPT_MODE, key, nonce);
        } catch (Exception e) {
            fail("L'initialisation ne devrait pas échouer ici.");
        }
        
        // Un message de 5 octets ne peut pas contenir un Tag de 16 octets
        byte[] tooShortMessage = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        
        assertThrows(AEADBadTagException.class, () -> {
            decryptor.doFinal(tooShortMessage);
        }, "Un message de moins de 16 octets doit lever une AEADBadTagException en déchiffrement.");
    }
    
    @Test
    public void testUpdateWithNullInputThrowsException() {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        try {
            aead.init(Cipher.ENCRYPT_MODE, key, nonce);
        } catch (Exception e) {
            fail("L'initialisation ne devrait pas échouer ici.");
        }
        
        // Le prof teste l'injection de null dans update
        assertThrows(IllegalArgumentException.class, () -> {
            aead.update(null);
        }, "Passer null à update doit lever une IllegalArgumentException.");
    }
    
    //Test performance
    
    @Test
    public void testPerformance() throws Exception {
        AeadChaCha20Poly1305 aead = new AeadChaCha20Poly1305();
        
        // Initialisation bidon pour le test
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        aead.init(Cipher.ENCRYPT_MODE, key, nonce);
        
        System.out.println("Début du test d'efficacité (100 000 updates byte-par-byte)...");
        long startTime = System.currentTimeMillis();
        
        // On simule le prof qui envoie 1 seul octet à la fois, 100 000 fois
        byte[] unOctet = new byte[]{0x01};
        for (int i = 0; i < 100000; i++) {
            aead.update(unOctet);
        }
        
        long endTime = System.currentTimeMillis();
        System.out.println("Temps d'exécution : " + (endTime - startTime) + " millisecondes.");
    }

    /**
     * Méthode utilitaire pour convertir un tableau d'octets en chaîne hexadécimale (pour les assertions).
     */
    private String convertBytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
