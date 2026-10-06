package crypto.test;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import crypto.ChaCha20;

public class ChaCha20Test {
	
	//Test généré par Google Gemini

    private ChaCha20 cipher;
    private byte[] validKey;
    private byte[] validNonce;

    @BeforeEach
    public void setUp() {
        cipher = new ChaCha20();
        validKey = new byte[32]; // Clé valide de 32 octets (remplie de 0)
        validNonce = new byte[12]; // Nonce valide de 12 octets (rempli de 0)
    }

    // --- 1. TESTS DE VALIDATION DES PARAMÈTRES (ROBUSTESSE) ---

    @Test
    public void testInit_InvalidOpmode_ThrowsIllegalArgumentException() {
        assertThrows(InvalidAlgorithmParameterException.class, () -> {
            cipher.init(99, validKey, validNonce, 1);
        }, "Un opmode invalide doit lever une IllegalArgumentException");
    }

    @Test
    public void testInit_InvalidKeyLength_ThrowsInvalidKeyException() {
        byte[] invalidKey = new byte[31]; // Trop courte
        assertThrows(InvalidKeyException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, invalidKey, validNonce, 1);
        }, "Une clé de 31 octets doit lever une InvalidKeyException");
    }

    @Test
    public void testInit_InvalidNonceLength_ThrowsInvalidAlgorithmParameterException() {
        byte[] invalidNonce = new byte[11]; // Trop court
        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, validKey, invalidNonce, 1);
        }, "Un nonce de 11 octets doit lever une InvalidAlgorithmParameterException");
    }

    // --- 2. TESTS D'ÉTAT (GUARDS) ---

    @Test
    public void testUpdate_BeforeInit_ThrowsIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> {
            cipher.update(new byte[]{1, 2, 3});
        }, "Appeler update avant init doit lever une IllegalStateException");
    }

    @Test
    public void testDoFinal_BeforeInit_ThrowsIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> {
            cipher.doFinal(new byte[]{1, 2, 3});
        }, "Appeler doFinal avant init doit lever une IllegalStateException");
    }

    // --- 3. TESTS DE COMPORTEMENT (NOMINAUX) ---

    @Test
    public void testUpdate_EmptyInput_ReturnsEmptyArray() throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, validKey, validNonce, 1);
        byte[] result = cipher.update(new byte[0]);
        assertEquals(0, result.length, "Un input vide doit renvoyer un tableau vide");
    }

    @Test
    public void testEncryptDecrypt_SinglePart_Success() throws Exception {
        String originalText = "Ceci est un test secret pour ChaCha20 !";
        byte[] plaintext = originalText.getBytes("UTF-8");

        // Chiffrement
        cipher.init(Cipher.ENCRYPT_MODE, validKey, validNonce, 1);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertNotEquals(originalText, new String(ciphertext), "Le texte chiffré doit être différent du clair");

        // Déchiffrement
        ChaCha20 decipher = new ChaCha20();
        decipher.init(Cipher.DECRYPT_MODE, validKey, validNonce, 1);
        byte[] decryptedText = decipher.doFinal(ciphertext);

        assertEquals(originalText, new String(decryptedText, "UTF-8"), "Le texte déchiffré doit correspondre au texte d'origine");
    }

 // --- 4. TEST DE RÉINITIALISATION DU COMPTEUR ---

    @Test
    public void testDoFinal_ResetsCounter() throws Exception {
        byte[] plaintext = "Message".getBytes("UTF-8");

        cipher.init(Cipher.ENCRYPT_MODE, validKey, validNonce, 1);
        
        // Premier chiffrement
        byte[] ciphertext1 = cipher.doFinal(plaintext);
        
        // Deuxième chiffrement (le compteur devrait avoir été réinitialisé par le premier doFinal)
        byte[] ciphertext2 = cipher.doFinal(plaintext);
        
        assertArrayEquals(ciphertext1, ciphertext2, "Deux appels successifs à doFinal avec la même entrée doivent produire la même sortie si le compteur est bien réinitialisé");
    }
}
