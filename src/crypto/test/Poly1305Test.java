package crypto.test;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import crypto.Poly1305;

public class Poly1305Test {
	//Test généré par Google Gemini

    private Poly1305 macAlgorithm;
    private byte[] validKey;

    @BeforeEach
    public void setUp() {
        macAlgorithm = new Poly1305();
        // Une clé valide de 32 octets (remplie de 0 pour les tests basiques)
        validKey = new byte[32]; 
        new java.security.SecureRandom().nextBytes(validKey);
    }

    // --- 1. TESTS DE VALIDATION DES PARAMÈTRES (ROBUSTESSE) ---

    @Test
    public void testInit_InvalidKeyLength_ThrowsInvalidKeyException() {
        byte[] invalidKey = new byte[31]; // Trop courte
        assertThrows(InvalidKeyException.class, () -> {
            macAlgorithm.init(invalidKey);
        }, "Une clé de 31 octets doit lever une InvalidKeyException");
    }

    @Test
    public void testInit_NullKey_ThrowsInvalidKeyException() {
        assertThrows(InvalidKeyException.class, () -> {
            macAlgorithm.init(null);
        }, "Une clé nulle doit lever une InvalidKeyException");
    }

    // --- 2. TESTS D'ÉTAT (GUARDS) ---

    @Test
    public void testUpdate_BeforeInit_ThrowsIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> {
            macAlgorithm.update(new byte[]{1, 2, 3});
        }, "Appeler update avant init doit lever une IllegalStateException");
    }

    @Test
    public void testDoFinal_BeforeInit_ThrowsIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> {
            macAlgorithm.doFinal(new byte[]{1, 2, 3});
        }, "Appeler doFinal avant init doit lever une IllegalStateException");
    }

    // --- 3. TESTS DE COMPORTEMENT (NOMINAUX) ---

    @Test
    public void testDoFinal_ReturnsExactly16Bytes() throws Exception {
        macAlgorithm.init(validKey);
        byte[] mac = macAlgorithm.doFinal("Test message".getBytes("UTF-8"));
        
        assertNotNull(mac, "Le MAC ne doit pas être nul");
        assertEquals(16, mac.length, "Le MAC Poly1305 doit faire exactement 16 octets");
    }

    @Test
    public void testDoFinal_EmptyInput_HandlesGracefully() throws Exception {
        macAlgorithm.init(validKey);
        // On teste le cas où on ne passe rien ou un tableau vide
        byte[] mac = macAlgorithm.doFinal(new byte[0]);
        
        assertNotNull(mac);
        assertEquals(16, mac.length);
    }

    @Test
    public void testMac_IsDeterministic() throws Exception {
        // Pour une même clé et un même message, le MAC doit être strictement identique
        byte[] message = "Message secret pour Poly1305".getBytes("UTF-8");

        macAlgorithm.init(validKey);
        byte[] mac1 = macAlgorithm.doFinal(message);

        // On réinitialise et on recalcule
        macAlgorithm.init(validKey);
        byte[] mac2 = macAlgorithm.doFinal(message);

        assertArrayEquals(mac1, mac2, "Deux calculs avec les mêmes paramètres doivent donner le même MAC");
    }

    @Test
    public void testMac_DifferentMessages_ProduceDifferentMacs() throws Exception {
        macAlgorithm.init(validKey);
        byte[] mac1 = macAlgorithm.doFinal("Message A".getBytes("UTF-8"));

        macAlgorithm.init(validKey);
        byte[] mac2 = macAlgorithm.doFinal("Message B".getBytes("UTF-8"));

        // Il est mathématiquement hautement improbable d'avoir une collision sur deux petits messages
        assertFalse(java.util.Arrays.equals(mac1, mac2), "Deux messages différents doivent produire des MAC différents");
    }
}