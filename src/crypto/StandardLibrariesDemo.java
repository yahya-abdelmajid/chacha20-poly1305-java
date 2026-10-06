package crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.SecureRandom;

/**
 * Illustration de chiffrement/déchiffrement ChaCha20 et ChaCha20-Poly1305
 * avec les bibliothèques de Java.
 * ATTENTION : ce code est uniquement exemplatif de la séquence d'opérations!
 */
public class StandardLibrariesDemo {

	public static void demoChaCha20Only() throws Exception {
		String plainTextPart1 = "Ladies and Gentlemen of the class of '99: ";
		String plainTextLastPart = "If I could offer you only one tip for the future, sunscreen would be it.";
		System.out.println("Plain Text    : " + plainTextPart1 + plainTextLastPart);

		SecureRandom srand = new SecureRandom();
		byte[] key = new byte[32];
		srand.nextBytes(key);

		byte[] nonce = new byte[12];
		srand.nextBytes(nonce);

		int counter = 1;
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, counter);

		/*
		 * Encryption
		 */
		// Initialization
		Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), paramSpec);

        // Encrypt a multi-part plain text
		byte[] cTextPart1 = cipher.update(plainTextPart1.getBytes());
		// ... cipher.update(<next part>)
		byte[] cTextLastPart = cipher.doFinal(plainTextLastPart.getBytes());
		// Display concatenated encrypted cipher parts
		System.out.println("Cipher Text   : " + convertBytesToHex(cTextPart1) + convertBytesToHex(cTextLastPart));

		/*
		 * Decryption
		 */
		// Initialization
		Cipher decipher = Cipher.getInstance("ChaCha20");
        decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), paramSpec);
        
		// Decrypt multi-part encrypted text
		byte[] pTextPart1 = decipher.update(cTextPart1);
		// ... decipher.update(<next part>)
		byte[] pTextLastPart = decipher.doFinal(cTextLastPart);

		// Display concatenated decrypted text parts
		System.out.println("Decipher Text : " + new String(pTextPart1) + new String(pTextLastPart));
	}

	public static void demoChaCha20Poly1305() throws Exception {
		String plainTextPart1 = "Ladies and Gentlemen of the class of '99: ";
		String plainTextLastPart = "If I could offer you only one tip for the future, sunscreen would be it.";
		System.out.println("Plain Text    : " + plainTextPart1 + plainTextLastPart);

		byte[] aad = "authentication data".getBytes();

		SecureRandom srand = new SecureRandom();
		byte[] key = new byte[32];
		srand.nextBytes(key);

		byte[] nonce = new byte[12];
		srand.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        // Provide AAD in one or multiple parts
        cipher.updateAAD(aad);
        // ... cipher.updateAAD(<next part>)
        
		// Encrypt a multi-part plain text
		byte[] cTextPart1 = cipher.update(plainTextPart1.getBytes());
		// ... cipher.update(<next part>)
		byte[] cTextLastPart = cipher.doFinal(plainTextLastPart.getBytes());

		// Display concatenated encrypted cipher parts + MAC
		System.out.println("AEAD (hex)    : " + convertBytesToHex(cTextPart1) + convertBytesToHex(cTextLastPart));
		
		/*
		 * Decryption (including validation of MAC)
		 */
        Cipher decipher = Cipher.getInstance("ChaCha20-Poly1305");
        decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
        
        // Provide AAD in one or multiple parts
        decipher.updateAAD(aad);
        // ... cipher.updateAAD(<next part>)
        
		// Decrypt multi-part encrypted text
		byte[] pTextPart1 = decipher.update(cTextPart1);
		// ... decipher.update(<next part>)
		byte[] pTextLastPart = decipher.doFinal(cTextLastPart); // Throws javax.crypto.AEADBadTagException if MAC is incorrect

		// Display concatenated decrypted text parts
		System.out.println("Decipher Text : " + new String(pTextPart1) + new String(pTextLastPart));
	}
	
	public static void main(String[] args) throws Exception {
		// ChaCha20
		System.out.println(">>> Encrypt/decrypt ChaCha20 without authentification\n");
		demoChaCha20Only();
		System.out.println();

		// ChaCha20-Poly1305 AEAD
		System.out.println(">>> Encrypt/decrypt ChaCha20-Poly1305 AEAD\n");
		demoChaCha20Poly1305();
		System.out.println();
	}

	private static String convertBytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
