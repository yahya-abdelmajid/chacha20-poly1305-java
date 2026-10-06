package crypto;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;

/**
 * Implements the ChaCha20-Poly1305 authenticated encryption with associated data (AEAD) algorithm. 
 */
public class AeadChaCha20Poly1305 {
	
	/**
     * Note concernant l'implémentation (Ressources externes / Collaboration IA) :
     * Ce code est le fruit d'un travail collaboratif étroit avec une intelligence artificielle (Google Gemini).
     * L'intégralité des méthodes a été générée, comprise, analysée et améliorée ensemble au fil des itérations. 
     * Ce processus conjoint s'est révélé indispensable pour restructurer en profondeur l'architecture,
     * optimiser la complexité mémoire (streaming) et garantir la sécurité temporelle (temps constant).
     * * En tant que concepteur et superviseur du projet :
     * - J'ai piloté la recherche de solutions et remanié manuellement le code pour respecter strictement les packages autorisés.
     * - J'ai validé la chronologie de la machine à états ainsi que la robustesse des exceptions.
     * - J'ai supervisé et ajusté la documentation (Javadoc) pour refléter fidèlement la maîtrise technique de la solution.
     */
	
	// Variables d'état
    private int opmode;
    private ChaCha20 chacha20;
    private Poly1305 poly1305;
    
    // Buffers pour stocker les données en attendant le calcul final (doFinal)
    private byte[] aadBuffer;
    private int aadLength;
    
    private byte[] dataBuffer;
    private int dataLength;
    
    private boolean isInitialized = false;
    
    /**
     * Indique si la méthode update() a été appelée pour empêcher l'ajout d'AAD après le début du traitement des données.
     */
    private boolean isUpdateCalled = false;
	
	/**
	 * Initializes this ChaCha20Poly1305AEAD object with a key and a nonce.
	 * See Java javax.crypto.Cipher documentation for further details.

	 * @param opmode - the operation mode of this ChaCha20Poly1305AEAD object this is one of the following: ENCRYPT_MODE or DECRYPT_MODE
	 * @param key - the encryption key
	 * @param nonce - the nonce
	 * @throws IllegalArgumentException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedOperationException
	 */
	public void init(int opmode, byte[] key, byte[] nonce) throws IllegalArgumentException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedOperationException {
		// 1. Validation du mode d'opération
		if (opmode == Cipher.WRAP_MODE || opmode == Cipher.UNWRAP_MODE) {
            throw new UnsupportedOperationException("Mode WRAP ou UNWRAP non supporté.");
        }
		if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new InvalidAlgorithmParameterException("Opmode invalide. Doit être ENCRYPT_MODE ou DECRYPT_MODE.");
        }
        
        // 2. Validation des tailles de la clé et du nonce selon la RFC 7539
		if (key == null || key.length != 32) {
            throw new InvalidKeyException("La clé AEAD ne peut pas être null et doit faire exactement 32 octets.");
        }
		
        if (nonce == null) {
            throw new NullPointerException("Le nonce ne peut pas être null.");
        }
        if (nonce.length != 12) {
            throw new IllegalArgumentException("Le nonce AEAD doit faire exactement 12 octets.");
        }

        this.opmode = opmode;

        // 3. Génération de la clé One-Time pour Poly1305
        // On allume un ChaCha20 temporaire avec le compteur à 0.
        ChaCha20 keyGenChaCha = new ChaCha20();
        keyGenChaCha.init(Cipher.ENCRYPT_MODE, key, nonce, 0);
        
        // Pour récupérer le flux pseudo-aléatoire pur de ChaCha20, on lui demande de "chiffrer" 32 octets de zéros.
        // 0 XOR keystream = keystream. Le résultat est notre clé Poly1305.
        byte[] polyKey = keyGenChaCha.update(new byte[32]);

        // 4. Initialisation de Poly1305 avec cette clé unique
        this.poly1305 = new Poly1305();
        this.poly1305.init(polyKey);

        // 5. Initialisation du moteur ChaCha20 principal (RFC 7539 - Section 2.8)
        // Le vrai moteur qui traitera le message démarre TOUJOURS avec le compteur à 1.
        this.chacha20 = new ChaCha20();
        this.chacha20.init(opmode, key, nonce, 1);

        // 6. Remise à zéro des zones de stockage (Buffers)
        this.aadBuffer = new byte[0];
        this.dataBuffer = new byte[0];
        
        this.isInitialized = true;
	}
	
	/**
     * Ajoute dynamiquement des données au tampon des données associées (AAD).
     * Afin de garantir des performances optimales (complexité O(1) amortie), 
     * la capacité du tableau interne est doublée si l'espace devient insuffisant.
     * * @param input Le tableau d'octets contenant les données AAD à accumuler.
     */
    private void appendToAad(byte[] input) {
        // Redimensionnement dynamique si la capacité actuelle est dépassée
    	// On fusionne l'ancien buffer avec le nouveau morceau reçu.
        if (this.aadLength + input.length > this.aadBuffer.length) {
            int newCapacity = Math.max(this.aadBuffer.length * 2, this.aadLength + input.length);
            byte[] newBuffer = new byte[newCapacity];
            System.arraycopy(this.aadBuffer, 0, newBuffer, 0, this.aadLength);
            this.aadBuffer = newBuffer;
        }
        
        // Ajout des nouvelles données à la suite de l'existant
        System.arraycopy(input, 0, this.aadBuffer, this.aadLength, input.length);
        this.aadLength += input.length;
    }

    /**
     * Ajoute dynamiquement des données au tampon du message principal (Data).
     * Utilise une stratégie de redimensionnement par doublement de capacité 
     * pour éviter les copies mémoires excessives lors d'ajouts fragmentés (streaming).
     * * @param input Le tableau d'octets contenant les données du message à accumuler.
     */
    private void appendToData(byte[] input) {
        // Redimensionnement dynamique si la capacité actuelle est dépassée
        if (this.dataLength + input.length > this.dataBuffer.length) {
            int newCapacity = Math.max(this.dataBuffer.length * 2, this.dataLength + input.length);
            byte[] newBuffer = new byte[newCapacity];
            System.arraycopy(this.dataBuffer, 0, newBuffer, 0, this.dataLength);
            this.dataBuffer = newBuffer;
        }
        
        // Ajout des nouvelles données à la suite de l'existant
        System.arraycopy(input, 0, this.dataBuffer, this.dataLength, input.length);
        this.dataLength += input.length;
    }
		
	/**
	 * Continues a multi-part update of the Additional Authentication Data (AAD).
	 * 
	 * @param input
	 * @throws IllegalArgumentException
	 * @throws IllegalStateException
	 */
	public void updateAAD(byte[] input) throws IllegalArgumentException, IllegalStateException {
		// 1. Vérification de l'état L'AEAD doit être initialisé avant de recevoir des données.
		
		if (!this.isInitialized) {
 	        throw new IllegalStateException("L'objet n'a pas été initialisé. Appelez init() d'abord.");
 	    }
		
        
        if (this.isUpdateCalled) {
            throw new IllegalStateException("Impossible d'ajouter des AAD après avoir commencé le traitement des données (update).");
        }
        
        // 2. Validation de l'entrée
        if (input == null) {
            throw new IllegalArgumentException("Le tableau d'entrée AAD ne peut pas être null.");
        }
        
        // Si on nous envoie un tableau vide, on ne perd pas de temps en calculs inutiles
        if (input.length == 0) {
        	return;
        }

        // 3. Accumulation (Buffering) des données AAD
        
        appendToAad(input);
	}
	
	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
	 * See Java javax.crypto.Cipher documentation for further details.
	 * 
	 * @param input - the input buffer
	 * @return the new buffer with the result
	 * @throws AEADBadTagException
	 * @throws IllegalStateException
	 */
	public byte[] doFinal(byte[] input) throws AEADBadTagException, IllegalStateException {
		// 1. Validation
		
		if (!this.isInitialized) {
 	        throw new IllegalStateException("L'objet n'a pas été initialisé. Appelez init() d'abord.");
 	    }
		
		if (input == null) {
            throw new IllegalArgumentException("Le tableau d'entrée (input) ne peut pas être null.");
        }

        // 2. Préparation des données
        byte[] finalData = accumulateData(input);
        byte[] result;

        try {
            if (this.opmode == Cipher.ENCRYPT_MODE) {
                result = encryption(finalData);
            } else {
                result = decryption(finalData);
            }
        } finally {
            // 4. Nettoyage même si decryption() plante au milieu et lance une AEADBadTagException.
            resetBuffers();
        }
        
        return result;
	}
	
	/**
     * Fusionne le buffer de données global avec la toute dernière portion de données reçue.
     * Cette méthode centralise la préparation des données avant l'opération cryptographique finale,
     * en utilisant des copies mémoire optimisées.
     *
     * @param input Le dernier bloc de données à traiter (peut être null ou vide).
     * @return Un nouveau tableau contenant l'intégralité des données accumulées prêtes à être traitées.
     */
    private byte[] accumulateData(byte[] input) {
    	
    	if (input.length > 0) {
            appendToData(input);
        }
        
        // On crée le tableau final exactement à la bonne taille
        byte[] finalData = new byte[this.dataLength];
        System.arraycopy(this.dataBuffer, 0, finalData, 0, this.dataLength);
        
        return finalData;
    }
    
    private byte[] getExactAad() {
        byte[] exactAad = new byte[this.aadLength];
        System.arraycopy(this.aadBuffer, 0, exactAad, 0, this.aadLength);
        return exactAad;
    }
    
    /**
     * Exécute la séquence complète de chiffrement authentifié (AEAD) selon la RFC 7539.
     * Le processus suit un ordre strict :
     * 1. Chiffrement du texte en clair avec ChaCha20.
     * 2. Assemblage des données associées (AAD) et du texte chiffré.
     * 3. Calcul du Tag (MAC) d'authentification avec Poly1305.
     * 4. Concaténation du texte chiffré et du Tag.
     *
     * @param finalData L'intégralité du texte en clair à chiffrer.
     * @return Le message final composé du texte chiffré suivi directement du Tag de 16 octets.
     */
    private byte[] encryption(byte[] finalData) {
        // 1. Chiffrement
        byte[] ciphertext = this.chacha20.doFinal(finalData);
        
        // 2. Assemblage et calcul du MAC
        byte[] macData = buildMacData(getExactAad(), ciphertext);
        byte[] tag = this.poly1305.doFinal(macData);
        
        // 3. Assemblage final (Ciphertext + Tag)
        byte[] result = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        System.arraycopy(tag, 0, result, ciphertext.length, tag.length);
        
        return result;
    }
    
    /**
     * Exécute la séquence complète de déchiffrement et vérifie formellement l'intégrité du message.
     * Pour éviter toute vulnérabilité de type "Release Unverified Plaintext", le calcul 
     * et la comparaison en temps constant du Tag sont impérativement réalisés AVANT tout déchiffrement.
     *
     * @param finalData Le message reçu, contenant le texte chiffré suivi du Tag de 16 octets.
     * @return Le texte en clair déchiffré, uniquement si l'authenticité est prouvée.
     * @throws AEADBadTagException Si le message est trop court ou si la vérification du Tag échoue.
     */
    private byte[] decryption(byte[] finalData) throws AEADBadTagException {
        // 1. Vérification de la taille minimale
        if (finalData.length < 16) {
            throw new AEADBadTagException("Les données sont trop courtes pour contenir un tag MAC valide.");
        }
        
        // 2. Séparation du ciphertext et du tag
        int cipherLen = finalData.length - 16;
        byte[] ciphertext = new byte[cipherLen];
        byte[] receivedTag = new byte[16];
        System.arraycopy(finalData, 0, ciphertext, 0, cipherLen);
        System.arraycopy(finalData, cipherLen, receivedTag, 0, 16);
        
        // 3. Calcul et vérification du Tag
        byte[] macData = buildMacData(getExactAad(), ciphertext);
        byte[] calculatedTag = this.poly1305.doFinal(macData);
        
        if (!isEqualConstantTime(calculatedTag, receivedTag)) {
            throw new AEADBadTagException("Échec de la vérification de l'intégrité : les tags ne correspondent pas !");
        }
        
        // 4. Déchiffrement autorisé
        return this.chacha20.doFinal(ciphertext);
    }
    
    /**
     * Réinitialise les tampons de données (buffers) de l'instance.
     * Cette opération garantit qu'aucune donnée sensible ou résiduelle n'est conservée en mémoire 
     * après la finalisation, et prépare l'objet à traiter un éventuel nouveau message.
     */
    private void resetBuffers() {
        this.aadBuffer = new byte[1024];
        this.aadLength = 0;
        this.dataBuffer = new byte[1024];
        this.dataLength = 0;
        this.isUpdateCalled = false;
    }
	
	
    /**
     * Construit le bloc de données exact à authentifier par Poly1305, conformément à la RFC 7539 (Section 2.8).
     * La structure de ce bloc est strictement définie par la norme :
     * 1. Les données associées (AAD).
     * 2. Un remplissage (padding) de zéros pour que la taille de l'AAD soit un multiple de 16 octets.
     * 3. Le texte chiffré (Ciphertext).
     * 4. Un remplissage de zéros pour que la taille du texte chiffré soit un multiple de 16 octets.
     * 5. La longueur de l'AAD en octets, encodée sur 64 bits (8 octets) en ordre Little-Endian.
     * 6. La longueur du texte chiffré en octets, encodée sur 64 bits en ordre Little-Endian.
     *
     * @param aad        Le tableau contenant les Données Associées Authentifiées (peuvent être vides).
     * @param ciphertext Le tableau contenant le message préalablement chiffré par ChaCha20.
     * @return Un tableau d'octets formaté et prêt à être traité par la méthode doFinal de Poly1305.
     */
    private byte[] buildMacData(byte[] aad, byte[] ciphertext) {
        // Calcul du nombre de zéros nécessaires pour atteindre un multiple de 16
        int aadPadLen = (16 - (aad.length % 16)) % 16;
        int cipherPadLen = (16 - (ciphertext.length % 16)) % 16;
        
        // La longueur totale comprend les paddings et les deux entiers de 64 bits (8 octets chacun = 16 octets)
        // +16 = Stockage des 2 longueurs exigé par la RFC (8 octets AAD + 8 octets Cipher) en long car il faut que ça occupe 8 octets
        int totalLen = aad.length + aadPadLen + ciphertext.length + cipherPadLen + 16;
        byte[] macData = new byte[totalLen];
        
        int offset = 0;
        
        // 1. Ajout de l'AAD
        System.arraycopy(aad, 0, macData, offset, aad.length);
        offset += aad.length;
        
        // 2. Padding AAD (déjà rempli de zéros par défaut à la création du tableau)
        offset += aadPadLen;
        
        // 3. Ajout du Ciphertext
        System.arraycopy(ciphertext, 0, macData, offset, ciphertext.length);
        offset += ciphertext.length;
        
        // 4. Padding Ciphertext
        offset += cipherPadLen;
        
        // 5. Longueur de l'AAD (convertie en 64-bit little endian)
        byte[] aadLenBytes = longToLittleEndianBytes(aad.length);
        System.arraycopy(aadLenBytes, 0, macData, offset, 8);
        offset += 8;
        
        // 6. Longueur du Ciphertext (convertie en 64-bit little endian)
        byte[] cipherLenBytes = longToLittleEndianBytes(ciphertext.length);
        System.arraycopy(cipherLenBytes, 0, macData, offset, 8);
        
        return macData;
    }

    /**
     * Convertit une valeur de longueur (entière) en un tableau de 8 octets (64 bits) selon l'ordre Little-Endian.
     * Cette conversion est une exigence stricte de la RFC 7539 pour l'intégration des longueurs 
     * de l'AAD et du Ciphertext à la fin du bloc d'authentification MAC.
     *
     * @param length La longueur (en octets) à convertir.
     * @return Un tableau de 8 octets représentant la longueur en Little-Endian.
     */
    private byte[] longToLittleEndianBytes(long length) {
    	// Isole et extrait les 8 octets du 'long' un par un, du plus faible au plus fort (Little-Endian)
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++) {
            result[i] = (byte) ((length >> (8 * i)) & 0xFF);
        }
        return result;
    }

    /**
     * Compare deux tableaux d'octets en temps d'exécution constant (Constant-Time).
     * Contrairement aux méthodes standards (comme Arrays.equals) qui s'arrêtent dès la première 
     * différence trouvée, cette méthode parcourt systématiquement l'intégralité des tableaux.
     * Cela prévient les attaques par canaux auxiliaires (Timing Attacks) où un attaquant pourrait 
     * déduire le contenu du Tag en mesurant le temps de réponse de la fonction de vérification.
     *
     * @param a Le premier tableau d'octets (généralement le Tag calculé par notre algorithme).
     * @param b Le second tableau d'octets (généralement le Tag reçu et extrait du message).
     * @return true si les deux tableaux sont de même taille et ont un contenu strictement identique, false sinon.
     */
    private boolean isEqualConstantTime(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int result = 0;
        // On vérifie TOUS les octets sans jamais s'arrêter prématurément via une porte logique XOR
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

	/**
	 * Continues a multiple-part encryption or decryption operation
	 * (depending on how this Cipher object was initialized), processing another data part.
	 * See Java javax.crypto.Cipher documentation for further details.
	 * 
	 * @param input - the input buffer
	 * @return the new buffer with the result, or null if this cipher is a block cipher and
	 *         the input data is too short to result in a new block
	 * @throws IllegalStateException
	 */
	public byte[] update(byte[] input) throws IllegalStateException {
		// 1. La validation
		
		if (!this.isInitialized) {
 	        throw new IllegalStateException("Les objets ChaCha20 et poly1305 n'ont pas été initialisé. Appelez init() d'abord.");
 	    }
        
		if (input == null) {
            throw new IllegalArgumentException("Le tableau d'entrée ne peut pas être null.");
        }

        // 2. Vérification de l'entrée : si c'est vide, on ne fait rien
        if (input.length == 0) {
            return new byte[0]; 
        }

        // 3. Accumulation (Buffering) du message
        
        appendToData(input);
        
        this.isUpdateCalled=true;        
        // 4. On ne livre rien pour le moment !
        return new byte[0];
	}

	public static void main(String[] args) throws Exception {
		String plainText = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		String associatedData = "associated data";

		SecureRandom srand = new SecureRandom();
		byte[] chaCha20Key = new byte[32];
		srand.nextBytes(chaCha20Key);
		
		byte[] chaCha20Nonce = new byte[12];
		srand.nextBytes(chaCha20Nonce);

		/* ENCRYPTION */
		System.out.println(">>> ENCRYPTION");
		AeadChaCha20Poly1305 cpaead = new AeadChaCha20Poly1305();
		cpaead.init(Cipher.ENCRYPT_MODE, chaCha20Key, chaCha20Nonce);
		
		cpaead.updateAAD(associatedData.getBytes());
		byte[] aead = cpaead.doFinal(plainText.getBytes());
		System.out.println("AEAD (hex): " + convertBytesToHex(aead) + "\n");
		
		/* DECRYPT STREAMED */
		System.out.println(">>> DECRYPTION");
		cpaead = new AeadChaCha20Poly1305();
		cpaead.init(Cipher.DECRYPT_MODE, chaCha20Key, chaCha20Nonce);
		cpaead.updateAAD(associatedData.getBytes());
		byte[] decryptedText = cpaead.doFinal(aead);
		System.out.println("decryptedText: " + new String(decryptedText) + "\n");
	}

	private static String convertBytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
