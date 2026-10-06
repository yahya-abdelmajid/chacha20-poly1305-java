package crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * Implements the ChaCha20 stream cipher algorithm. 
 */
public class ChaCha20 {
	
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
	
	// Constantes de taille selon la RFC 8439
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int NONCE_SIZE = 12; // 96 bits

    // État de l'algorithme
    private boolean isInitialized = false;
    
    //La clé
    private byte[] key;
    
    /** Le nonce (Number used once) est un sel unique de 12 octets.
     * Il garantit que le même message, chiffré deux fois, produira des résultats différents.
     * NE JAMAIS réutiliser le même nonce avec la même clé.
     */
    private byte[] nonce;

    /** La valeur de départ du compteur (généralement 0).
     * Elle définit le point d'entrée dans la suite de nombres aléatoires.
     */
    private int initialCounter;

    /** Le compteur de bloc actuel. 
     * Il s'incrémente de 1 après chaque bloc de 64 octets généré 
     * pour garantir que chaque segment du message est chiffré différemment.
     */
    private int currentCounter;
    
    // Le bloc de 64 octets généré par l'algorithme ChaCha20
    private byte[] keyStreamBuffer = new byte[64]; 

    // L'index actuel dans ce buffer (initialisé à 64 pour forcer la génération du premier bloc dès le premier octet reçu)
    private int keyStreamIndex = 64;
	
	/**
	 * Initializes this ChaCha20 object with a key, nonce and counter.
	 * See Java javax.crypto.Cipher documentation for further details.
	 * 
	 * @param opmode - the operation mode of this ChaCha20 object this is one of the following: ENCRYPT_MODE or DECRYPT_MODE
	 * @param key - the encryption key
	 * @param nonce - the nonce
	 * @param counter - the initial counter value
	 * @throws IllegalArgumentException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedOperationException
	 */
    public void init(int opmode, byte[] key, byte[] nonce, int counter)
    		throws IllegalArgumentException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedOperationException {
		
    	//Initialisation des variables
    	if (opmode == Cipher.WRAP_MODE || opmode == Cipher.UNWRAP_MODE) {
            throw new UnsupportedOperationException("Mode WRAP ou UNWRAP non supporté.");
        }
		
		// 1. Validation de l'opmode
    	if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
	        throw new InvalidAlgorithmParameterException("Opmode invalide. Doit être ENCRYPT_MODE ou DECRYPT_MODE.");
	    }
	    
	    // 2. Validation de la clé
	    if (key == null || key.length != KEY_SIZE) {
	        throw new InvalidKeyException("La clé ChaCha20 doit faire exactement 32 octets.");
	    }
	    
	    if (nonce == null) {
            throw new NullPointerException("Le nonce ne peut pas être null.");
        }
	    
	    // 3. Validation du nonce
	    if (nonce.length != NONCE_SIZE) {
	        throw new IllegalArgumentException("Le nonce ChaCha20 doit faire exactement 12 octets.");
	    }
	    
	    if (counter < 0) {
	        throw new IllegalArgumentException("Le compteur initial ne peut pas être négatif.");
	    }

	    this.key = key.clone();
	    this.nonce = nonce.clone();
	    this.initialCounter = counter;
	    this.currentCounter = counter;
	    this.isInitialized = true;
	    
	    this.keyStreamIndex = 64;
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
	 * See Java javax.crypto.Cipher documentation for further details.
	 * 
	 * @param input - the input buffer
	 * @return the new buffer with the result
	 * @throws IllegalStateException
	 */
    public byte[] doFinal(byte[] input) throws IllegalStateException {
		
	 		// 1. Validation de l'initialisation
	 	    if (!this.isInitialized) {
	 	        throw new IllegalStateException("L'objet ChaCha20 n'a pas été initialisé. Appelez init() d'abord.");
	 	    }

	 		// 2. Le travail final (Chiffrement)
	 	    byte[] result = new byte[0];
	 	    
	 	    if (input == null) {
	            throw new IllegalArgumentException("Le tableau d'entrée (input) ne peut pas être null.");
	        }
	 	    
	 	    // La méthode update() va se charger de faire le XOR entre ce texte et le flux aléatoire.
	 	    if (input.length > 0) {
	 	        result = this.update(input); 
	 	    }

	 		// 3. Le grand nettoyage (Remise à zéro) Machine dans son état de départ.
	 	    
	 	    // a. On remet le compteur à sa valeur initiale (notre point de sauvegarde).
	 	    this.currentCounter = this.initialCounter;
	 	    
	 	    // b. Notre réservoir de flux fait 64 octets. Si on n'a utilisé que 5 octets, on jette le reste !
	 	    // En forçant le curseur à 64 (qui est hors-limite), on force l'algorithme à fabriquer 
	 	    // un tout nouveau bloc de 64 octets lorsqu'on chiffrera le prochain message.
	 	    this.keyStreamIndex = 64; 

	 		// 4. La livraison, On renvoie le résultat final.
	 	    return result;
		
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
		
		//Continue une opération de chiffrement ou de déchiffrement en plusieurs parties

 		// 1. Validation de l'initialisation
 	    if (!this.isInitialized) {
 	        throw new IllegalStateException("L'objet ChaCha20 n'a pas été initialisé. Appelez init() d'abord.");
 	    }
 	    
 	   if (input == null) {
           throw new IllegalArgumentException("Le tableau d'entrée ne peut pas être null.");
       }

 	    //Message vide, on ne fait rien
 	    if (input.length == 0) {
 	        return new byte[0]; 
 	    }

 		// 2. Préparation de la boîte de livraison le texte chiffré fera EXACTEMENT la même taille que le texte en clair pas besoin de padding
 	    byte[] output = new byte[input.length];

 		// 3. Le travail à la chaîne (La boucle), on prend chaque lettre (octet) du message, une par une.
 	    for (int i = 0; i < input.length; i++) {
 	        
 	        // a. Vérification du Le réservoir de 64 octets
 	        // L'index a atteint 64, on arrête la chaîne de montage 
 	        if (this.keyStreamIndex >= 64) {
 	            this.generateNextKeyStreamBlock(); // Fabrique un nouveau bloc pseudo-aléatoire
 	            this.keyStreamIndex = 0; // On remet notre index au début
 	        }

 	        // b. L'opération XOR
 	        // 1 octet du message (input[i]) XOR 1 élement de notre buffer (keyStreamBuffer[keyStreamIndex]).
 	        output[i] = (byte) (input[i] ^ this.keyStreamBuffer[this.keyStreamIndex]);
 	        
 	        // c. On avance d'un cran Pour être sûr de ne jamais réutiliser la même donnée aléatoire pour la lettre suivante.
 	        this.keyStreamIndex++;
 	    }

 		// 4. L'expédition Toutes les lettres chiffrées et rangées dans la boîte.
 	    return output;
	}
	
	/**
     * Convertit 4 octets lus selon l'ordre Little-Endian en un entier 32 bits signé.
     * Cette méthode assemble les octets individuels en appliquant les décalages de bits 
     * nécessaires pour reconstruire l'entier tel qu'utilisé par l'algorithme ChaCha20.
     *
     * @param input  Le tableau d'octets contenant les données brutes.
     * @param offset L'index de départ dans le tableau pour lire les 4 octets.
     * @return L'entier 32 bits résultant de l'assemblage des 4 octets.
     */
    private int bytesToIntLE(byte[] input, int offset) {

        // 1. On extrait chaque octet et on le décale à sa place définitive
    	System.out.println(input[offset]);
    	
        int octet1 = (input[offset] & 0xFF);                  // Prend le 1er octet (poids le plus faible, reste à droite)
        int octet2 = (input[offset + 1] & 0xFF) << 8;         // Prend le 2ème octet et le pousse de 8 cases à gauche
        int octet3 = (input[offset + 2] & 0xFF) << 16;        // Prend le 3ème octet et le pousse de 16 cases à gauche
        int octet4 = (input[offset + 3] & 0xFF) << 24;        // Prend le 4ème octet et le pousse tout à gauche (poids fort)
        System.out.println(octet1+" "+octet2+" "+octet3+" "+octet4);
        System.out.println(octet1 | octet2 | octet3 | octet4);
        // 2. L'opérateur '|' (OU binaire) superpose ces 4 tranches pour former l'entier final.
        return octet1 | octet2 | octet3 | octet4;
    }

    /**
     * Convertit un entier 32 bits en 4 octets selon l'ordre Little-Endian.
     * Cette méthode décompose l'entier et place chaque octet dans le tableau de destination.
     *
     * @param value  L'entier 32 bits à convertir.
     * @param output Le tableau d'octets de destination.
     * @param offset L'index de départ dans le tableau de destination pour l'écriture des 4 octets.
     */
    private void intToBytesLE(int value, byte[] output, int offset) {
    	System.out.println();
    	// découpe pour isoler
        output[offset]     = (byte) (value & 0xFF);// le & permet d'isoler les 8 derniers bits car 0xFF 0000 0000 0000 0000 0000 0000 1111 1111
        System.out.println(output[offset]);
        output[offset + 1] = (byte) ((value >>> 8) & 0xFF);
        output[offset + 2] = (byte) ((value >>> 16) & 0xFF);
        output[offset + 3] = (byte) ((value >>> 24) & 0xFF);
        
        //opérateur moins gourmand en cpu plus rapide que interger
    }
	
    /**
     * Exécute l'opération de base "Quarter Round" sur quatre indices de l'état ChaCha20.
     * Cette fonction combine des additions modulaires, des rotations de bits et des 
     * opérations XOR selon les spécifications de la RFC 7539 (Section 2.1).
     * * @param state Le tableau d'entiers représentant la matrice d'état de 16 mots.
     * @param a     L'index du premier mot de l'état (souvent une constante ou un mot de clé).
     * @param b     L'index du deuxième mot de l'état (souvent un mot de clé).
     * @param c     L'index du troisième mot de l'état (souvent un mot de clé ou le compteur).
     * @param d     L'index du quatrième mot de l'état (souvent le compteur ou le nonce).
     */
    private void quarterRound(int[] state, int a, int b, int c, int d) {
    	
    	// avec Integer.rotateLeft(state[b] ^ state[c], 12); aucun bit n'est détruit
    	// RFC utilise des blocs de 32 bits non signé ne les prend pas en compte mais il existe
    	
        state[a] += state[b]; //addition a et b
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);
        //Conversion int en binaire
        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 12); // ^== XOR
        state[a] += state[b]; 
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);
        state[c] += state[d]; 
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
    }
    
    /**
     * Initialise la matrice d'état (state) de ChaCha20 selon la structure définie par la RFC 7539.
     * La matrice de 16 mots (32 bits chacun) est organisée comme suit :
     * - Les mots 0 à 3 : Constantes "magiques" (expand 32-byte k).
     * - Les mots 4 à 11 : La clé de 256 bits (8 mots)[cite: 348].
     * - Le mot 12 : Le compteur de bloc[cite: 349].
     * - Les mots 13 à 15 : Le nonce de 96 bits (3 mots)[cite: 350, 351].
     *
     * @return Un tableau de 16 entiers représentant l'état initial de l'algorithme.
     */
    private int[] initializeState(){
    	int[] state = new int[16];// convention structurelle imposée par la RFC
        
        // Constantes magiques imposée par la RFC
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        
        // La clé de 32 octets (8 entiers) mis à l'envers
        state[4] = bytesToIntLE(this.key, 0);
        System.out.println(state[4]);
        state[5] = bytesToIntLE(this.key, 4);
        state[6] = bytesToIntLE(this.key, 8);
        state[7] = bytesToIntLE(this.key, 12);
        state[8] = bytesToIntLE(this.key, 16);
        state[9] = bytesToIntLE(this.key, 20);
        state[10] = bytesToIntLE(this.key, 24);
        state[11] = bytesToIntLE(this.key, 28);
        
        //Convention structurelle imposée par la RFC la 12 réservé au compteur
        state[12] = this.currentCounter;
        
        // Le nonce de 12 octets (3 entiers) mis à l'envers
        state[13] = bytesToIntLE(this.nonce, 0);
        state[14] = bytesToIntLE(this.nonce, 4);
        state[15] = bytesToIntLE(this.nonce, 8);
        return state;
    }
    
    /**
     * Réalise le brassage de la matrice d'état en exécutant 20 rounds de calcul.
     * L'algorithme alterne entre 10 "column rounds" et 10 "diagonal rounds" pour 
     * assurer une diffusion maximale des bits de la clé et du nonce dans tout l'état.
     * Chaque itération de la boucle effectue 2 rounds (un de chaque type).
     * @param workingState La copie de travail de la matrice d'état (16 mots) à brasser.
     */
    private void shuffleState(int[] workingState) {
        for (int i = 0; i < 10; i++) {
            // Colonnes
            quarterRound(workingState, 0, 4, 8, 12);
            quarterRound(workingState, 1, 5, 9, 13);
            quarterRound(workingState, 2, 6, 10, 14);
            quarterRound(workingState, 3, 7, 11, 15);
            // Diagonales
            quarterRound(workingState, 0, 5, 10, 15);
            quarterRound(workingState, 1, 6, 11, 12);
            quarterRound(workingState, 2, 7, 8, 13);
            quarterRound(workingState, 3, 4, 9, 14);
        }
    }
    

    /**
     * Génère le prochain bloc de 64 octets de flux de clé (keystream).
     * Cette méthode implémente la fonction de bloc ChaCha20 telle que définie dans la RFC 7539 :
     * 1. Initialise la matrice d'état avec les constantes, la clé, le compteur et le nonce.
     * 2. Réalise le brassage de l'état via 20 rounds (10 itérations de doubles rounds).
     * 3. Effectue l'addition modulaire (2^32) entre l'état brassé et l'état initial.
     * 4. Sérialise le résultat en un tableau de 64 octets dans l'ordre Little-Endian.
     * 5. Incrémente le compteur de bloc pour garantir l'unicité du flux suivant.
     */
    private void generateNextKeyStreamBlock() {
    	
    	// Initialise la matrice d'état (state) de ChaCha20 selon la structure définie par la RFC 7539
        int[] state = initializeState();

        // Copie de travail pour les 20 tours
        int[] workingState = state.clone();

        // Les 20 tours (10 boucles de 2) colonnes et diagonales
        shuffleState(workingState);
        
        // Ce que vous regardez dans l'État Final, c'est votre "seau de peinture chiffrante" prêt à l'emploi.
        
        // Addition de l'état final et conversion en tableau d'octets (Keystream)
        for (int i = 0; i < 16; i++) {
            workingState[i] += state[i]; //addition classique
            intToBytesLE(workingState[i], this.keyStreamBuffer, i * 4);
        }

        // Incrémentation du compteur pour le prochain appel
        this.currentCounter++;
    }
	
	/**
	 * Illustration d'un chiffrement/déchiffrement en un seul morceau.
	 * ATTENTION : ce code est uniquement exemplatif de la séquence d'opérations!
	 */
	public static void main(String[] args) throws Exception {
		
		
		// Reprenons les 4 octets de notre exemple fétiche (454586665)
        // Une fois qu'ils ont été décalés à leur place respective :
        int octet1 = 41;          // Couloir 1 (Tout à droite)
        int octet2 = 28928;       // Couloir 2
        int octet3 = 1572864;     // Couloir 3
        int octet4 = 452984832;   // Couloir 4 (Tout à gauche)

        System.out.println("=== CAS 1 : LES COULOIRS SONT ISOLÉS (Ton code) ===");
        
        // 1. Calcul avec l'addition classique
        int resultatAddition = octet1 + octet2 + octet3 + octet4;
        
        // 2. Calcul avec le OU binaire (Superposition)
        int resultatOU = octet1 | octet2 | octet3 | octet4;

        System.out.println("Résultat avec ADDITION (+) : " + resultatAddition);
        System.out.println("Résultat avec OU BINAIRE (|) : " + resultatOU);
        System.out.println("Est-ce identique ? : " + (resultatAddition == resultatOU ? "OUI ! 🔥" : "NON"));
		
		String input = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

		SecureRandom srand = new SecureRandom();
		byte[] key = new byte[32];
		srand.nextBytes(key);
		System.out.println(convertBytesToHex(key));
		byte[] nonce = new byte[12];
		srand.nextBytes(nonce);
		
		System.out.println("\n---Encryption---");

		ChaCha20 cipher = new ChaCha20();
		cipher.init(Cipher.ENCRYPT_MODE, key, nonce, 1);
		byte[] cText = cipher.doFinal(input.getBytes());
		System.out.println("Encrypted : " + (cText != null ? convertBytesToHex(cText) : ""));
		
//		System.out.println("\n---Decryption---");
//		cipher.init(Cipher.DECRYPT_MODE, key, nonce, 1);
//		byte[] pText = cipher.doFinal(cText);
//		System.out.println("Plain Text : " + new String(pText));
	}

	/**
     * Convertit un tableau d'octets en sa représentation textuelle hexadécimale.
     * Cette méthode est principalement utilisée pour le débogage et l'affichage 
     * des résultats de chiffrement ou des Tags (MAC) de manière lisible.
     *
     * @param bytes Le tableau d'octets à convertir.
     * @return Une chaîne de caractères représentant les octets en format hexadécimal (2 caractères par octet).
     */
	private static String convertBytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
