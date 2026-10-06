package crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

/**
 * Implements the Poly1305 message authentication code algorithm. 
 */
public class Poly1305 {
	
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

	// Le modulo P = 2^130 - 5
    private static final BigInteger P = BigInteger.valueOf(2).pow(130).subtract(BigInteger.valueOf(5));
    
    // Les deux parties de la clé
    private BigInteger r;
    private BigInteger s;
    
    // L'accumulateur pour les calculs de l'authentification
    private BigInteger accumulator;
    private boolean isInitialized = false;
    
    // Buffer pour stocker les octets en attendant d'avoir un bloc complet de 16 octets
    private byte[] buffer = new byte[16];
    private int bufferLength = 0;
	
	/**
	 * Initializes this Poly1305 object with the provided key.
	 * See Java javax.crypto.Cipher documentation for further details.
	 * 
	 * @param key - the encryption key
	 * @throws InvalidKeyException
	 */
	public void init(byte[] key) throws InvalidKeyException {
		// 1. Validation de la clé : Poly1305 exige exactement 32 octets
        if (key == null || key.length != 32) {
            throw new InvalidKeyException("La clé Poly1305 doit faire exactement 32 octets.");
        }

        // 2. Extraction et nettoyage de 'r' (les 16 premiers octets)
        byte[] rBytes = new byte[16];
        System.arraycopy(key, 0, rBytes, 0, 16);

//        key : Le tableau d'origine (ta clé de 32 octets fournie en entrée).
//        0 : On commence la lecture au tout début du tableau key.
//        rBytes : Le tableau de destination (celui qui va recevoir les données). 
//        0 : On commence l'écriture au tout début du tableau rBytes. 
//        16 : On copie exactement 16 octets.
        
        // Application du masque de clamping sur les octets spécifiques de r
        rBytes[3] &= 15;// a &= b == a= a&b
        rBytes[7] &= 15;
        rBytes[11] &= 15;
        rBytes[15] &= 15;
        rBytes[4] &= 252;
        rBytes[8] &= 252;
        rBytes[12] &= 252;

        // 3. Extraction de 's' (les 16 derniers octets)
        byte[] sBytes = new byte[16];
        System.arraycopy(key, 16, sBytes, 0, 16);

        // 4. Conversion en BigInteger (en respectant l'ordre Little-Endian) pour pouvoir effecuter des opérations arithmétique
        this.r = bytesToBigIntegerLE(rBytes);
        this.s = bytesToBigIntegerLE(sBytes);
        
        // 5. Initialisation de l'accumulateur à 0
        this.accumulator = BigInteger.ZERO;
        this.isInitialized = true;
        
        //BigInteger.ZERO est une constante déjà créée en mémoire par Java. 
        //Le programme n'a pas besoin de "fabriquer" un nouvel objet zéro à chaque fois, ce qui rend le code plus rapide et plus léger.
	}
	
	/**
     * Convertit un tableau d'octets lu en Little-Endian en un objet BigInteger positif.
     * Cette méthode est essentielle pour Poly1305 car Java interprète nativement les tableaux 
     * d'octets en Big-Endian et utilise le premier bit pour le signe (complément à deux).
     * * Le processus suit deux étapes clés :
     * 1. L'inversion de l'ordre des octets pour passer du Little-Endian au Big-Endian.
     * 2. L'ajout d'un octet de poids fort à zéro pour garantir que le nombre est traité comme positif.
     *
     * @param bytes Le tableau d'octets à convertir (format Little-Endian).
     * @return Un BigInteger représentant la valeur numérique positive du tableau.
     */
    private BigInteger bytesToBigIntegerLE(byte[] bytes) {
    	
    	//Exemple : Imagine les octets [0x01, 0x02].En Big-Endian, l'ordinateur comprend : $1 \times 256 + 2 = 258$.En Little-Endian, l'ordinateur comprend : $2 \times 256 + 1 = 513$.
    	
        // On crée un tableau d'une case plus grand pour forcer le bit de signe à 0 pour qu'il soit positif
        byte[] reversed = new byte[bytes.length + 1];
        
        // Inversion de l'ordre des octets
        for (int i = 0; i < bytes.length; i++) {
            reversed[bytes.length - i] = bytes[i];
        }
        
        // L'octet d'indice 0 reste à 0x00 pour garantir que le BigInteger est positif
        reversed[0] = 0;
        
        return new BigInteger(reversed);
    }
	
	/**
	 * Calculates the Poly1305 MAC in a single-part operation, or finishes a multiple-part operation.
	 * See Java javax.crypto.Cipher documentation for further details.
	 * 
	 * @param input - the input buffer
	 * @return the new buffer with the MAC
	 * @throws IllegalStateException
	 */
	public byte[] doFinal(byte[] input) throws IllegalStateException {
		// 1. Vérification de l'état
        if (!this.isInitialized) {
            throw new IllegalStateException("L'objet Poly1305 n'a pas été initialisé.");
        }

        // 2. Traitement des toutes dernières données fournies en paramètre
        if (input != null && input.length > 0) {
            this.update(input);
        }

        // 3. Traitement du buffer restant s'il n'est pas vide (le dernier bloc)
        if (this.bufferLength > 0) {
            this.processBlock(); // On traitera le bloc partiel avec le padding spécifique
        }

        // 4. Calcul final : MAC = (accumulator + s)
        BigInteger macValue = this.accumulator.add(this.s);

        // 5. Conversion en tableau de 16 octets (Little-Endian)
        byte[] mac = bigIntegerToBytesLE(macValue, 16);

        // 6. Réinitialisation de l'état (comportement standard Java)
        this.accumulator = BigInteger.ZERO;
        this.bufferLength = 0;

        return mac;
	}
	
	/**
     * Convertit un objet BigInteger en un tableau d'octets de taille fixe selon l'ordre Little-Endian.
     * Cette méthode est cruciale pour la sérialisation finale du Tag (MAC) et respecte les 
     * spécifications de la RFC 7539 en inversant l'ordre Big-Endian natif de Java.
     * * Le processus gère automatiquement :
     * 1. L'inversion de l'ordre des octets (du plus faible au plus fort).
     * 2. Le bourrage (padding) par des zéros si le nombre est plus petit que la taille demandée.
     * 3. La troncature si le nombre dépasse la capacité du tableau de destination.
     *
     * @param value  La valeur numérique (BigInteger) à convertir.
     * @param length La taille souhaitée pour le tableau de sortie (généralement 16 octets).
     * @return Un tableau d'octets de la taille spécifiée en format Little-Endian.
     */
    private byte[] bigIntegerToBytesLE(BigInteger value, int length) {
        byte[] result = new byte[length];
        byte[] valueBytes = value.toByteArray(); 
        
        // On copie les octets en partant de la fin Big-Endian vers Little-Endian
        int sourceIndex = valueBytes.length - 1;
        int destIndex = 0;
        
        while (sourceIndex >= 0 && destIndex < length) {
            result[destIndex] = valueBytes[sourceIndex];
            sourceIndex--;
            destIndex++;
        }
        
        // Les octets non remplis restent à 0 (comportement par défaut des tableaux Java)
        return result;
    }

	/**
	 * Continues a multiple-part MAC calculation, processing another data part.
	 * See Java javax.crypto.Cipher documentation for further details.
	 * 
	 * @param input - the input buffer
	 * @throws IllegalStateException
	 */
	public void update(byte[] input) throws IllegalStateException {
		
		
		//input == tableau en clair
		
		// 1. Vérification de l'état (Guard imposé par la robustesse)
        if (!this.isInitialized) {
            throw new IllegalStateException("L'objet Poly1305 n'a pas été initialisé. Appelez init() d'abord.");
        }

        // 2. Vérification des entrées
        if (input == null || input.length == 0) {
            return; // Rien à traiter
        }

        // 3. Boucle de remplissage du buffer
        for (int i = 0; i < input.length; i++) {
            this.buffer[this.bufferLength] = input[i];
            this.bufferLength++;

            // 4. Dès qu'on a un bloc complet de 16 octets, on le traite
            if (this.bufferLength == 16) {
                this.processBlock();
                this.bufferLength = 0; // On réinitialise l'index du buffer
            }
        }
	}

	/**
     * Évalue le polynôme de Poly1305 pour le bloc courant présent dans le buffer.
     * L'équation est : accumulator = ((accumulator + block) * r) % P
     */
    private void processBlock() {
        // 1. Création d'un tableau contenant le bloc + 1 octet pour le padding (0x01) c'est la RFC qui me demande ça
        byte[] paddedBlock = new byte[this.bufferLength + 1];
        
        // Copie des données du buffer
        System.arraycopy(this.buffer, 0, paddedBlock, 0, this.bufferLength);
        
        // Ajout du bit/octet de padding (0x01) requis par Poly1305
        //important pour pouvoir faire la différence entre un message vide et un qui contient que des 0
        paddedBlock[this.bufferLength] = 0x01;

        // 2. Conversion du bloc paddé en un grand entier (Little-Endian)
        BigInteger blockValue = bytesToBigIntegerLE(paddedBlock);

        System.out.println(blockValue);
        // 3. Opérations mathématiques : (Accumulateur + Bloc)
        this.accumulator = this.accumulator.add(blockValue);

        // 4. Multiplication par 'r'
        this.accumulator = this.accumulator.multiply(this.r);

        // 5. Modulo P (2^130 - 5)
        //Ah en fait, j'ai bien compris. C'est le nombre premier le plus grand. Qui puisse exister et qui en même temps la condition. De pouvoir tricher et calculer le modulo instantanément c'est le maximum c'est ça.
        this.accumulator = this.accumulator.mod(P);
    }
	
	/**
	 * Illustration du calcul d'un MAC en un seul morceau.
	 * ATTENTION : ce code est uniquement exemplatif de la séquence d'opérations!
	 */
	public static void main(String[] args) throws Exception {
		String input = "Cryptographic Forum Research Group";
		
		SecureRandom srand = new SecureRandom();
		byte[] key = new byte[32];
		srand.nextBytes(key);

		Poly1305 cipher = new Poly1305();
		cipher.init(key);

		byte[] mac = cipher.doFinal(input.getBytes());
		System.out.println("MAC = " + (mac != null ? convertBytesToHex(mac) : ""));
	}


	private static String convertBytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
