# ChaCha20-Poly1305 en Java

Implémentation pédagogique du chiffrement authentifié **ChaCha20-Poly1305** (AEAD), écrite en Java 21 dans le cadre du cours de mathématiques (B2, HELMo).

> ⚠️ Projet à but éducatif : ne pas utiliser en production. Pour un usage réel, privilégiez les bibliothèques cryptographiques éprouvées.

## Objectif

Comprendre et implémenter de bout en bout un algorithme de chiffrement moderne, utilisé notamment dans TLS 1.3, WireGuard et SSH : chiffrer un message **et** garantir qu'il n'a pas été modifié.

## Contenu du projet

### Code (`src/crypto`)

| Classe | Rôle |
|---|---|
| `ChaCha20` | Chiffrement par flux ChaCha20 (génération du keystream à partir d'une clé de 256 bits, d'un nonce et d'un compteur) |
| `Poly1305` | Code d'authentification de message (MAC) Poly1305 |
| `AeadChaCha20Poly1305` | Combinaison des deux : chiffrement authentifié avec données associées (AEAD) |
| `StandardLibrariesDemo` | Démonstration et comparaison avec les bibliothèques standard de Java |

### Tests (`src/crypto.test`)

| Test | Ce qui est vérifié |
|---|---|
| `ChaCha20Test` | Exactitude du chiffrement ChaCha20 |
| `Poly1305Test` | Exactitude du calcul du MAC |
| `AeadChaCha20Poly1305Test` | Chiffrement / déchiffrement et détection de messages altérés |
| `AeadPerformanceTest` | Mesure des performances |
| `AeadStressTest` | Comportement sur un grand nombre d'entrées |

## Technologies

- Java 21
- JUnit
- Eclipse

## Lancer les tests

1. Cloner le dépôt :
   ```
   git clone https://github.com/yahya-abdelmajid/chacha20-poly1305-java.git
   ```
2. Importer le projet dans Eclipse : **File → Import → Existing Projects into Workspace**.
3. Clic droit sur le dossier `src/crypto.test` → **Run As → JUnit Test**.

## Ce que j'ai appris

- Le fonctionnement d'un chiffrement par flux et d'un MAC, et pourquoi on les combine.
- L'arithmétique modulaire sur de grands entiers (Poly1305 travaille modulo 2¹³⁰ − 5).
- L'importance des tests de référence pour valider une implémentation cryptographique.

## Référence

- [RFC 8439 : ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)

## Auteur

Yahya Abdelmajid, étudiant en informatique (B2, HELMo).
