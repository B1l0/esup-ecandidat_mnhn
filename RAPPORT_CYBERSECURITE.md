# Rapport d'Audit de Cybersécurité Complexe - Projet eCandidat (ESUP-Portail)

## 1. Résumé Exécutif

* **Nom du Projet** : eCandidat V2 (`fr.univlorraine:ecandidat`)
* **Version analysée** : `2.4.10-SNAPSHOT`
* **Technologies principales** : Java 11, Spring Framework 5.2.25.RELEASE, Spring Security 5.2.15.RELEASE, Vaadin 7.7.47, Maven, Hibernate / EclipseLink, MySQL / Oracle.
* **Niveau de Risque Global** : **ÉLEVÉ / CRITIQUE (Obsolescence applicative & configurations de sécurité)**

### Aperçu synthétique
L'audit de cybersécurité du projet **eCandidat** révèle une architecture logicielle reposant sur des frameworks majeurs ayant atteint leur fin de vie (End-Of-Life - EOL) ou nécessitant une mise à jour urgente vers des branches supportées. En particulier, la version de **Vaadin (7.7.47)** n'est plus maintenue, et **Spring Framework 5.2.x / Spring Security 5.2.x** ne reçoivent plus de correctifs de sécurité publics gratuits.

De plus, certaines configurations de sécurité au niveau de Spring Security (`SecurityConfig.java`) présentent des faiblesses notables (désactivation totale de la protection contre le Clickjacking via `frameOptions().disable()`, désactivation du `cacheControl()`, désactivation de `csrf()`).

---

## 2. Analyse de la Supply Chain & Dépendances (SCA)

### 2.1. Cartographie des composants majeurs

| Composant / Dépendance | Version Déclarée | Statut de Maintenance / Risque | Recommandation |
| :--- | :--- | :--- | :--- |
| **Java (JDK)** | `11` | Support étendu uniquement (EOL actif) | Migrer vers **Java 17 LTS** ou **Java 21 LTS** |
| **Spring Framework** | `5.2.25.RELEASE` | **EOL** (Support communautaire expiré) | Migrer vers **Spring 6.x** / **Spring Boot 3.x** |
| **Spring Security** | `5.2.15.RELEASE` | **EOL** | Migrer vers **Spring Security 6.x** |
| **Vaadin Framework** | `7.7.47` | **EOL Majeur** (obsolète depuis 2019) | Planifier la migration vers **Vaadin 24+** |
| **Flyway DB** | `4.2.0` | **Ancien** (version actuelle > 9.x) | Mettre à jour Flyway |
| **Apache Tika** | `2.9.1` | Récent / Maintenu | Conserver à jour |
| **Apache PDFBox** | `2.0.25` | Relativement récent | Mettre à jour vers 2.0.31+ / 3.x |
| **Logback / SLF4J** | `1.3.14` / `2.0.9` | Récent | Bon alignement |
| **MySQL Connector/J** | `8.4.0` | Récent | Bon alignement |

### 2.2. Risques liés aux dépendances EOL
1. **Vaadin 7.x** : Vaadin 7 est obsolète. De nombreuses vulnérabilités XSS ou de gestion d'état côté client/serveur ne sont plus corrigées dans la branche open-source 7.x.
2. **Spring 5.2.x / Security 5.2.x** : Des failles de contournement d'autorisation, de désérialisation ou de déni de service (DoS) découvertes ultérieurement ne sont plus corrigées dans cette version.

---

## 3. Analyse des Configurations de Sécurité (Spring Security & HTTP)

### 3.1. Analyse du fichier `SecurityConfig.java`

* **Clickjacking (`frameOptions().disable()`)** :
  - *Constat* : Les en-têtes `X-Frame-Options` et la directive CSP `frame-ancestors` sont désactivés pour permettre l'intégration en iframe.
  - *Risque* : Exposition à des attaques de Clickjacking si l'application est chargée dans un site tiers malveillant.
  - *Remédiation* : Utiliser `.sameOrigin()` au lieu de `.disable()`, ou restreindre via une politique Content-Security-Policy (CSP) explicite (`frame-ancestors 'self' https://domaines-autorises.fr`).

* **Gestion du Cache (`cacheControl().disable()`)** :
  - *Constat* : Désactivation du contrôle du cache navigateur.
  - *Risque* : Des pages contenant des données personnelles sensibles d'étudiants/candidats peuvent être enregistrées dans le cache local du navigateur ou sur des proxys intermédiaires.
  - *Remédiation* : Réactiver `cacheControl()` et ne désactiver sélectivement le cache que sur les endpoints spécifiques si un bug avec d'anciens navigateurs l'exige impérativement.

* **CSRF (`csrf().disable()`)** :
  - *Constat* : Désactivation du mécanisme CSRF de Spring Security.
  - *Analyse* : Vaadin gère la protection CSRF pour ses communications WebSocket / UI. Néanmoins, pour tout endpoint HTTP REST / Servlet exposé en dehors de l'UI Vaadin, l'absence de jeton CSRF présente un risque.

---

## 4. Analyse de la Cryptographie & Gestion des Authentifications

### 4.1. Hachage des Mots de Passe (`PasswordHashService`)
* **PBKDF2 (`PasswordHashServicePBKDF2.java`)** :
  - *Constat* : Utilisation de `PBKDF2WithHmacSHA1` avec **1 000 itérations** seulement (`PBKDF2_ITERATIONS = 1000`).
  - *Risque* : 1 000 itérations est une valeur très faible selon les standards OWASP / NIST actuels (qui recommandent au moins 600 000 itérations pour PBKDF2-HMAC-SHA256). Un attaquant disposant d'un dump de la base de données pourrait facilement casser les mots de passe par force brute/GPU.
  - *Remédiation* : Conserver BCrypt (avec un coût >= 12) ou Argon2id comme algorithme par défaut, et migrer de manière transparente les comptes utilisant encore le vieux hash PBKDF2 lors de leur prochaine connexion.

### 4.2. Génération de Mots de Passe Chiffrés
* *Point Positif* : L'utilisation de `java.security.SecureRandom` dans `PasswordHashService` garantit une génération de jetons/mots de passe temporaires cryptographiquement forte.

---

## 5. Analyse de la Sécurité des Fichiers & Téléversements (File Management)

### 5.1. Validation des Fichiers (`FileController.java`)
* **Détection du type MIME via Apache Tika** :
  - *Point Positif* : L'application vérifie le contenu réel des fichiers téléversés via la bibliothèque Apache Tika (`scanExtension`) et non uniquement l'extension soumise dans le nom de fichier.
  - *Attention* : La propriété `enableScanExtension` peut être désactivée dans la configuration (`enableScanExtension: false` dans `context.sample.xml`). Elle doit **impérativement être activée en production** (`true`).

### 5.2. Analyse Antivirus (ClamAV)
* *Point Positif* : Intégration native de ClamAV (`CustomClamAVClient`) pour analyser chaque fichier téléversé avant stockage.
* *Attention* : En cas d'indisponibilité ou de timeout du serveur ClamAV, s'assurer que le comportement par défaut (fail-open ou fail-close) est aligné avec la politique de sécurité de l'établissement.

---

## 6. Synthèse des Vulnérabilités & Matrice de Priorisation

| Ref | Vulnérabilité / Inconvénient | Sévérité | Effort | Action Recommandée |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Frameworks clés EOL (Vaadin 7, Spring 5.2) | **Critique** | Élevé | Établir un plan de migration vers Spring Boot 3 / Vaadin 24 |
| **SEC-02** | Configuration Spring Security permensive (`X-Frame-Options` & Cache désactivés) | **Moyenne** | Faible | Configurer `sameOrigin()` et réactiver `cacheControl()` dans `SecurityConfig` |
| **SEC-03** | Faible nombre d'itérations PBKDF2 (1000 itérations HMAC-SHA1) | **Élevée** | Moyen | Imposer BCrypt ou rehausser le coût d'itération |
| **SEC-04** | Risque de désactivation du contrôle Tika (`enableScanExtension=false`) | **Moyenne** | Faible | Forcer `enableScanExtension=true` par défaut dans la configuration de production |
| **SEC-05** | Mots de passe et secrets par défaut dans les fichiers d'exemple (`context.sample.xml`) | **Faible** | Faible | Documenter la stricte rotation des secrets et l'utilisation de coffres-forts de clés |

---

## 7. Recommandations & Feuille de Route de Remédiation

### 7.1. Court Terme (Sous 1 à 3 mois)
1. **Durcir `SecurityConfig.java`** :
   - Remplacer `.frameOptions().disable()` par `.frameOptions().sameOrigin()` ou ajouter une directive CSP `frame-ancestors`.
   - Réactiver le `cacheControl()` pour les ressources dynamiques.
2. **Forcer `enableScanExtension=true`** et s'assurer que ClamAV est toujours opérationnel en production.
3. **Mettre à niveau PBKDF2** ou forcer la migration de tous les comptes locaux vers BCrypt avec un facteur de coût adéquat.

### 7.2. Moyen / Long Terme (6 à 12 mois)
1. **Refonte / Upgrade de version majeure** :
   - Migrer du JDK 11 vers **Java 17 / 21 LTS**.
   - Migrer l'architecture Spring vers **Spring Boot 3.x / Spring Security 6.x**.
   - Planifier la refonte des vues Vaadin 7 vers une version moderne de Vaadin (Vaadin Flow 24+).
2. **Intégration CI/CD** :
   - Ajouter un scanner de dépendances automatique (ex: OWASP Dependency-Check, Trivy, Snyk) dans le pipeline `.gitlab-ci.yml`.

---
*Rapport généré par l'outil d'audit de cybersécurité automatique Jules.*
