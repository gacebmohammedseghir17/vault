# Référence des Commandes CLI de l'Agent ERDPS

**Version :** v0.1.0  
**Dernière Mise à Jour :** 30 septembre 2025  
**Cible :** Équipes SOC et Sécurité

---

## Référence Rapide

| Commande | Statut | Objectif | Utilisation |
|---------|--------|---------|-------------|
| `scan-enhanced` | ✅ | Analyse de fichiers améliorée | `.\erdps-agent.exe scan-enhanced [OPTIONS] <CHEMIN>` |
| `multi-scan` | ✅ | Détection multi-couches | `.\erdps-agent.exe multi-scan [OPTIONS] <CHEMIN>` |
| `list-rules` | ✅ | Gestion des règles YARA | `.\erdps-agent.exe list-rules [OPTIONS]` |
| `stats` | ✅ | Statistiques du moteur | `.\erdps-agent.exe stats [OPTIONS]` |
| `show-metrics` | ✅ | Métriques de performance | `.\erdps-agent.exe show-metrics [OPTIONS]` |
| `update-rules` | ✅ | Synchronisation des règles | `.\erdps-agent.exe update-rules [OPTIONS]` |
| `config-repo` | ✅ | Gestion des dépôts | `.\erdps-agent.exe config-repo <COMMANDE>` |
| `optimize-rules` | ✅ | Optimisation des performances | `.\erdps-agent.exe optimize-rules [OPTIONS]` |
| `ember-scan` | ✅ | Détection ML de malware | `.\erdps-agent.exe ember-scan --path <CHEMIN> --ember-model <MODÈLE>` |
| `correlate` | ✅ | Corrélation d'alertes | `.\erdps-agent.exe correlate --scan-result <RÉSULTAT>` |
| `score-threats` | ✅ | Notation ML des menaces | `.\erdps-agent.exe score-threats --model-path <MODÈLE> --input <ENTRÉE>` |
| `auto-response` | ✅ | Réponses automatisées | `.\erdps-agent.exe auto-response --response-policy <POLITIQUE>` |
| `validate-rules` | ⚠️ | Validation des règles | `.\erdps-agent.exe validate-rules [OPTIONS]` |
| `--dashboard` | ❌ | Tableau de bord web | `.\erdps-agent.exe --dashboard` |
| `--scan-file` | ⚠️ | Analyse directe de fichier | `.\erdps-agent.exe --scan-file <FICHIER>` |

**Légende :** ✅ Entièrement Fonctionnel | ⚠️ Partiellement Fonctionnel | ❌ Non-Fonctionnel

---

## Documentation Détaillée des Commandes

### 1. scan-enhanced - Analyse de Fichiers Améliorée

**Objectif :** Effectuer une analyse complète de fichiers basée sur YARA avec des options avancées.

**Syntaxe :**
```bash
.\erdps-agent.exe scan-enhanced [OPTIONS] <CHEMIN>
```

**Options :**
- `--performance-mode <MODE>` - Mode de performance d'analyse
  - Valeurs : `fast`, `balanced`, `thorough`
  - Défaut : `balanced`
- `--category <CATÉGORIE>` - Filtrer les règles par catégorie
- `--optimize-rules` - Activer l'optimisation des règles
- `--parallel` - Activer l'analyse parallèle
- `--output-format <FORMAT>` - Format de sortie
  - Valeurs : `table`, `json`
  - Défaut : `table`

**Exemples :**
```bash
# Analyse de fichier basique
.\erdps-agent.exe scan-enhanced .\test_file.txt

# Analyse rapide avec sortie JSON
.\erdps-agent.exe scan-enhanced --performance-mode fast --output-format json .\suspicious_file.exe

# Analyse approfondie avec optimisation des règles
.\erdps-agent.exe scan-enhanced --performance-mode thorough --optimize-rules .\malware_sample.bin
```

**Sortie :**
- Résultats d'analyse avec détails des correspondances
- Métriques de performance
- Statistiques de compilation des règles

---

### 2. multi-scan - Détection Multi-Couches

**Objectif :** Exécuter une analyse complète multi-couches à travers les couches fichier, mémoire, comportement et réseau.

**Syntaxe :**
```bash
.\erdps-agent.exe multi-scan [OPTIONS] <CHEMIN>
```

**Options :**
- `--risk-threshold <SEUIL>` - Seuil de score de risque (0.0-1.0)
  - Défaut : `0.5`
- `--output-format <FORMAT>` - Format de sortie
  - Valeurs : `table`, `json`
  - Défaut : `table`
- `--layers <COUCHES>` - Spécifier les couches de détection
  - Valeurs : `file`, `memory`, `behavior`, `network`
  - Défaut : Toutes les couches

**Exemples :**
```bash
# Analyse multi-couches complète
.\erdps-agent.exe multi-scan .\target_file.exe

# Analyse haute sensibilité
.\erdps-agent.exe multi-scan --risk-threshold 0.2 .\suspicious_process.exe

# Couches fichier et mémoire uniquement
.\erdps-agent.exe multi-scan --layers file,memory .\sample.bin
```

**Sortie :**
- Score de risque (0.0-1.0)
- Résultats spécifiques par couche
- Nombre de correspondances par couche
- Temps total d'analyse

---

### 3. list-rules - Gestion des Règles YARA

**Objectif :** Afficher et gérer les règles YARA dans la base de données.

**Syntaxe :**
```bash
.\erdps-agent.exe list-rules [OPTIONS]
```

**Options :**
- `--category <CATÉGORIE>` - Filtrer par catégorie de règle
- `--repository <DÉPÔT>` - Filtrer par dépôt
- `--output-format <FORMAT>` - Format de sortie
  - Valeurs : `table`, `json`, `csv`
  - Défaut : `table`
- `--detailed` - Afficher les informations détaillées des règles

**Exemples :**
```bash
# Lister toutes les règles
.\erdps-agent.exe list-rules

# Lister les règles par catégorie
.\erdps-agent.exe list-rules --category malware

# Sortie JSON détaillée
.\erdps-agent.exe list-rules --detailed --output-format json
```

**Sortie :**
- Noms et catégories des règles
- Informations sur les dépôts
- Statistiques des règles
- Statut de compilation

---

### 4. stats - Statistiques du Moteur

**Objectif :** Afficher les statistiques du moteur YARA et de la base de données.

**Syntaxe :**
```bash
.\erdps-agent.exe stats [OPTIONS]
```

**Options :**
- `--output-format <FORMAT>` - Format de sortie
  - Valeurs : `table`, `json`
  - Défaut : `table`
- `--detailed` - Afficher les statistiques détaillées

**Exemples :**
```bash
# Statistiques basiques
.\erdps-agent.exe stats

# Statistiques JSON détaillées
.\erdps-agent.exe stats --detailed --output-format json
```

**Sortie :**
- Nombre total de règles
- Règles valides/invalides
- Nombre de dépôts
- Taille de la base de données
- Statistiques de validation

---

### 5. show-metrics - Métriques de Performance

**Objectif :** Afficher les métriques de compilation et de performance des règles.

**Syntaxe :**
```bash
.\erdps-agent.exe show-metrics [OPTIONS]
```

**Options :**
- `--top <N>` - Afficher les N règles les plus lentes
  - Défaut : `10`
- `--output-format <FORMAT>` - Format de sortie
  - Valeurs : `table`, `json`
  - Défaut : `table`

**Exemples :**
```bash
# Afficher les 10 règles les plus lentes
.\erdps-agent.exe show-metrics

# Afficher le top 5 avec sortie JSON
.\erdps-agent.exe show-metrics --top 5 --output-format json
```

**Sortie :**
- Temps de compilation des règles
- Classements de performance
- Recommandations d'optimisation

---

### 6. update-rules - Synchronisation des Règles

**Objectif :** Synchroniser les règles YARA depuis les dépôts GitHub configurés.

**Syntaxe :**
```bash
.\erdps-agent.exe update-rules [OPTIONS]
```

**Options :**
- `--repository <DÉPÔT>` - Mettre à jour un dépôt spécifique
- `--force` - Forcer la mise à jour même si à jour
- `--validate` - Valider les règles après mise à jour

**Exemples :**
```bash
# Mettre à jour tous les dépôts
.\erdps-agent.exe update-rules

# Forcer la mise à jour d'un dépôt spécifique
.\erdps-agent.exe update-rules --repository malware-rules --force

# Mise à jour avec validation
.\erdps-agent.exe update-rules --validate
```

**Sortie :**
- Statut de mise à jour par dépôt
- Nouvelles règles ajoutées
- Résultats de validation

---

### 7. config-repo - Gestion des Dépôts

**Objectif :** Gérer les dépôts de règles YARA.

**Syntaxe :**
```bash
.\erdps-agent.exe config-repo <COMMANDE>
```

**Commandes :**
- `add <URL>` - Ajouter un nouveau dépôt
- `remove <NOM>` - Supprimer un dépôt
- `list` - Lister les dépôts configurés
- `enable <NOM>` - Activer un dépôt
- `disable <NOM>` - Désactiver un dépôt

**Exemples :**
```bash
# Ajouter un dépôt
.\erdps-agent.exe config-repo add https://github.com/example/yara-rules.git

# Lister les dépôts
.\erdps-agent.exe config-repo list

# Activer/désactiver un dépôt
.\erdps-agent.exe config-repo enable malware-rules
.\erdps-agent.exe config-repo disable test-rules
```

**Sortie :**
- Statut des dépôts
- Changements de configuration
- Résultats de validation

---

### 8. optimize-rules - Optimisation des Performances

**Objectif :** Optimiser les règles YARA pour les performances et la déduplication.

**Syntaxe :**
```bash
.\erdps-agent.exe optimize-rules [OPTIONS]
```

**Options :**
- `--performance-threshold <MS>` - Seuil de performance en millisecondes
  - Défaut : `100`
- `--dry-run` - Afficher le plan d'optimisation sans l'appliquer
- `--deduplicate` - Supprimer les règles dupliquées

**Exemples :**
```bash
# Optimisation basique
.\erdps-agent.exe optimize-rules

# Simulation avec seuil personnalisé
.\erdps-agent.exe optimize-rules --performance-threshold 50 --dry-run

# Optimisation complète avec déduplication
.\erdps-agent.exe optimize-rules --deduplicate
```

**Sortie :**
- Statistiques d'optimisation
- Améliorations de performance
- Résultats de déduplication

---

### 9. ember-scan - Détection ML de Malware

**Objectif :** Effectuer une détection de malware basée sur l'apprentissage automatique en utilisant les modèles EMBER.

**Syntaxe :**
```bash
.\erdps-agent.exe ember-scan --path <CHEMIN> --ember-model <MODÈLE>
```

**Options Requises :**
- `--path <CHEMIN>` - Fichier ou répertoire à analyser
- `--ember-model <MODÈLE>` - Chemin vers le fichier de modèle ONNX

**Options Facultatives :**
- `--threshold <SEUIL>` - Seuil de détection (0.0-1.0)
  - Défaut : `0.5`
- `--auto-response` - Activer la réponse automatisée

**Exemples :**
```bash
# Analyse EMBER basique
.\erdps-agent.exe ember-scan --path .\sample.exe --ember-model .\models\ember.onnx

# Analyse haute sensibilité avec réponse automatique
.\erdps-agent.exe ember-scan --path .\suspicious\ --ember-model .\models\ember.onnx --threshold 0.3 --auto-response
```

**Sortie :**
- Scores de prédiction ML
- Résultats de classification
- Détails d'extraction de caractéristiques

---

### 10. correlate - Corrélation d'Alertes

**Objectif :** Corréler les alertes de multiples couches de détection.

**Syntaxe :**
```bash
.\erdps-agent.exe correlate --scan-result <RÉSULTAT>
```

**Options Requises :**
- `--scan-result <RÉSULTAT>` - Chemin vers le fichier de résultat d'analyse (JSON)

**Options Facultatives :**
- `--correlation-threshold <SEUIL>` - Seuil de corrélation
- `--output-format <FORMAT>` - Format de sortie

**Exemples :**
```bash
# Corréler les résultats d'analyse
.\erdps-agent.exe correlate --scan-result .\results\multi_scan_output.json

# Seuil de corrélation personnalisé
.\erdps-agent.exe correlate --scan-result .\results\scan.json --correlation-threshold 0.7
```

**Sortie :**
- Alertes corrélées
- Scores de confiance
- Analyse des relations

---

### 11. score-threats - Notation ML des Menaces

**Objectif :** Noter les menaces en utilisant des modèles d'apprentissage automatique.

**Syntaxe :**
```bash
.\erdps-agent.exe score-threats --model-path <MODÈLE> --input <ENTRÉE>
```

**Options Requises :**
- `--model-path <MODÈLE>` - Chemin vers le fichier de modèle ML
- `--input <ENTRÉE>` - Fichier de données d'entrée (JSON)

**Options Facultatives :**
- `--feature-scaling` - Activer la mise à l'échelle des caractéristiques
- `--output-format <FORMAT>` - Format de sortie

**Exemples :**
```bash
# Notation basique des menaces
.\erdps-agent.exe score-threats --model-path .\models\threat_model.onnx --input .\data\features.json

# Avec mise à l'échelle des caractéristiques
.\erdps-agent.exe score-threats --model-path .\models\model.onnx --input .\data\input.json --feature-scaling
```

**Sortie :**
- Scores de menaces
- Classifications de risque
- Prédictions du modèle

---

### 12. auto-response - Réponse Automatisée

**Objectif :** Exécuter des politiques de réponse automatisées basées sur les résultats de détection.

**Syntaxe :**
```bash
.\erdps-agent.exe auto-response --response-policy <POLITIQUE>
```

**Options Requises :**
- `--response-policy <POLITIQUE>` - Chemin vers le fichier de politique de réponse

**Options Facultatives :**
- `--dry-run` - Afficher les actions sans les exécuter
- `--log-level <NIVEAU>` - Niveau de journalisation

**Exemples :**
```bash
# Exécuter une politique de réponse
.\erdps-agent.exe auto-response --response-policy .\policies\malware_response.json

# Mode simulation
.\erdps-agent.exe auto-response --response-policy .\policies\policy.json --dry-run
```

**Sortie :**
- Actions exécutées
- Conformité aux politiques
- Résultats de réponse

---

## Commandes Partiellement Fonctionnelles

### 13. validate-rules - Validation des Règles ⚠️

**Objectif :** Valider les règles YARA pour les erreurs de syntaxe et de compilation.

**Statut :** Partiellement fonctionnel - signale des échecs de validation sur les règles de test.

**Syntaxe :**
```bash
.\erdps-agent.exe validate-rules [OPTIONS]
```

**Problèmes Connus :**
- Échecs de validation sur les règles de test existantes
- Erreur : "Échec de l'ajout de la règle au compilateur"

**Action Recommandée :** Réviser la syntaxe des règles avant utilisation en production.

---

## Commandes Non-Fonctionnelles

### 14. --dashboard - Tableau de Bord Web ❌

**Objectif :** Lancer l'interface de tableau de bord web.

**Statut :** Non-fonctionnel en raison d'une erreur de configuration.

**Syntaxe :**
```bash
.\erdps-agent.exe --dashboard
```

**Erreur :** "Adresse de liaison du tableau de bord invalide : syntaxe d'adresse socket invalide"

**Correction Requise :** Réviser la configuration du tableau de bord dans config.toml

---

### 15. --scan-file - Analyse Directe de Fichier ⚠️

**Objectif :** Analyse directe de fichier via le service agent.

**Statut :** Nécessite un service agent en cours d'exécution.

**Syntaxe :**
```bash
.\erdps-agent.exe --scan-file <FICHIER>
```

**Erreur :** Connexion refusée au service agent (127.0.0.1:19091)

**Solution de Contournement :** Démarrer d'abord le service agent, puis utiliser cette commande.

---

## Options Globales

Toutes les commandes supportent ces options globales :

- `--help` - Afficher l'aide de la commande
- `--version` - Afficher les informations de version
- `--config <CONFIG>` - Spécifier le fichier de configuration
- `--verbose` - Activer la journalisation détaillée
- `--quiet` - Supprimer les sorties non-essentielles

---

## Fichiers de Configuration

### Configuration Principale
- **Fichier :** `config.toml`
- **Emplacement :** Répertoire racine de l'agent
- **Objectif :** Configuration principale de l'agent

### Dépôts de Règles
- **Fichier :** `repositories.json`
- **Emplacement :** Répertoire `config/`
- **Objectif :** Configuration des dépôts

### Politiques de Réponse
- **Répertoire :** `policies/`
- **Format :** JSON
- **Objectif :** Définitions de réponse automatisée

---

## Codes de Sortie

| Code | Signification |
|------|---------------|
| 0 | Succès |
| 1 | Erreur générale |
| 2 | Erreur de configuration |
| 3 | Erreur de validation |
| 4 | Erreur réseau |
| 5 | Erreur du système de fichiers |

---

## Meilleures Pratiques

### Pour les Opérations SOC :

1. **Mises à Jour Régulières des Règles :**
   ```bash
   .\erdps-agent.exe update-rules --validate
   ```

2. **Surveillance des Performances :**
   ```bash
   .\erdps-agent.exe show-metrics --top 20
   ```

3. **Analyse Multi-Couches :**
   ```bash
   .\erdps-agent.exe multi-scan --risk-threshold 0.3 <cible>
   ```

4. **Réponse Automatisée :**
   ```bash
   .\erdps-agent.exe auto-response --response-policy .\policies\soc_policy.json
   ```

### Pour la Réponse aux Incidents :

1. **Analyse Améliorée :**
   ```bash
   .\erdps-agent.exe scan-enhanced --performance-mode thorough --optimize-rules <preuve>
   ```

2. **Analyse ML :**
   ```bash
   .\erdps-agent.exe ember-scan --path <échantillon> --ember-model <modèle> --threshold 0.2
   ```

3. **Corrélation d'Alertes :**
   ```bash
   .\erdps-agent.exe correlate --scan-result <résultats.json>
   ```

---

## Dépannage

### Problèmes Courants :

1. **Aucune Règle Chargée :**
   - Configurer les dépôts : `config-repo add <url>`
   - Mettre à jour les règles : `update-rules`

2. **Tableau de Bord ne Démarre Pas :**
   - Vérifier les paramètres du tableau de bord dans config.toml
   - Vérifier la configuration de l'adresse de liaison

3. **Échecs de Validation :**
   - Réviser la syntaxe des règles
   - Vérifier la compatibilité du compilateur YARA

4. **Erreurs de Connexion :**
   - S'assurer que le service agent est en cours d'exécution
   - Vérifier la disponibilité des ports (19091, 19094)

---

*Fin de la Référence CLI*

**Version du Document :** v0.1.0  
**Dernière Mise à Jour :** 30 septembre 2025  
**Maintenu Par :** Équipe de Développement ERDPS