# Contribuer à zrouga-spring-security

Merci de votre intérêt pour le projet ! Ce document décrit comment monter
l'environnement, exécuter les vérifications et proposer vos changements.

## Prérequis

- **JDK 21** (le projet cible Java 21, Spring Boot 4.1)
- **Maven Wrapper** inclus (`./mvnw`) : aucune installation Maven globale requise
- **Docker** : *optionnel* — le test PostgreSQL (Testcontainers) est automatiquement
  ignoré sans Docker (`@Testcontainers(disabledWithoutDocker = true)`) et tourne dans CI

## Démarrage

```bash
# Compilation + tests + couverture + japicmp (la commande de référence)
./mvnw verify          # Windows : mvnw.cmd verify

# Tests rapides uniquement
./mvnw test

# Installer la lib localement (requis pour construire les démos examples/)
./mvnw install
```

Seuils de couverture JaCoCo appliqués par le build : **≥ 80 % d'instructions** et
**≥ 55 % de branches**. Un build `verify` vert est requis avant tout commit.

Les démos vivent dans `examples/` (projets Maven indépendants, hors reactor) :

```bash
cd examples/demo-jwt    # mode header (JWT stateless), port 8080, Swagger UI sur /swagger-ui.html
cd examples/demo-cookie # mode cookie, port 8081, front statique intégré sur /
```

## Conventions

- **Commits** : en anglais, minuscules, à l'impératif, un commit par unité de
  travail cohérente (`add email verification endpoints`).
- **Messages API / erreurs** : en anglais (valeurs `error`, `message`…).
- **Documentation et commentaires** : en français (README, CHANGELOG, Javadoc).
- **Bibliothèques** : ne pas introduire de dépendance sans discussion préalable ;
  le starter reste volontairement léger (Spring Security + JWT uniquement).
- **API publique** : toute rupture binaire est détectée en CI par `japicmp`
  (comparaison avec la dernière release) — les ajouts dépréciés progressifs
  (`@Deprecated` + délégation) sont le mécanisme de migration privilégié.

## Tests

- Tests unitaires classiques pour la logique métier (TOTP, politique de mots de
  passe, événements…).
- Tests d'intégration avec `@SpringBootTest` et propriétés d'environnement dédiées
  (ne pas hériter de la config d'une autre classe de test).
- Un test par exigence de sécurité observée (évènements, métriques, revocation…)
  est toujours bienvenu.

## Pull requests

1. Ouvrez une issue pertinente pour toute modification non triviale.
2. Branche à partir de `main`, changements ciblés (un sujet par PR).
3. `./mvnw verify` vert localement (avec Docker si vous touchez au code JPA).
4. Décrivez le *quoi* et le *pourquoi*, et l'impact sur la compatibilité binaire.
5. Mettez à jour `README.md` / `README.fr.md` et `CHANGELOG.md` si le comportement
   visible change.

## Signaler un bug / proposer une idée

Utilisez les gabarits d'issues : [Rapport de bug](.github/ISSUE_TEMPLATE/bug_report.yml),
[Demande de fonctionnalité](.github/ISSUE_TEMPLATE/feature_request.yml).

## Releases

Le processus de publication (bump de version, `japicmp`, GitHub Packages, release
auto-notes) est décrit dans [RELEASING.md](RELEASING.md).
