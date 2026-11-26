# Processus de release

## 1. Release standard (GitHub Packages)

1. **Verifier** `./mvnw verify` vert : tests, JaCoCo (instruction >= 80 %,
   branches >= 55 %) et **japicmp** (compatibilite binaire).
2. **Bumper** `<version>` dans `pom.xml` (semver : major / minor / patch).
3. **Bumper** `<japicmp.oldVersion>` dans `pom.xml` avec la derniere version
   *publiee* (le tag `vX.Y.Z` doit exister : la CI le reconstruit pour la
   comparaison).
4. **Ajouter** la section `## [X.Y.Z] - AAAA-MM-JJ` en tete de `CHANGELOG.md`.
5. **Commit** (minuscule, anglais, impératif) puis **tag annoté** `vX.Y.Z` :
   ```bash
   git commit -am "release 2.2.0: metrics, health, 2fa"
   git tag -a v2.2.0 -m "release 2.2.0"
   git push origin main --follow-tags
   ```
6. **La CI prend le relais** sur le tag :
   - construction de la release precedente (`japicmp.oldVersion`) puis
     `mvnw verify` complet (tests + JaCoCo + japicmp) ;
   - publication sur **GitHub Packages** (`zrouga.spring:security-starter`) ;
   - creation de la **release GitHub avec notes automatiques**
     (commits / PR depuis le tag precedent).

### Consommer l'artefact

```xml
<dependency>
    <groupId>zrouga.spring</groupId>
    <artifactId>security-starter</artifactId>
    <version>2.2.0</version>
</dependency>
```

```xml
<repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/karimzrouga/zrouga-spring-security</url>
</repository>
```

(avec un `settings.xml` portant un `server` id `github` et un token
`read:packages`.)

## 2. Compatibilite binaire (japicmp)

- Chaque `mvnw verify` compare la version courante a `japicmp.oldVersion`
  (rapport : `target/japicmp/japicmp.md`).
- **Incompatibilite binaire = build en echec** : corriger le code, ajouter un
  shim `@Deprecated` deleguant, ou exclure une classe interne ciblee
  (voir `<excludes>` dans le `pom.xml`, ex. l'auto-configuration).
- Si l'ancienne version n'est pas dans le m2 local, le check est ignore
  (`ignoreMissingOldVersion`) : la CI, elle, la construit toujours a partir du
  tag.

## 3. Vers Maven Central (migration possible)

Le projet publie aujourd'hui sur **GitHub Packages**. Le `pom.xml` respecte
deja les exigences Maven Central (name, description, url, license, scm,
developers + jars sources et javadoc). Pour migrer vers Central :

1. Creer un compte [Sonatype Central Portal](https://central.sonatype.com/)
   et verifier la possession du groupId (`zrouga.spring`).
2. Ajouter la signature **GPG** (`maven-gpg-plugin`) et le plugin
   `central-publishing-maven-plugin` (ou `nexus-staging-maven-plugin`).
3. Remplacer `distributionManagement` par la configuration Central
   (ou publier via le portail web / CI dediee avec `SONATYPE_TOKEN`).
4. Activer un second job CI sur les tags, avec les secrets GPG et Sonatype.

Les artefacts publices doivent inclure : jar binaire, jar sources, jar
javadoc, POM complet, checksums et signature.
