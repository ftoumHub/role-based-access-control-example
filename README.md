# Role based access control example

Application Spring Boot de démonstration : connexion durcie, authentification sans mot de passe, MFA et contrôle d'accès par rôles.
Fork de [lombocska/role-based-access-control-example](https://github.com/lombocska/role-based-access-control-example), modernisé (plateau **P1 – durcissement**).

## Stack

- Java 21, Spring Boot 4.1, Spring Security 7.1 (MFA, passkeys/WebAuthn, lien à usage unique)
- Thymeleaf, Spring Data JPA, Liquibase, PostgreSQL 17
- Spring Session JDBC (sessions partagées), Redis (compteurs anti-force brute partagés)
- Actuator + Micrometer/Prometheus, Grafana
- Tests : JUnit 5, MockMvc, Testcontainers (PostgreSQL + Redis)

## Ce que change le plateau P1

| Avant | Après |
|---|---|
| Compteur d'échecs dans une `HashMap` statique, clé = IP **ou en-tête X-Forwarded-For** | Compteurs Redis par compte **et** par IP réelle, avec expiration ; X-Forwarded-For pris en compte uniquement depuis un proxy de confiance (`server.forward-headers-strategy=native`) |
| reCAPTCHA vérifié dans un listener, **après** l'authentification | `CaptchaVerificationFilter` placé avant `UsernamePasswordAuthenticationFilter` |
| Pas de verrouillage | Verrouillage temporaire du compte après 10 échecs (15 min), événement + métrique |
| Tous les endpoints Actuator ouverts sans authentification | Port de management 8081, `health` public, `prometheus` réservé au compte technique (HTTP Basic, gestionnaire d'authentification isolé), `env`/`heapdump` non exposés |
| CSRF désactivé, déconnexion en GET | CSRF actif, déconnexion en POST |
| Clés reCAPTCHA et mots de passe par défaut dans `application.yml` | Secrets par variables d'environnement ; démarrage refusé s'ils manquent ; valeurs locales uniquement dans le profil `dev` |
| BCrypt seul | `DelegatingPasswordEncoder` : Argon2 pour les nouveaux hash, ré-encodage automatique des anciens hash BCrypt à la connexion |
| Aucun état de compte | Colonnes `enabled`, `locked_until`, `account_expires_at`, `credentials_expire_at` traduites en `UserDetails` |
| Mot de passe uniquement | + passkeys (WebAuthn) et lien de connexion à usage unique |
| Rôle ADMIN testé à la main dans le contrôleur | `/administration/accounts` exige ROLE_ADMIN **et** deux facteurs : passkey, ou mot de passe + lien à usage unique (`AllRequiredFactorsAuthorizationManager.anyOf`) |
| Logs applicatifs | Table `audit_event` (succès/échecs, déconnexions, refus d'autorisation) via l'audit Actuator ; métriques `app.security.authentication` et `app.security.account.lockouts` |
| Spring Boot 2.3, `WebSecurityConfigurerAdapter`, Lombok | Spring Boot 4, `SecurityFilterChain`, records Java |

À noter : dans Spring Security 7.1, `OneTimeTokenAuthenticationProvider` et `WebAuthnAuthenticationProvider` ne vérifient pas l'état du compte. `StatusEnforcingUserDetailsService` comble ce manque : un compte verrouillé ou désactivé ne peut pas non plus se connecter par lien ou par passkey (couvert par `SecurityIT`).

## Lancer en local

```bash
./mvnw -DskipTests package
docker compose -f docker/compose.yml up --build
```

- Application : http://localhost:8080 (profil `dev`)
- Le lien de connexion à usage unique est écrit dans les logs de l'application (adaptateur `LoggingMagicLinkSender`)
- Prometheus : http://localhost:9090, Grafana : http://localhost:3000 (admin/admin)

Variables attendues hors profil `dev` : `DB_USERNAME`, `DB_PASSWORD`, `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY`, `MONITORING_PASSWORD`, et selon le déploiement `WEBAUTHN_RP_ID`, `WEBAUTHN_ALLOWED_ORIGINS`, `REDIS_HOST`, `LIQUIBASE_CONTEXTS`.

## Comptes de démonstration (profil `dev`, mot de passe `test`)

| Email | Rôles |
|---|---|
| admin@admin.com | ROLE_ADMIN, ROLE_EDITOR, ROLE_USER |
| user1@test.com | ROLE_EDITOR, ROLE_USER |
| user2@test.com | ROLE_EDITOR |
| user3@test.com | ROLE_USER |

Pour l'administration, connectez-vous avec admin@admin.com puis ouvrez « Administration » : l'application demande un second facteur (lien à usage unique, ou passkey enregistrée depuis « Mes passkeys »).

## Tests

```bash
./mvnw verify   # Docker requis pour Testcontainers
```

`BruteForceProtectionTest` (unitaire) couvre la politique anti-force brute ; `SecurityIT` (intégration) couvre connexion, CAPTCHA avant authentification, X-Forwarded-For forgé, verrouillage, liens à usage unique, matrice rôles × pages, MFA admin, CSRF, déconnexion, Actuator et audit.
