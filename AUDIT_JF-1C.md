# Security & Code Audit Report — JF-1C (ZhanFinance)

## Дата: 2026-08-14
## Репозиторий: https://github.com/MrSgemaSeny/JF-1C
## Коммит аудита: `ddc2fb1` (main, актуальный на дату аудита)
## Аудитор: AI-агент OpenHands (read-only аудит, в код изменений не вносилось)

---

## Контекст

JF-1C (ZhanFinance) — корпоративная CRM/ERP-платформа для финансовой компании: учёт клиентов, задачи/пайплайны, документы, курсы, биллинг, аудит-логи, чат (WebSocket), 2FA. Стек: Spring Boot 3 (Java 17, Spring Security 6, Spring Cloud Gateway не используется — монолит) + React 19 (FSD, Tailwind v4). 243 Java-класса, 120 Flyway-миграций (V1–V120).

Уровни: `[CRITICAL]` (CVSS 7.0+) / `[HIGH]` (4.0–6.9) / `[MEDIUM]` / `[LOW/INFO]`.

---

## СВОДНЫЙ РИСК-ПРОФИЛЬ

| Уровень | Кол-во | Примечание |
|---|---|---|
| **CRITICAL** | 1 | Хардкоженный слабый JWT-секрет в docker-compose |
| **HIGH** | 3 | Cookie SameSite=None без CSRF для state-changing, .env в репо, WS origin fallback `*` |
| **MEDIUM** | 5 | |
| **LOW/INFO** | 9 | |

---

## КРИТИЧЕСКИЕ УЯЗВИМОСТИ (требуют немедленного исправления)

### [CRIT-01] Хардкоженный слабый JWT-секрет в docker-compose
- **Репозиторий:** JF-1C
- **Файл:** `docker-compose.yml:43`
- **Описание:** Переменная окружения `JWT_SECRET=change-me-change-me-change-me-change-me-in-production-long-key-needed` захардкожена в committed `docker-compose.yml`. Это known-weak placeholder.
- **Эксплойт:** Любой, кто прочитает публичный репозиторий, знает production JWT-секрет (если docker-compose используется для деплоя или как шаблон). Атакующий подделывает JWT с произвольным `uid`/`role=ADMIN` (`Jwts.builder().claim("uid",1).claim("role","ADMIN")`) и получает полный admin-доступ ко всем эндпоинтам, документам, CRM, биллингу.
- **Защита в коде:** `JwtService` конструктор бросает `IllegalStateException`, если секрет содержит `change-me` И активен prod-профиль. Это блокирует запуск с weak-секретом в prod — отличная защита. **Но** docker-compose не запускает prod-профиль явно (нет `SPRING_PROFILES_ACTIVE=prod`), а dev/default профиль принимает weak-секрет. Если docker-compose используется ближе к прод-среде — уязвимость реальна.
- **Рекомендация:** Убрать `JWT_SECRET` из `docker-compose.yml` (использовать `${JWT_SECRET}` из `.env`, который должен быть в `.gitignore`). Принудительно активировать prod-профиль в любом окружении кроме локального dev.

---

## ВЫСОКИЕ (исправить до деплоя в прод)

### [HIGH-01] Cookie SameSite=None + CSRF отключён для state-changing requests
- **Репозиторий:** JF-1C
- **Файл:** `zhan-finance-backend/src/main/java/com/example/zhanfinancebackend/modules/auth/controller/AuthCookieHelper.java` (`.sameSite("None")`) + `SecurityConfig.java` (`csrf.disable`)
- **Описание:** Access и refresh токены устанавливаются как `HttpOnly; Secure; SameSite=None` cookies. CSRF отключён. Компенсация — `CsrfHeaderFilter` требует `X-Requested-With` или `Content-Type: application/json` на state-changing запросах.
- **Эксплойт:** `CsrfHeaderFilter` пропускает любой POST/PUT/DELETE с `Content-Type: application/json` (CSRF-запрос не может установить этот заголовок для simple-request... **но** `application/json` триггерит CORS-preflight, что блокирует CSRF из arbitrary origin). Это работает, **пока** CORS разрешённые origins строгие. Риск: если CORS когда-нибудь станет `*` (или широкий wildcard-pattern), CSRF-защита сломается. SameSite=None делает cookie отправляемым при cross-site запросе.
- **Рекомендация:** Для cross-site (github.io → fly.dev) SameSite=None+Secure оправдан. Но добавить `SameSite=Lax` как дефолт для same-site деплоев, и явно документировать, что `Content-Type: application/json` gate — единственный CSRF-барьер. Рассмотреть double-submit cookie token как второй слой.

### [HIGH-02] `.env` файл закоммичен в репозиторий
- **Репозиторий:** JF-1C
- **Файл:** `zhan-finance-frontend/.env`, `zhan-finance-frontend/.env.development`
- **Описание:** `.gitignore` игнорирует `.env.local`, `.env.development.local` и т.п., но **не** базовый `.env` / `.env.development`. Оба файла закоммичены.
- **Содержимое:** `VITE_API_URL`, `VITE_GOOGLE_CLIENT_ID`, `VITE_USE_MOCK_SERVICES`. **Секретов нет** — Google Client ID public по дизайну OAuth, остальные значения non-secret. Реальной утечки секретов не произошло.
- **Риск:** Нарушение конвенции. Будущий секрет, случайно положенный в `.env`, попадёт в git-историю. CI (`ci.yml`) тоже хардкодит `VITE_GOOGLE_CLIENT_ID` как fallback — не секрет, но антипаттерн.
- **Рекомендация:** Добавить `.env` и `.env.development` в `.gitignore`. Оставить только `.env.example`. Удалить закоммиченные `.env`/`.env.development` новой миграцией/коммитом (история останется, но рабочее дерево чистое).

### [HIGH-03] WebSocket allowedOrigins fallback к `*`
- **Репозиторий:** JF-1C
- **Файл:** `zhan-finance-backend/src/main/java/com/example/zhanfinancebackend/modules/chat/config/WebSocketConfig.java` (`@Value("${app.cors.allowed-origins:*}")`)
- **Описание:** `allowedOrigins` для STOMP-эндпоинта `/ws` берётся из `app.cors.allowed-origins` с дефолтом `*` (звёздочка). Если env-переменная не установлена — WebSocket принимает соединения с любого origin.
- **Эксплойт:** CSRF/CSWSH (Cross-Site WebSocket Hijacking). Злоумышленный сайт открывает WebSocket к `/ws`, браузер жертвы отправляет cookies (SameSite=None!), соединение аутентифицируется как жертва. Атакующий читает/пишет в чат от имени жертвы через WebSocket-канал.
- **Рекомендация:** Убрать дефолт `*`. Зафиксировать явный список origins в `application.properties` (`app.cors.allowed-origins` уже определён) и пробрасывать тот же список в WebSocketConfig. Никогда `*` для authenticated WebSocket.

---

## СРЕДНИЕ (исправить в ближайшей итерации)

### [MED-01] Actuator endpoints выставлены на том же порту (8080), `/actuator/health` permitAll
- **Файл:** `application.properties` (`management.server.port=${MANAGEMENT_SERVER_PORT:8080}`) + `SecurityConfig` (`/actuator/health`, `/actuator/info` permitAll)
- **Описание:** Actuator на том же порту, что и приложение. `/health` и `/info` публичные — разумно. Но `management.endpoints.web.exposure.include=health,info,metrics,prometheus` — `metrics`/`prometheus` не публичные (требуют auth), что хорошо. Однако на одном порту с app — risk surface.
- **Рекомендация:** В прод — отдельный management-порт (`MANAGEMENT_SERVER_PORT=9090`) за firewall, или `/actuator/**` strictly denyAll кроме `/health`.

### [MED-02] Refresh token не ротируется при refresh — token reuse не детектируется на уровне "old token stays valid until consumed"
- **Файл:** `RefreshTokenService.java` (`verify` + `create` new)
- **Описание:** При refresh: старый токен удаляется (`deleteByToken`), создаётся новый. **Это хорошо** — старый инвалидидируется. Логирует "possible token reuse attack" при повторном использовании. Но в `AuthService.refresh`: `verify` сначала (`findByToken`), потом `deleteByToken` — между этими двумя вызовами в конкурентной среде токен может быть использован дважды (TOCTOU). `deleteByToken` возвращает 0 → второй запрос падает — есть защита.
- **Рекомендация:** Текущая реализация защищена (deleteByToken atomic). Задокументировать как предполагаемое поведение. Рассмотреть `@Transactional` isolation level REPEATABLE_READ на refresh для дополнительной защиты.

### [MED-03] AuthRateLimitFilter резолвит IP из `Fly-Client-IP` header
- **Файл:** `AuthRateLimitFilter.java` (`request.getHeader("Fly-Client-IP")`)
- **Описание:** IP берётся из `Fly-Client-IP` (Fly.io-specific header). Это header, который клиент-контролируем, если запрос не проходит через trusted Fly proxy. Спуфинг → обход rate-limit на login/register.
- **Рекомендация:** На Fly.io `Fly-Client-IP` устанавливается прокси и не подделывается клиентом — корректно для этого хостинга. Но если бэкенд когда-нибудь переедет — header станет спуфабельным. Зафиксировать в конфиге доверие только Fly proxy, или fallback на `getRemoteAddr` только если `Fly-Client-IP` отсутствует (уже так). Документировать зависимость от Fly.io.

### [MED-04] Документ upload: extension blocklist вместо строгого allowlist для content-type
- **Файл:** `DocumentService.java:99-105` (`.html`, `.htm`, `.svg`, `.exe`, `.js`, `.sh` blocklist)
- **Описание:** MIME определяется через Tika (хорошо), но есть fallback на extension-блок. Blocklist не покрывает все опасные типы (например, `.php`, `.jsp`, `.aspx`, `.svgz` — хотя svg есть). `application/octet-stream` fallback на text для `md/txt/csv`.
- **Рекомендация:** Перейти на strict allowlist `ALLOWED_CONTENT_TYPES` (уже есть!) и не полагаться на extension-блок. Текущий `ALLOWED_CONTENT_TYPES` — основной gate, extension-block — defence-in-depth. Ок, но документировать.

### [MED-05] `open-in-view=false` (хорошо), но нет явного `@Transactional` audit на некоторых read-paths
- **Файл:** `application.properties` (`spring.jpa.open-in-view=false`)
- **Описание:** `open-in-view=false` — отличная практика (ленивая загрузка вне транзакции → исключение). Но требует, чтобы все read-paths, использующие lazy-связи, были помечены `@Transactional(readOnly=true)`. Аудит не прошёл по всем 243 классам — это поверхность для отдельной проверки на N+1/LazyInitializationException.
- **Рекомендация:** Проверить контроллеры, возвращающие сущности с lazy-связями (Client.tasks, User.documents), на наличие `@Transactional(readOnly=true)` в service-слое.

---

## НИЗКИЕ / INFO

- **[LOW-01]** `ApiRateLimitFilter` имеет no-arg конструктор (`this(null)`) — fallback, если JwtService не внедрён. Создаёт stateful filter без auth-resolve. Технически мёртвый путь (Spring всегда внедряет), но code smell.
- **[LOW-02]** `CsrfHeaderFilter` позволяет `application/json` без `X-Requested-With` — полагается на CORS-preflight. Если CORS сломается — единственный барьер упадёт (см. HIGH-01).
- **[LOW-03]** Redis закоммичен в docker-compose без пароля (`redis:latest`, без `requirepass`). Локальная dev — ок, но опасно, если compose используется ближе к прод.
- **[LOW-04]** PostgreSQL в docker-compose: `test_user/pass1` — weak dev креды. Не прод-секрет, но антипаттерн (как CRIT-01 паттерн).
- **[LOW-05]** `spring.flyway.out-of-order=true` + `ignore-migration-patterns=*:missing` — позволяет пропускать миграции. Опасно для воспроизводимости схемы. Рассмотреть disable в прод.
- **[LOW-06]** `spring.flyway.baseline-version=110` — baseline на 110, при наличии V1-V120. Означает, что V1-V110 могут быть "уже применены" без проверки. Опасно для свежей БД.
- **[LOW-07]** CORS `allowedOriginPatterns` в dev включает `http://localhost:*` — широкий wildcard для dev. В prod-свойствах сужается (хорошо).
- **[LOW-08]** 120 Flyway-миграций, включая rollback (`V118__Rollback_Payments.sql`) — schema-evolution активно. Нет аудита каждой на деструктивность, но V103 (Performance_Indexes), V111 (Protect_Audit_Log_Table) — признаки зрелой schema-гигиены.
- **[LOW-09]** Google Client ID хардкожен в `GoogleAuthService` (`@Value` с default) и в `ci.yml` fallback. Не секрет (public OAuth client), но env-config лучше.

---

## CODE REVIEW — ЗАМЕЧАНИЯ

### JF-1C Backend

**Положительное:**
- **Security headers — отличный набор.** CSP (`default-src 'self'; script-src 'self'`), X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy strict-origin-when-cross-origin, COOP, Permissions-Policy (camera/mic/geo disabled). Лучший набор из двух репозиториев.
- **JWT prod-guard.** `JwtService` конструктор бросает `IllegalStateException` при weak-секрет в prod-профиле. Превентивная защита.
- **JWT type segregation.** `type=access` claim, `extractUsernameIfValidAccessToken` проверяет type.
- **CrmAccessService — централизованный RBAC на уровне данных.** `canReadClient`, `canReadTask`, `canCreateTaskFor`, `canUpdateTaskStage` — role + ownership + business-rule (не non-admin не может вывести из WON/LOST). Зрелая authz.
- **DocumentAccessService** — аналогичный gate для документов (canRead/canWrite/canCreateFor).
- **2FA (TOTP)** — полноценная реализация через `dev.samstevens.totp`, pre-auth flow, попытки ограничены (`V113__add_attempts_to_two_factor_pre_auth`).
- **Path traversal защита в LocalStorageService** — `StringUtils.cleanPath`, проверка `..`, нормализация + проверка `destinationFile.getParent().equals(rootLocation)`. Правильная защита.
- **Tika MIME-detection** для upload (не доверяет расширению).
- **Refresh token rotation** с atomic delete + reuse-detection logging.
- **Rate limiting** — двухуровневый: AuthRateLimitFilter (auth, 10/мин) + ApiRateLimitFilter (tiered: tasks/documents/search/general). User-based + IP fallback.
- **Audit-логи** — отдельный модуль (`modules/audit`), `@Audited` annotation, `V111__Protect_Audit_Log_Table`. Production-grade.
- **Swagger/OpenAPI закрыт в prod** (`application-prod.properties`: `springdoc.api-docs.enabled=false`).
- **`/v1/internal/**` denyAll** — internal endpoints явно запрещены.
- **BCrypt** password hashing.
- **Swagger доступен только ADMIN** — `hasRole("ADMIN")`.
- **Flyway `ddl-auto=none` в prod** (строже, чем MeDev's validate).

**Замечания (non-security):**
- Spring Boot 4.1.0 в `build.gradle` — крайне новая версия. Проверить стабильность production-deps.
- `poi-tl:1.12.2`, `tika-core:2.9.2` — проверить на CVE (Apache POI/XLSX historical parser CVEs).
- 120 миграций — schema mature, но `out-of-order=true` + `baseline-version=110` — risk (LOW-05/06).
- `open-in-view=false` требует дисциплины `@Transactional(readOnly=true)` (MED-05).

### JF-1C Frontend

**Положительное:**
- **Access token в памяти** (`memoryAccessToken` в `http.ts`), не в localStorage. Хранится только в JS-переменной.
- **Refresh token в HttpOnly cookie** (`credentials: 'include'`) — фронт не имеет JS-доступа к refresh. Хорошая модель.
- **Auto-refresh interceptor** — 401 → refresh → retry, с dedup (`refreshPromise`).
- **`X-Requested-With: XMLHttpRequest`** на каждом запросе — компенсирует CSRF (см. CsrfHeaderFilter).
- **Zod** для runtime-валидации DTO на фронте.
- **Sentry** error tracking (PII disabled в prod).
- **i18n** (kk/ru/en).

**Замечания:**
- `localStorage.removeItem(AUTH_STORAGE_KEY)` на failed refresh — но `AUTH_STORAGE_KEY` (`zhan_finance_auth`) хранит **только user-profile** (userId, email, role), не токены (токены в cookie/memory). Ок — не утечка токенов.
- E2E тестов не видно (только vitest).
- `html2pdf.js` client-side — проверяет на XSS в рендере (контент из CRM).

---

## ЧТО СДЕЛАНО ПРАВИЛЬНО (зелёный список)

1. Security headers (CSP, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, COOP, Permissions-Policy) — лучший набор.
2. JWT prod-guard (IllegalStateException при weak-секрет в prod).
3. JWT type segregation (access claim).
4. CrmAccessService + DocumentAccessService — централизованная data-level RBAC с business-rules.
5. 2FA TOTP с pre-auth и rate-limiting попыток.
6. Path traversal защита в LocalStorageService (cleanPath + normalize + parent check).
7. Tika MIME-detection для upload (не доверяет расширению).
8. Refresh token rotation с atomic delete + reuse-detection.
9. Двухуровневый rate limiting (auth + tiered API).
10. Audit-модуль с annotation-driven логированием + protected table.
11. Swagger закрыт в prod, `/v1/internal/**` denyAll.
12. BCrypt password hashing, `ddl-auto=none` в прод.
13. Access token в памяти фронтенда, refresh в HttpOnly cookie.
14. Auto-refresh interceptor с dedup.
15. Flyway 120 миграций с schema-protection (V111 audit protection).

---

## ИТОГОВАЯ ОЦЕНКА

- **JF-1C Security Score: 7.5/10**
  - 1 CRITICAL (хардкоженный JWT-секрет в compose, но mitigated prod-guard), 3 HIGH (SameSite=None+CSRF, .env в репо, WS origin `*`).
  - Сильная defense-in-depth (headers, RBAC, 2FA, audit), но конфигурационные дыры (compose, WS, env) тянут вниз.
- **JF-1C Code Quality: 8.5/10**
  - Централизованный RBAC, audit-модуль, зрелая schema-эволюция. Spring Boot 4.1 — риск новизны.
- **JF-1C Architecture: 8/10**
  - Монолит, но хорошо модулирован (CRM/documents/services/notifications/audit/chat). WebSocket + 2FA + audit — production-фичи.

**Вердикт:** Зрелая корпоративная платформа с сильной defense-in-depth на уровне кода (security headers, RBAC, 2FA, audit, path-traversal защита). Основные риски — конфигурационные: хардкоженный JWT-секрет в docker-compose (CRIT-01, mitigated prod-guard но всё равно anti-pattern), закоммиченный `.env` (HIGH-02, без реальной утечки), WebSocket origin `*` fallback (HIGH-03, реальная CSWSH-поверхность). Закрытие CRIT-01 + HIGH-03 поднимет score до 8.5+.

---

*Аудит подготовлен как read-only обзор. В код JF-1C изменений не вносилось.*
