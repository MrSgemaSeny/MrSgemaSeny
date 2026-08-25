# Security & Code Audit Report — MeDev

## Дата: 2026-08-14
## Репозиторий: https://github.com/MrSgemaSeny/MeDev
## Коммит аудита: `ce68d94` (main, актуальный на дату аудита)
## Аудитор: AI-агент OpenHands (read-only аудит, в код изменений не вносилось)

---

## Контекст

MeDev — data-first SaaS для разработчиков: берёт GitHub-активность + резюме PDF, через AI (Groq, llama-3.1-70b) строит профиль, генерирует ATS-friendly PDF резюме и публичное веб-портфолио. Стек: Spring Boot 3.3.0 (Java 17) + React 19 (FSD). Модульный монолит.

Аудит проводился после серии security-hardening коммитов (Sprint 5: `cafb31c`, `59d1ec5`, `7c65473` и др.). Большинство ранее идентифицированных проблем закрыты — это отражено ниже.

Уровни: `[CRITICAL]` (CVSS 7.0+) / `[HIGH]` (4.0–6.9) / `[MEDIUM]` / `[LOW/INFO]`.

---

## СВОДНЫЙ РИСК-ПРОФИЛЬ

| Уровень | Кол-во | Примечание |
|---|---|---|
| **CRITICAL** | 0 | Все ранее идентифицированные CRITICAL закрыты в Sprint 5 |
| **HIGH** | 3 | Требуют исправления до масштабирования на прод |
| **MEDIUM** | 4 | Ближайшая итерация |
| **LOW/INFO** | 11 | Дублирование, мёртвый код, несогласованности |

---

## КРИТИЧЕСКИЕ УЯЗВИМОСТИ (требуют немедленного исправления)

**Нет.** Все ранее идентифицированные критические векторы (ECB-шифрование, незашифрованные токены, отсутствие IDOR-проверок) закрыты в Sprint 5.

---

## ВЫСОКИЕ (исправить до деплоя в прод)

### [HIGH-01] Kaspi orderId содержит user-controlled userId
- **Репозиторий:** MeDev
- **Файл:** `backend/src/main/java/com/medev/modules/billing/service/KaspiPayService.java:79`
- **Описание:** Ссылка оплаты формируется как `orderId={userId}_{months}`. `userId` — это идентификатор плательщика, но он встраивается в user-controlled часть URL платежа. Webhook парсит `orderId` и повышает план пользователя по этому ID.
- **Эксплойт:** Если `KASPI_SECRET_KEY` скомпрометирован (или Kaspi-эндпоинт не защищён подписью на прод-уровне), атакующий формирует webhook с произвольным `orderId={victimUserId}_{12}` и повышает любого пользователя до PRO на 12 месяцев.
- **Рекомендация:** Не класть `userId` в user-visible часть `orderId`. Использовать серверный `paymentIntentId` (UUID, хранимый в БД) и резолвить `userId` через него при обработке webhook. Подпись HMAC должна покрывать весь payload, не только `orderId`.

### [HIGH-02] CSRF отключён, refresh через Authorization header/тело без компенсирующего контроля для non-browser клиентов
- **Репозиторий:** MeDev
- **Файл:** `backend/src/main/java/com/medev/shared/security/SecurityConfig.java:40` (`.csrf(AbstractHttpConfigurer::disable)`)
- **Описание:** CSRF осознанно отключён (stateless JWT). Это обосновано для access-токена в `Authorization` header. Однако refresh-токен также передаётся — фронтенд сохраняет состояние. Если refresh когда-либо будет приниматься через cookie (а не тело), это станет CSRF-уязвимым.
- **Текущее состояние:** Refresh передаётся в теле запроса (`TokenRefreshRequest`), не в cookie — компенсирует. Но `CookieOAuth2AuthorizationRequestRepository` использует cookies с `SameSite` через `X-Forwarded-Proto` (см. MEDIUM-01).
- **Рекомендация:** Зафиксировать в контракте: refresh токен — только тело запроса, никогда cookie. Добавить explicit проверку `Content-Type: application/json` на `/auth/refresh` как CSRF-компенсацию (как сделано в JF-1C `CsrfHeaderFilter`).

### [HIGH-03] Фронтенд-тесты не запускаются в CI
- **Репозиторий:** MeDev
- **Файл:** `.github/workflows/ci.yml` (только `npm run build`, нет `npm test`)
- **Описание:** CI проверяет сборку фронтенда, но не запускает `vitest`. Security-критичные пути фронтенда (interceptor 401-refresh, ownership-guards, sanitize) не защищены от регресса.
- **Эксплойт:** Не прямая уязвимость, но дыра в safety-net: будущий рефакторинг может сломать auto-logout при failed refresh и пропустить в main.
- **Рекомендация:** Добавить `npm test` (или `npm run test -- --run`) в `ci.yml` для фронтенд-джоб. Vitest уже настроен (`package.json` имеет `test` скрипт).

---

## СРЕДНИЕ (исправить в ближайшей итерации)

### [MED-01] OAuth2 cookie SameSite зависит от X-Forwarded-Proto
- **Файл:** `backend/src/main/java/com/medev/modules/auth/security/CookieOAuth2AuthorizationRequestRepository.java` (`setSecure(request.isSecure() || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")))`)
- **Описание:** Флаг `Secure` на OAuth2-state cookie ставится на основе `X-Forwarded-Proto`, который клиент-контролируем при отсутствии trusted-proxy конфигурации. Спуфинг заголовка может привести к `Secure=false` cookie поверх HTTPS.
- **Рекомендация:** Зафиксировать `Secure=true` в прод-профиле (env-based), не полагаться на заголовок. Или использовать Spring `server.forward-headers-strategy=framework` с доверенным прокси.

### [MED-02] AI structured-эндпоинты не лимитируют размер input
- **Файл:** `backend/src/main/java/com/medev/modules/ai/controller/AiController.java` (`/match-job`, `/cover-letter`, `/tailor`)
- **Описание:** `sanitize()` (обрезка до 2000 символов) применяется только к chat-streaming. Structured-эндпоинты передают `jobDescription` без лимита в Groq. Это стоимость-риск (token-burn DoS) и prompt-injection-поверхность.
- **Рекомендация:** Ввести `@Size(max=10000)` на DTO для всех structured-эндпоинтов. Применять единый sanitize.

### [MED-03] Stripe webhook без idempotency-key
- **Файл:** `backend/src/main/java/com/medev/modules/billing/service/StripeService.java` (handleWebhook)
- **Описание:** Подпись проверяется, но event-id не сохраняется. Replay-дубликат обработается повторно (идемпотентен по плану, но логирует шумно и при ошибке может дважды применить downgrade).
- **Рекомендация:** Сохранять `event.getId()` в Redis с TTL 30 дней; при повторе — ранний return.

### [MED-04] Дублирование JSON-cleaning в двух местах
- **Файл:** `GroqClient.java` и `AiAnalysisService.java`
- **Описание:** Логика снятия ` ```json ` обёртки дублируется. Расхождение в обработке edge-case может привести к тому, что один путь примет невалидный JSON, а другой — нет.
- **Рекомендация:** Вынести в единый `JsonSanitizer.clean()`.

---

## НИЗКИЕ / INFO

- **[LOW-01]** Мёртвая колонка `profiles.github_token` (`Profile.java:38`). Токен хранится в `users.github_access_token` через GCM-конвертер. Колонка не используется, но осталась в схеме. Удалить новой миграцией `V25__drop_profiles_github_token.sql`.
- **[LOW-02]** Мёртвая таблица `subscriptions` (V8). План в `users.plan`. Аналогично — кандидат на cleanup-миграцию.
- **[LOW-03]** `AdminGuard` (frontend) проверяет `username === 'admin'`, а не `role === 'ADMIN'`. UI-gate, реальная защита на бэкенде (`hasRole('ADMIN')`). Вводит в заблуждение, но не уязвимость. Исправить для консистентности.
- **[LOW-04]** `structuredCompletion` использует `.block()` — блокирует thread в reactive-пайплайне. При нагрузке упрётся в thread pool. Перевести на reactive-chain или вынести в bounded-elastic.
- **[LOW-05]** `max_tokens=2048` фиксирован в GroqClient — длинные генерации (full-profile) могут обрезаться. Сделать параметром.
- **[LOW-06]** `VectorizationService` удаляет и пере-добавляет все векторы на каждое обновление профиля — O(n) вместо diff. При росте профилей станет узким местом.
- **[LOW-07]** `GitHubService.fetchUserPublicRepos` тянет без авторизации (публичные 10 шт) — теряет приватные проекты пользователя. Roadmap Phase 1.
- **[LOW-08]** `ServerPortCustomizer` сканирует порты 8080–8083 — race condition в Docker/CI при параллельном старте. Зафиксировать порт через env.
- **[LOW-09]** `RedisTemplate<String,Object>` смешивает сериализаторы (GenericJackson2Json для Object-template, StringRedisTemplate для auth). Потенциальная десериализация-гадкость при ошибочном типе. Унифицировать.
- **[LOW-10]** Stripe не ставит `subscriptionExpiresAt` (бессрочная подписка), Kaspi ставит. `assertPro` проверяет expiry только если `!= null`. Несогласованная модель PRO-gate. Унифицировать.
- **[LOW-11]** Нет staging-окружения (деплой main → prod напрямую). Branch protection есть, но нет pre-prod верификации.

---

## CODE REVIEW — ЗАМЕЧАНИЯ

### MeDev Backend

**Положительное:**
- **IDOR закрыт системно.** Все эндпоинты резолвят `userId` из `SecurityUtils.getCurrentUserId()` (JWT), не из тела. Ownership-проверки на уровне записей: `entity.getProfile().getId().equals(profile.getId())` перед update/delete. Reorder дополнительно валидирует все ID.
- **JWT type segregation.** `type=access`/`type=refresh` claim; `JwtFilter` принимает только access; refresh в Authorization блокируется.
- **AES-256-GCM** для `github_access_token` (`EncryptionUtils`). IV per-encryption (12 byte), tag 128 bit, ключ из env. ECB-конвертер (`StringCryptoConverter`) удалён в Sprint 5.
- **OAuth2 code-exchange через Redis** — короткий `oauth2_code` (5 мин, single-use), нет access-токена в URL.
- **Smart Merge** — запрет галлюцинации (null вместо выдумки), `RuntimeException "Aborting to prevent data loss"` при невалидном JSON (не затирает профиль).
- **AuditService теперь wired** (Sprint 5) — `logAction` вызывается в auth-register, OAuth2-success, admin-plan/role-change, billing-kaspi/stripe.
- **Admin dashboard реальный** (Sprint 5) — `countByPlan`, `sumTotalTokensSince` вместо заглушек.
- **ResumeController PRO-проверка исправлена** (Sprint 5) — `if (user.getPlan() != PRO)` вместо инвертированной `contains('pro')`.
- **match-job теперь PRO-gated** (Sprint 5) — `assertPro` в `AiApplicationService.matchJob`.
- **Rate limiting** — AuthRateLimiter + AiRateLimiter через `getRemoteAddr()` (не `X-Forwarded-For`). Унифицировано в Sprint 5.
- **PiiMasker** (Sprint 5) — маскирование email/SSN/IIN/phone перед LLM.
- **Resilience4j** CircuitBreaker + Retry (только retriable 429/5xx) в GroqClient.

**Замечания (non-security):**
- SRP соблюдён — сервисы компактные, нет god-objects.
- MapStruct для entity→DTO.
- Event-driven (`ProfileUpdatedEvent` → async VectorizationService).
- Тесты: JUnit 5 + Testcontainers (PostgreSQL, Redis), `AbstractIntegrationTest`. Покрытие security-путей есть.
- Flyway миграции V1–V24, `ddl-auto=validate`. Не модифицируются существующие.

### MeDev Frontend

**Положительное:**
- **Access token в памяти, не в localStorage** — Zustand store `partialize` персистит только `username/plan/role`, НЕ `accessToken`/`refreshToken` (`store.ts:41`). XSS не крадёт токен.
- **Axios interceptor** — авто-рефреш access при 401, queue повторных запросов, logout при failed refresh, logout при 404 на `/profile` (desynced token).
- **FSD строго** — слои не пробиваются вверх.
- **GitHub Dark Mode** — консистентный дизайн.

**Замечания:**
- E2E-тестов нет (только unit/integration). Security-critical flows (refresh-fallback, admin-guard) стоит покрывать e2e.
- `AdminGuard` на `username` — см. LOW-03.

---

## ЧТО СДЕЛАНО ПРАВИЛЬНО (зелёный список)

1. IDOR protection системная, на уровне записей, с ownership-проверками reorder.
2. JWT type segregation (access vs refresh).
3. AES-256-GCM шифрование OAuth-токенов (IV per-encryption, tag 128 bit).
4. OAuth2 code-exchange через Redis (нет токена в URL).
5. Access token в памяти фронтенда, не в localStorage.
6. Smart Merge с запретом галлюцинации (null, не выдумка; abort при невалидном JSON).
7. AuditService wired в критические потоки (auth, OAuth, admin, billing).
8. SSRF-защита в WebScraper (whitelist хостов + loopback/private check + DNS-кэш).
9. PDF MIME-проверка (content-type + magic bytes `%PDF`, лимит 10 МБ).
10. Stripe webhook signature verification.
11. Kaspi webhook HMAC-SHA256 + constant-time compare.
12. CORS строгий (env-based), credentials=true.
13. Rate limiting унифицирован (getRemoteAddr) + AI-квоты (Redis, FREE/PRO).
14. Branch protection в CI (require PR + status checks).
15. PiiMasker перед LLM (Sprint 5).
16. Branch protection + structured JSON-логи (Logstash, MDC userId/requestId).

---

## ИТОГОВАЯ ОЦЕНКА

- **MeDev Security Score: 8.5/10**
  - 0 CRITICAL, 3 HIGH (Kaspi orderId, CSRF-контракт, фронтенд-тесты в CI), 4 MEDIUM.
  - Все ранее критические закрыты в Sprint 5. Архитектура security-by-design.
- **MeDev Code Quality: 8/10**
  - SRP, FSD, MapStruct, event-driven, Testcontainers. Мёртвый код (colonка/таблица) и дублирование JSON-cleaning тянут вниз.
- **MeDev Architecture: 9/10**
  - Модульный монолит, чёткие границы, подменяемый AI-провайдер (`LlmProvider`), resilient GroqClient.

**Вердикт:** Production-ready MVP с зрелой security-моделью. HIGH-01 (Kaspi orderId) — единственный реальный риск, требующий исправления перед включением Kaspi в реальный платёжный поток.

---

*Аудит подготовлен как read-only обзор. В код MeDev изменений не вносилось.*
