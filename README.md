# spring-session-rbac-java

基于 Spring Boot Web 的会话认证、角色授权与高风险操作保护示例。不依赖 Spring Security，
核心逻辑（会话存储、认证、授权、CSRF）均为工程内实现，便于本地验证与审计。

## 快速开始

```bash
mvn test          # 运行全部单元/集成测试（23 个）
mvn spring-boot:run
```

演示账号（仅本地验证用，口令加盐哈希存储）：

| 用户  | 口令        | 角色         |
|-------|-------------|--------------|
| alice | alice-pass  | USER         |
| bob   | bob-pass    | USER, ADMIN  |

## 会话生命周期

1. **登录** `POST /auth/login`（JSON: `username`/`password`）
   - 成功：签发全新会话 ID（CSPRNG，防会话固定）+ 会话绑定 CSRF 令牌；
     会话 ID 通过 `Set-Cookie: SESSIONID=...; HttpOnly; SameSite=Strict; Path=/` 下发，
     CSRF 令牌在响应体 `csrfToken` 字段返回。
   - 失败：统一 `401 {"error":"UNAUTHORIZED","reason":"INVALID_CREDENTIALS"}`，
     **账号不存在与口令错误的响应完全一致**（含常量时间比较），不泄露账号存在性。
2. **续期** `POST /auth/renew`（需会话 Cookie + CSRF 头）：滑动延长过期时间；
   过期/已注销会话不得通过续期复活。
3. **注销** `POST /auth/logout`：幂等，重复注销返回相同成功结果，并下发过期 Cookie。
4. **过期**：TTL 到期后会话失效；后台访问时惰性清理。

### 并发会话上限

`security.max-concurrent-sessions`（默认 2）。同一账号超出上限时按**稳定策略淘汰最旧会话**；
按用户名加锁，并发登录/注销/续期不会串号或产生不可恢复状态。

### 失败原因可区分

会话类失败在响应体 `reason` 字段区分：`SESSION_MISSING` / `SESSION_EXPIRED` /
`SESSION_REVOKED` / `CSRF_TOKEN_MISSING` / `CSRF_TOKEN_MISMATCH`；
凭据类失败对外只有 `INVALID_CREDENTIALS`（内部日志区分账号是否存在）。

## 授权规则

- **默认拒绝**：`PolicyRegistry` 中无命中策略的路径一律拒绝。
- **资源级策略**：路径前缀 → 所需角色（最长前缀匹配），内置 `/api/user`→USER、
  `/api/admin`→ADMIN；运行时可通过 `setPolicy/removePolicy` 变更。
- **即时生效**：会话中不快照角色，每次请求实时查询 `UserDirectory` 与 `PolicyRegistry`，
  角色/资源/策略变更后已有会话的下一次请求即按新规则判定。
- **客户端提交的角色/权限不参与判定**：授权入口只接受 `username + path`，
  身份只取自服务端会话。
- **越权不暴露资源存在性**：已认证但越权一律返回 `404 {"error":"NOT_FOUND"}`，
  与资源不存在时的响应逐字节一致。

## 安全边界

- **CSRF**：`CsrfFilter`（最高优先级）对携带会话 Cookie 的状态变更请求
  （POST/PUT/DELETE/PATCH）强制校验 `X-CSRF-TOKEN` 头与会话绑定令牌（常量时间比较）。
  登录端点豁免（无会话可绑定，由 SameSite=Strict + 凭据校验防护）；
  会话已失效的请求放行给下游认证逻辑，保证重复注销等并发提交得到稳定结果。
- **Cookie 安全属性**：`HttpOnly`（防 XSS 窃取）、`SameSite=Strict`（跨站不携带）、
  `Path=/`、`Secure` 可配置（`security.cookie-secure`，生产开启）。
- **口令存储**：加盐 SHA-256 + 常量时间比较；账号不存在时执行等长计算，响应时间不可区分。
- **高风险操作**：`POST /api/user/transfer` 需有效会话 + USER 角色 + CSRF 令牌三重校验。

## 配置项（application.properties）

| 键 | 默认 | 说明 |
|---|---|---|
| `security.session-ttl-seconds` | 1800 | 会话 TTL（滑动续期） |
| `security.max-concurrent-sessions` | 2 | 同账号并发会话上限 |
| `security.cookie-secure` | false | 生产环境置 true |

## 验证方法

| 测试类 | 覆盖场景 |
|---|---|
| `SessionStoreTest` | 上限淘汰最旧、过期清理、续期、幂等注销、16 线程并发登录不串号且不超过上限 |
| `AuthServiceTest` | 登录成功、账号不存在与口令错误响应一致、失败原因可区分、幂等注销、并发登录+注销一致性 |
| `AuthorizationServiceTest` | 默认拒绝、角色判定、角色/策略变更即时生效、客户端角色不参与判定 |
| `WebFlowTest` | 全生命周期多入口一致性、Cookie 安全属性、越权=404、CSRF 缺失/错误/正确、并发重复登录与注销 |
| `SessionExpiryWebTest` | ttl=0 下过期会话返回 `SESSION_EXPIRED` 且不可续期复活 |

所有测试通过 SLF4J 打印关键输入（用户、路径、会话 ID）与判定依据（命中策略、
所需角色、实际角色、拒绝原因），`mvn test` 日志可直接审计。

### 手动验证示例

```bash
# 登录并保存 Cookie 与 CSRF 令牌
curl -i -c jar.txt -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pass"}'

# 访问 USER 资源 / 越权访问 ADMIN 资源（应为 404）
curl -b jar.txt localhost:8080/api/user/profile
curl -b jar.txt localhost:8080/api/admin/dashboard

# 高风险操作（无 CSRF 头应 403，带上后 200）
curl -b jar.txt -X POST localhost:8080/api/user/transfer
curl -b jar.txt -X POST localhost:8080/api/user/transfer -H "X-CSRF-TOKEN: <csrfToken>"
```
