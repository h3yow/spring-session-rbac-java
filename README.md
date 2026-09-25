# spring-session-rbac-java

基于 Spring Boot 3 / Java 21 的会话认证、角色授权与高风险操作保护示例，可本地验证。

## 架构概览

```
请求 → AuthSessionFilter(@Order 1) → CsrfFilter(@Order 2) → Controller → PolicyService
```

| 组件 | 职责 |
| --- | --- |
| `AuthService` | 登录（BCrypt 口令校验 + 会话建立）、注销 |
| `SessionManager` | 会话创建/校验/滑动续期/注销，并发上限与稳定淘汰 |
| `PolicyService` | 默认拒绝的资源→角色策略，运行时更新即时生效 |
| `AuthSessionFilter` | 解析会话 Cookie、校验续期，失败返回可区分原因 |
| `CsrfFilter` | 状态变更请求校验会话绑定 CSRF 令牌（常量时间比较） |
| `SecurityExceptionHandler` | 统一稳定错误响应 |

## 会话生命周期

1. **建立**：`POST /api/auth/login`（`{"username","password"}`）。成功后下发
   `Set-Cookie: SESSION=...; Path=/; HttpOnly; SameSite=Strict`（`Secure` 可配置），
   响应体返回 `csrfToken` 与 `expiresAt`。每次登录生成全新会话 id，防止会话固定。
2. **续期**：每次携带会话的受保护请求自动滑动续期（TTL 由 `app.security.session-ttl` 配置）。
3. **注销**：`POST /api/auth/logout`（需 CSRF 令牌），幂等；服务端标记 revoked 并清除 Cookie。
4. **并发上限**：`app.security.max-concurrent-sessions`（默认 2）。超出时按稳定策略
   淘汰创建时间最早的活跃会话；创建过程整体加锁，并发登录不会突破上限。

### 失败原因（可区分）

| 场景 | HTTP | 错误码 |
| --- | --- | --- |
| 无会话 Cookie | 401 | `SESSION_MISSING` |
| 未知会话 id | 401 | `SESSION_INVALID` |
| 会话已过期 | 401 | `SESSION_EXPIRED` |
| 会话已注销/被淘汰 | 401 | `SESSION_REVOKED` |
| 缺少 CSRF 令牌 | 403 | `CSRF_TOKEN_MISSING` |
| CSRF 令牌不匹配 | 403 | `CSRF_TOKEN_MISMATCH` |
| 凭据错误 | 401 | `INVALID_CREDENTIALS` |
| 越权或资源不存在 | 404 | `RESOURCE_NOT_AVAILABLE` |

## 授权规则

- **默认拒绝**：无策略的资源一律拒绝。
- **资源级策略**：`PolicyService` 维护 资源路径 → 所需角色 映射，初始：
  `/api/resources/user`→USER，`/api/resources/admin`→ADMIN，`/api/resources/transfer`→USER。
- **即时生效**：角色在每次判定时从 `UserDirectory` 实时读取，策略映射可运行时修改；
  已有会话不做任何缓存快照，立即按新策略判定。
- **客户端信息不参与授权**：身份只取自服务端会话，请求头/参数中的角色声明被忽略。
- **不泄露资源存在性**：越权与资源不存在返回相同的 404 + `RESOURCE_NOT_AVAILABLE`。

## 安全边界

- 口令以 BCrypt 哈希存储；未知用户也执行哑哈希比较，且与口令错误返回完全相同的
  响应（状态码与响应体一致），不泄露账号是否存在。
- 会话 id 与 CSRF 令牌为 256 位安全随机值；CSRF 比较使用常量时间算法。
- 会话状态仅存服务端，Cookie 仅含不透明 id（HttpOnly + SameSite=Strict）。
- 高风险操作（`POST /api/resources/transfer`）要求：有效会话 + CSRF 令牌 + USER 角色
  + `Idempotency-Key` 头；同一幂等键的重复/并发提交只执行一次并返回相同结果。
- 注销/淘汰为幂等终态，竞争条件下后续访问稳定失败为 `SESSION_REVOKED`，不产生串号。

## 本地验证

```bash
mvn test
```

测试覆盖（共 25 例，日志打印关键输入与判定依据）：

- `SessionLifecycleTest`：登录成功、凭据失败不可区分、会话 id 轮换、过期、注销/未知
  会话原因区分、滑动续期、并发上限淘汰最旧、16 线程并发登录不突破上限、重复注销幂等。
- `PolicyServiceTest`：默认拒绝、角色允许/拒绝、策略变更即时生效、角色变更即时生效、
  越权与资源不存在不可区分。
- `AuthFlowWebTest`（MockMvc 端到端）：Cookie 安全属性、无会话拒绝、合法访问、
  越权 404、客户端自报角色被忽略、CSRF 缺失/不匹配/通过、8 线程并发重复提交幂等、
  注销后复用拒绝、注销后并发访问状态一致。

手动验证（可选）：

```bash
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080
curl -i -c jar.txt -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pass"}'
curl -b jar.txt localhost:8080/api/resources/user
curl -b jar.txt -X POST localhost:8080/api/resources/transfer \
  -H 'Content-Type: application/json' -H 'X-CSRF-TOKEN: <登录响应中的 csrfToken>' \
  -H 'Idempotency-Key: tx-1' -d '{"toAccount":"bob","amount":100}'
```

内置账号：`alice/alice-pass`（USER）、`bob/bob-pass`（USER+ADMIN）。

## 配置项（`app.security.*`）

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `session-ttl` | `30m` | 会话空闲过期时间（滑动续期） |
| `max-concurrent-sessions` | `2` | 同一账号并发会话上限 |
| `cookie-name` | `SESSION` | 会话 Cookie 名 |
| `cookie-secure` | `false` | 是否加 `Secure` 属性（生产应置 true） |
| `csrf-header-name` | `X-CSRF-TOKEN` | CSRF 令牌请求头名 |
