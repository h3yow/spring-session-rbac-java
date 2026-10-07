# spring-session-rbac-java

基于 Spring Boot Web 的会话认证、角色授权与高风险操作保护示例。不依赖 Spring Security，
核心逻辑（会话存储、认证、授权、CSRF）均为工程内实现，便于本地验证与审计。

## 快速开始

```bash
mvn test          # 运行全部单元/集成测试（36 个）
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

`security.max-concurrent-sessions`（默认 2）。同一账号超出上限时按**稳定策略淘汰最旧会话**
（按创建时间升序、会话 ID 兜底）；按用户名加锁，并发登录/注销/续期/下线不会串号或产生不可恢复状态。
被挤掉的会话立即失效并**释放名额**，用户重新登录即可正常占上名额。

### 失败原因可区分

会话类失败在响应体 `reason` 字段区分：`SESSION_MISSING` / `SESSION_EXPIRED` /
`SESSION_REVOKED` / `SESSION_CAP_EVICTED` / `CSRF_TOKEN_MISSING` / `CSRF_TOKEN_MISMATCH`；
凭据类失败对外只有 `INVALID_CREDENTIALS`（内部日志区分账号是否存在）。

旧会话再次访问受保护资源（`/api/**`）或调用续期 `POST /auth/renew` 时，两个入口给出
**一致**的结论，解释"我到底为什么被登出"：

| 情况 | reason |
|---|---|
| 本人主动注销 `/auth/logout`，或通过会话管理定向下线/一键下线 | `SESSION_REVOKED` |
| 同账号登录太多，被新登录按最旧优先策略挤掉 | `SESSION_CAP_EVICTED` |
| TTL 自然到期 | `SESSION_EXPIRED` |
| 根本不存在 / 伪造的会话 ID（与"没带 Cookie"一致） | `SESSION_MISSING` |

终止原因记录在服务端墓碑（tombstone）中并保留 24 小时；终止是一次性终态，
先发生的终止保留原因（例如已自然过期后并发到达的注销不会把结论改写成 REVOKED），
且任何终态都不能通过续期复活。墓碑保留期过后，旧 ID 退化为 `SESSION_MISSING`。

## 用户自助会话管理

以下端点位于 `/api/user/**`：要求**有效会话 + USER 角色 + CSRF 令牌**（GET 不需要 CSRF），
身份只取自服务端会话。

1. **查看当前活跃会话** `GET /api/user/sessions`
   - 返回 `{"sessions":[...]}`，每条含 `id`、`createdAt`（建立时间）、
     `lastActivityAt`（最近一次访问受保护资源/续期的时间）、`current`（是否为当前会话）；
   - 只包含**当前用户自己**的会话；按 `createdAt` 升序、`id` 兜底稳定排序，
     其他账号的登录/注销不会改变本列表的成员与顺序；
   - 无法通过该入口感知任何其他账号或其他人是否有会话。
2. **定向下线** `POST /api/user/sessions/{id}/revoke`（需 CSRF 头）
   - 立即终止本人指定会话并释放名额：被下线客户端下一次访问/续期即得到 `SESSION_REVOKED`；
   - 目标属于别人、目标不存在或已是终态：一律 `404 {"error":"NOT_FOUND"}`，
     与"越权=资源不存在"的既有约定逐字节一致，**不泄露目标会话是否存在、属于谁**；
   - 重复下线已终止目标返回 404（该目标已不是可操作资源），这不是注销端点的幂等场景。
3. **一键下线其他会话** `POST /api/user/sessions/revoke-others`（需 CSRF 头）
   - 终止除当前会话外本人的全部活跃会话，返回 `{"status":"OK","revokedCount":N}`；
   - 当前会话保留且立即可用；重复调用幂等（第二次 `revokedCount=0`）。

下线与并发上限严格对齐：下线/挤掉都在该账号的锁内完成"活跃表移除 + 名额释放 + 写入带原因墓碑"，
并发地登录、下线、续期不会张冠李戴或误伤他人会话，名下会话数始终与上限对得上。

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

### 与老行为的兼容边界

**结果会变化的地方（有意的行为增强）：**
- 本人**主动注销后**，再拿着旧会话访问/续期，过去返回 `SESSION_MISSING`，
  现在返回 `SESSION_REVOKED`，以便和"被挤掉/过期/不存在"区分；
  `/auth/logout` 本身仍幂等、仍返回 `200` 并下发过期 Cookie，重复注销行为不变。
- 被并发上限挤掉的旧会话，过去与"已注销"不可区分，现在明确返回 `SESSION_CAP_EVICTED`。
- 会话终止后在服务端保留 24h 墓碑用于原因判定（内存实现，重启即清空）；
  24h 后旧 ID 重新退化为 `SESSION_MISSING`。

**保持不变的不泄露约定：**
- 不存在/伪造的会话 ID 与未携带 Cookie 完全一致：`401 SESSION_MISSING`，
  不区分"从未存在"与"墓碑已过期"；
- 登录失败仍统一 `INVALID_CREDENTIALS`，不泄露账号是否存在；
- 已认证越权、下线他人会话、下线不存在的会话，仍一律 `404 {"error":"NOT_FOUND"}`，
  与资源不存在逐字节一致；
- 会话列表/下线操作只接受服务端会话中的本人身份，客户端提交的用户名/角色一律不参与判定。

### 其他安全措施

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
| `SessionStoreTest` | 上限淘汰最旧（墓碑原因 CAP_EVICTED）、过期清理、续期、幂等注销、16 线程并发登录不串号且不超过上限 |
| `AuthServiceTest` | 登录成功、账号不存在与口令错误响应一致、失败原因可区分（REVOKED/CAP_EVICTED/EXPIRED/MISSING）、幂等注销、并发登录+注销终态原因准确 |
| `AuthorizationServiceTest` | 默认拒绝、角色判定、角色/策略变更即时生效、客户端角色不参与判定 |
| `WebFlowTest` | 全生命周期多入口一致性、Cookie 安全属性、越权=404、CSRF 缺失/错误/正确、并发重复登录与注销 |
| `SessionExpiryWebTest` | ttl=0 下过期会话返回 `SESSION_EXPIRED` 且不可续期复活 |
| `SessionManagementServiceTest` | 列表只含本人且稳定排序/当前标记、定向下线立即生效并释放名额、一键下线其他、跨账号操作与不存在不可区分 |
| `SessionStoreConcurrencyTest` | 登录/下线/续期混合并发不串号不越上限、下线名额可被并发重新占用、竞争下首次终止原因保留 |
| `SessionManagementWebTest` | 端到端：会话列表、定向下线（含 CSRF）、一键下线、名额释放、越权下线=404、三种被登出原因在资源/续期入口一致、伪造会话稳定 MISSING、越权=404 不回归 |

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

### 会话管理手动验证

```bash
# 1) 同一账号登录两次（用不同 cookie jar 模拟两个客户端）
curl -i -c a.txt -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pass"}'
curl -i -c b.txt -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pass"}'

# 2) 用 b 查看会话列表（两条；b 的 current=true，含建立/最近活动时间）
curl -s -b b.txt localhost:8080/api/user/sessions | jq .

# 3) 用 b 一键下线其他会话（a 被终止；响应 revokedCount=1）
#    CSRF 令牌取自各自登录响应体的 csrfToken 字段
curl -s -b b.txt -X POST localhost:8080/api/user/sessions/revoke-others \
  -H "X-CSRF-TOKEN: <csrfToken-of-b>"
# a 再访问资源 / 续期，均为 401 且 reason=SESSION_REVOKED
curl -s -b a.txt localhost:8080/api/user/profile
curl -s -b a.txt -X POST localhost:8080/auth/renew -H "X-CSRF-TOKEN: x"

# 4) 被新登录挤掉：连登第三次（默认上限 2），最旧会话再访问得到 SESSION_CAP_EVICTED
curl -s -b a.txt localhost:8080/api/user/profile

# 5) 自然过期：以 security.session-ttl-seconds=0 启动后登录，旧会话得到 SESSION_EXPIRED
# 6) 伪造会话 / 尝试下线他人会话：分别得到 401 SESSION_MISSING 与 404 {"error":"NOT_FOUND"}
curl -s -H 'Cookie: SESSIONID=forged' localhost:8080/api/user/profile
curl -s -b b.txt -X POST localhost:8080/api/user/sessions/forged-id/revoke \
  -H "X-CSRF-TOKEN: <csrfToken-of-b>"
```

自动验证：`mvn test`（重点看 `SessionManagementServiceTest`、
`SessionStoreConcurrencyTest`、`SessionManagementWebTest` 三个类的日志，
含会话 ID、归属、下线数量、终态原因等关键输入与判定依据）。
