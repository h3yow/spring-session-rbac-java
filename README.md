# spring-session-rbac-java

基于 Spring Boot Web 的会话认证、角色授权与高风险操作保护示例。不依赖 Spring Security，
核心逻辑（会话存储、认证、授权、CSRF）均为工程内实现，便于本地验证与审计。

## 快速开始

```bash
mvn test          # 运行全部单元/集成测试（38 个）
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

`security.max-concurrent-sessions`（默认 2）。同一账号超出上限时按**稳定策略淘汰最旧的活跃会话**
（创建时间升序、再按会话 ID 升序）；被挤掉的会话立即释放名额并转为带原因的墓碑（见下）。
按用户名加锁，并发登录/下线/续期不会串号或产生不可恢复状态。

## 自助会话管理

所有端点挂在 `/api/sessions/**` 下，与其他受保护资源完全同构：需要有效会话、`USER` 角色，
状态变更（POST）还需要与会话绑定的 CSRF 令牌。数据范围严格限定为**当前账号本人**。

1. **查看我的活跃会话** `GET /api/sessions`
   - 返回 `{"sessions":[...]}`，每项字段稳定：`sessionId` / `createdAt`（登录建立时间，ISO-8601）/
     `lastAccessAt`（最近一次已认证活动）/ `expiresAt` / `current`（是否为当前请求所用会话）。
   - 排序稳定：创建时间升序，时间相同按会话 ID 升序；只含本人的**活跃**会话
     （已下线、已过期的不出现），别人登录或注销不会改变本列表的数量、顺序或字段。
2. **定向下线一个会话** `POST /api/sessions/{sessionId}/terminate`
   - 下线立即生效：该会话立即从活跃列表与名额中消失，客户端下次用旧会话访问资源或续期即被拒。
   - 只能下线本人会话。目标不存在、属于他人、或越权访问，都返回与"资源不存在"逐字节一致的
     `404 {"error":"NOT_FOUND"}`，不泄露目标会话是否存在、归属于谁。幂等：重复下线已下线会话仍 200。
3. **一键下线其他会话** `POST /api/sessions/terminate-others`
   - 下线除当前会话外的本人全部会话，返回 `{"status":"OK","revoked":N}`；
     当前会话永远不受影响（重复执行 `revoked=0`），释放的名额立即可用于新登录。

### "我为什么被登出"：三种原因可区分（仅对本人、限保留期）

下线/注销不再立刻物理删除会话，而是保留 24 小时"墓碑"
（`SessionStore.DEFAULT_TOMBSTONE_TTL_SECONDS`，可调）。墓碑不占并发名额，
仅用于让持有真实会话 ID 的本人在资源访问、续期等**所有入口得到一致结论**：

| 实际原因 | 响应 `reason` |
|---|---|
| 本人调用注销，或在会话管理中下线（含从另一台设备发起） | `SESSION_REVOKED` |
| 登录太多、超过并发上限被新登录挤掉 | `SESSION_CAP_EVICTED` |
| 会话自然过期（TTL 到期，过期后另有一个保留宽限可分辨） | `SESSION_EXPIRED` |
| 没有 Cookie、ID 伪造、服务端从未签发，或墓碑保留期已过 | `SESSION_MISSING` |

**兼容边界（相对老行为会变化的点）**：
- 旧版本注销/被挤后记录立即删除，旧会话再访问一律 `SESSION_MISSING`；
  新版本在 24 小时保留期内会返回 `SESSION_REVOKED` 或 `SESSION_CAP_EVICTED`。保留期过后结果回到
  `SESSION_MISSING`，与从未存在过的伪造 ID 逐字节一致。
- `POST` 到一个已失效会话（如拿着旧会话调续期/下线）不再返回 CSRF 错误，而是放行到认证层，
  由认证层给出与 GET 资源相同的失效原因；活跃会话的 CSRF 强制校验保持不变。

**保持不变的不泄露约定**：
- 登录失败仍只有 `INVALID_CREDENTIALS`，账号不存在与口令错误逐字节一致；
- 越权访问与资源不存在仍逐字节一致返回 `404 NOT_FOUND`；
- 伪造/不存在的会话 ID 在所有入口都是同一个 `401 SESSION_MISSING`，
  无法借此探测任何账号或会话是否存在；墓碑可分辨性只对"服务端确实签发过该 ID"的持有人成立，
  而会话 ID 为 256 位 CSPRNG 随机值，不可猜测。

### 失败原因可区分

会话类失败在响应体 `reason` 字段区分：`SESSION_MISSING` / `SESSION_EXPIRED` /
`SESSION_REVOKED` / `SESSION_CAP_EVICTED` /
`CSRF_TOKEN_MISSING` / `CSRF_TOKEN_MISMATCH`；
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
| `SessionStoreTest` | 上限淘汰最旧（带 CAP_EVICTED 墓碑）、过期清理、续期、幂等注销、16 线程并发登录不串号且不超过上限、活跃列表排序/隔离、下线释放名额、属主校验、墓碑保留期后清除、最近活动时间 |
| `AuthServiceTest` | 登录成功、账号不存在与口令错误响应一致、四种会话失败原因可区分、幂等注销、并发登录+注销一致性（名额归零） |
| `AuthorizationServiceTest` | 默认拒绝、角色判定、角色/策略变更即时生效、客户端角色不参与判定 |
| `WebFlowTest` | 全生命周期多入口一致性、Cookie 安全属性、越权=404、CSRF 缺失/错误/正确、并发重复登录与注销 |
| `SessionExpiryWebTest` | ttl=0 下过期会话返回 `SESSION_EXPIRED` 且不可续期复活 |
| `SessionManagementWebTest` | 会话列表字段/排序/当前标记/账号隔离且不随他人活动抖动、定向下线立即生效与名额释放重占、一键下线其他会话、他人/伪造目标 404 逐字节一致、三种被登出原因跨资源/续期入口一致、伪造 ID 稳定 MISSING、12 线程登录/下线/刷新竞争不串号不超额 |
| `SessionExpiryManagementWebTest` | ttl=0 下过期原因在资源/续期/会话管理三入口一致，且与伪造 ID 的 MISSING 可区分 |

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

# 会话管理：查看当前账号的活跃会话（current=true 即本次请求使用的会话）
curl -b jar.txt localhost:8080/api/sessions

# 定向下线指定会话（替换 <otherSessionId> 为列表中的另一个 sessionId）
curl -b jar.txt -X POST localhost:8080/api/sessions/<otherSessionId>/terminate \
  -H "X-CSRF-TOKEN: <csrfToken>"

# 一键下线除当前会话外的所有其他会话
curl -b jar.txt -X POST localhost:8080/api/sessions/terminate-others \
  -H "X-CSRF-TOKEN: <csrfToken>"

# 被下线客户端再次访问：401 且 reason 可分辨（REVOKED / CAP_EVICTED / EXPIRED / MISSING）
curl -i -b other-jar.txt localhost:8080/api/user/profile
```
