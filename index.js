require('dotenv').config()

const fs = require('fs/promises')
const path = require('path')
const { Authflow } = require('prismarine-auth')
const { RealmAPI } = require('prismarine-realms')

const STATE_PATH = path.join(__dirname, 'state.json')
const AUTH_CACHE_DIR = path.join(__dirname, 'auth-cache')

const DEFAULT_MONITOR_TIMEOUT_MS = 15_000
const DEFAULT_RECOVERY_TIMEOUT_MS = 300_000

class AuthNeedsRefreshError extends Error {
  constructor(message = 'auth-cache の再生成が必要です。', details = {}) {
    super(message)
    this.name = 'AuthNeedsRefreshError'
    this.details = details
  }
}

function requiredEnv(name) {
  const value = process.env[name]
  if (!value) {
    throw new Error(`${name} が未設定です。.env を確認してください。`)
  }
  return value
}

function optionalIntEnv(name, fallback) {
  const value = process.env[name]
  if (!value) return fallback
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function getRealmLabel() {
  return `Realm ${requiredEnv('REALM_ID')}`
}

async function readState() {
  try {
    const raw = await fs.readFile(STATE_PATH, 'utf8')
    return JSON.parse(raw)
  } catch (err) {
    if (err.code === 'ENOENT') return null
    throw err
  }
}

async function writeState(state) {
  await fs.writeFile(STATE_PATH, JSON.stringify(state, null, 2), 'utf8')
}

async function withTimeout(promise, ms, label = '処理') {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${label} が ${ms}ms 以内に完了しませんでした。`))
        }, ms)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function sendDiscordNotification(webhookUrl, payload) {
  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Discord Webhook送信失敗: ${res.status} ${text}`)
  }
}

function pickTargetRealm(realms) {
  const realmId = requiredEnv('REALM_ID')
  const found = realms.find((r) => String(r.id) === String(realmId))

  if (!found) {
    throw new Error(`REALM_ID=${realmId} に一致する Realm が見つかりません。`)
  }

  return found
}

async function getOnlinePlayers(api, targetRealmId) {
  const raw = await api.rest.get('/activities/live/players')
  const servers = Array.isArray(raw?.servers) ? raw.servers : []
  const target = servers.find((s) => String(s.id) === String(targetRealmId))

  if (!target) {
    return {
      count: 0,
      players: [],
      full: false,
      raw,
    }
  }

  const players = Array.isArray(target.players) ? target.players : []

  return {
    count: players.length,
    players,
    full: !!target.full,
    raw,
  }
}

function buildPlayStatusPayload({ realmName, currentCount }) {
  return {
    username: 'Realms Monitor',
    embeds: [
      {
        title: `[${realmName}] プレイ状況通知`,
        description: `現在 ${currentCount} 人のプレイヤーがログインしています。`,
        color: 5763719,
        timestamp: new Date().toISOString(),
      },
    ],
  }
}

function buildAdminAuthPausedPayload({ realmLabel }) {
  return {
    username: 'Realms Monitor Admin',
    embeds: [
      {
        title: `[${realmLabel}] 認証エラー通知`,
        description:
          'auth-cache の更新が必要です。通常監視を一時停止しました。次回以降は復旧モードで認証コードを発行します。',
        color: 15158332,
        timestamp: new Date().toISOString(),
      },
    ],
  }
}

function buildAdminAuthChallengePayload({
  realmLabel,
  verificationUri,
  userCode,
}) {
  return {
    username: 'Realms Monitor Admin',
    embeds: [
      {
        title: `[${realmLabel}] 認証復旧コード`,
        description: [
          'authPaused=true のため、復旧モードで対話認証を試行しています。',
          '',
          `Open this URL: ${verificationUri}`,
          `Enter this code: ${userCode}`,
          '',
          '別端末のブラウザでも認証できます。この実行中に完了すると、自動で復旧処理を進めます。',
        ].join('\n'),
        color: 15158332,
        timestamp: new Date().toISOString(),
      },
    ],
  }
}

function buildAdminRecoveredPayload({ realmName, currentCount, secretsUpdated }) {
  return {
    username: 'Realms Monitor Admin',
    embeds: [
      {
        title: `[${realmName}] 認証復旧通知`,
        description: [
          '認証が復旧しました。通常監視を再開します。',
          `現在人数: ${currentCount} 人`,
          secretsUpdated
            ? 'auth-cache を GitHub Secrets に書き戻しました。'
            : 'auth-cache の GitHub Secrets 書き戻しはスキップしました。',
        ].join('\n'),
        color: 5763719,
        timestamp: new Date().toISOString(),
      },
    ],
  }
}

async function bundleAuthCacheDir(cacheDir) {
  let entries = []
  try {
    entries = await fs.readdir(cacheDir, { withFileTypes: true })
  } catch (err) {
    if (err.code === 'ENOENT') return null
    throw err
  }

  const files = {}
  for (const entry of entries) {
    if (!entry.isFile()) continue
    const filePath = path.join(cacheDir, entry.name)
    const buf = await fs.readFile(filePath)
    files[entry.name] = buf.toString('base64')
  }

  if (Object.keys(files).length === 0) return null

  const json = JSON.stringify({ files })
  return Buffer.from(json, 'utf8').toString('base64')
}

async function updateGitHubAuthCacheSecretIfConfigured() {
  const repo = process.env.GH_REPO
  const token = process.env.GH_SECRETS_WRITE_TOKEN
  const secretName =
    process.env.GH_AUTH_CACHE_SECRET_NAME || 'PRISMARINE_AUTH_CACHE_BUNDLE'

  if (!repo || !token) {
    return false
  }

  const bundle = await bundleAuthCacheDir(AUTH_CACHE_DIR)
  if (!bundle) {
    throw new Error('auth-cache ディレクトリに保存対象ファイルがありません。')
  }

  const sodium = require('libsodium-wrappers')
  await sodium.ready

  const [owner, repoName] = repo.split('/')
  if (!owner || !repoName) {
    throw new Error(`GH_REPO="${repo}" の形式が不正です。owner/repo 形式で指定してください。`)
  }

  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2026-03-10',
  }

  const pkRes = await fetch(
    `https://api.github.com/repos/${owner}/${repoName}/actions/secrets/public-key`,
    {
      method: 'GET',
      headers,
    }
  )

  if (!pkRes.ok) {
    const text = await pkRes.text()
    throw new Error(`GitHub public key 取得失敗: ${pkRes.status} ${text}`)
  }

  const pkJson = await pkRes.json()
  const keyId = pkJson.key_id
  const key = pkJson.key

  const binkey = sodium.from_base64(key, sodium.base64_variants.ORIGINAL)
  const binsec = sodium.from_string(bundle)
  const encBytes = sodium.crypto_box_seal(binsec, binkey)
  const encryptedValue = sodium.to_base64(
    encBytes,
    sodium.base64_variants.ORIGINAL
  )

  const putRes = await fetch(
    `https://api.github.com/repos/${owner}/${repoName}/actions/secrets/${secretName}`,
    {
      method: 'PUT',
      headers: {
        ...headers,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        encrypted_value: encryptedValue,
        key_id: keyId,
      }),
    }
  )

  if (!putRes.ok) {
    const text = await putRes.text()
    throw new Error(`GitHub secret 更新失敗: ${putRes.status} ${text}`)
  }

  return true
}

async function attemptMonitoring({ state }) {
  const adminWebhookUrl = requiredEnv('DISCORD_ADMIN_WEBHOOK_URL')
  const monitorTimeoutMs = optionalIntEnv(
    'MONITOR_TIMEOUT_MS',
    DEFAULT_MONITOR_TIMEOUT_MS
  )
  const recoveryTimeoutMs = optionalIntEnv(
    'RECOVERY_TIMEOUT_MS',
    DEFAULT_RECOVERY_TIMEOUT_MS
  )

  const pausedAlready = !!state?.authPaused
  const timeoutMs = pausedAlready ? recoveryTimeoutMs : monitorTimeoutMs

  let interactiveAuthRequested = false
  let lastCodeInfo = null
  let challengeNotificationPromise = null

  const realmLabel = getRealmLabel()

  // 通常モードでも callback を付けてコンソール出力を抑止
  // ただし通常モードでは Discord へコード送信しない
  const codeCallback = (codeInfo) => {
    interactiveAuthRequested = true
    lastCodeInfo = codeInfo

    if (pausedAlready && !challengeNotificationPromise) {
      challengeNotificationPromise = sendDiscordNotification(
        adminWebhookUrl,
        buildAdminAuthChallengePayload({
          realmLabel,
          verificationUri: codeInfo.verification_uri || codeInfo.verificationUri,
          userCode: codeInfo.user_code || codeInfo.userCode,
        })
      ).catch((err) => {
        console.error('[WARN] 管理者向け認証通知送信失敗')
        console.error(err)
      })
    }
  }

  const authflow = new Authflow(
    'local-realms-watch',
    AUTH_CACHE_DIR,
    undefined,
    codeCallback
  )

  const api = RealmAPI.from(authflow, 'bedrock')

  // 通常モード:
  // device code callback が呼ばれたら即 auth エラー扱い
  // 復旧モード:
  // 5分待って認証完了を待つ
  const realmsPromise = api.getRealms()
  const realms = await withTimeout(
    Promise.race([
      realmsPromise,
      !pausedAlready
        ? new Promise((_, reject) => {
            const interval = setInterval(() => {
              if (interactiveAuthRequested) {
                clearInterval(interval)
                reject(
                  new AuthNeedsRefreshError(
                    '通常監視中に対話認証へ遷移しました。'
                  )
                )
              }
            }, 200)
          })
        : realmsPromise,
    ]),
    timeoutMs,
    '認証/Realm一覧取得'
  )

  if (challengeNotificationPromise) {
    await challengeNotificationPromise
  }

  const targetRealm = pickTargetRealm(realms)
  const result = await withTimeout(
    getOnlinePlayers(api, targetRealm.id),
    timeoutMs,
    'ログイン人数取得'
  )

  return {
    targetRealm,
    result,
    interactiveAuthRequested,
    pausedAlready,
  }
}

async function main() {
  const playWebhookUrl = requiredEnv('DISCORD_WEBHOOK_URL')
  const adminWebhookUrl = requiredEnv('DISCORD_ADMIN_WEBHOOK_URL')

  const previousState = await readState()

  try {
    const { targetRealm, result, interactiveAuthRequested, pausedAlready } =
      await attemptMonitoring({ state: previousState })

    // authPaused=true の復旧モードで成功した場合
    if (pausedAlready) {
      let secretsUpdated = false

      if (interactiveAuthRequested) {
        try {
          secretsUpdated = await updateGitHubAuthCacheSecretIfConfigured()
        } catch (err) {
          console.error('[WARN] GitHub Secrets の auth-cache 更新に失敗しました。')
          console.error(err)
        }
      }

      await writeState({
        previousCount: result.count,
        authPaused: false,
        authFailedAt: previousState?.authFailedAt ?? null,
        authRecoveredAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      })

      await sendDiscordNotification(
        adminWebhookUrl,
        buildAdminRecoveredPayload({
          realmName: targetRealm.name,
          currentCount: result.count,
          secretsUpdated,
        })
      )

      console.log('[INFO] 認証が復旧したため、通常監視を再開します。')
      console.log('[INFO] state.json を更新しました。')
      process.exit(0)
    }

    // 初回実行
    if (!previousState) {
      console.log('[INFO] state.json が無いため初回実行とみなし、保存のみ行います。')
      await writeState({
        previousCount: result.count,
        authPaused: false,
        authFailedAt: null,
        authRecoveredAt: null,
        updatedAt: new Date().toISOString(),
      })
      process.exit(0)
    }

    const previousCount = Number(previousState.previousCount ?? 0)
    const currentCount = result.count

    console.log('\n=== Comparison ===')
    console.log({
      previousCount,
      currentCount,
      increased: currentCount > previousCount,
    })

    if (currentCount > previousCount) {
      console.log('[INFO] 人数が増加したため Discord に通知します。')

      await sendDiscordNotification(
        playWebhookUrl,
        buildPlayStatusPayload({
          realmName: targetRealm.name,
          currentCount,
        })
      )

      console.log('[INFO] Discord 通知完了')
    } else {
      console.log('[INFO] 人数増加なしのため通知しません。')
    }

    await writeState({
      previousCount: currentCount,
      authPaused: false,
      authFailedAt: previousState.authFailedAt ?? null,
      authRecoveredAt: previousState.authRecoveredAt ?? null,
      updatedAt: new Date().toISOString(),
    })

    console.log('[INFO] state.json を更新しました。')
    process.exit(0)
  } catch (err) {
    // 通常モードで auth-cache がダメなとき
    if (!previousState?.authPaused && err instanceof AuthNeedsRefreshError) {
      await sendDiscordNotification(
        adminWebhookUrl,
        buildAdminAuthPausedPayload({
          realmLabel: getRealmLabel(),
        })
      )

      await writeState({
        previousCount: Number(previousState?.previousCount ?? 0),
        authPaused: true,
        authFailedAt: new Date().toISOString(),
        authRecoveredAt: previousState?.authRecoveredAt ?? null,
        updatedAt: new Date().toISOString(),
      })

      console.log('[INFO] 認証エラーのため監視を停止状態にしました。')
      process.exit(0)
    }

    // authPaused=true の復旧モードで今回の待機中に認証完了しなかった
    if (previousState?.authPaused) {
      console.log(
        '[INFO] authPaused=true のため、今回の復旧待機時間内では認証完了しませんでした。'
      )
      process.exit(0)
    }

    console.error('\n[ERROR]')
    console.error(err)
    process.exit(1)
  }
}

main()