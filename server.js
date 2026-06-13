// ── Umi Dashboard · API server ────────────────────────────────────────────────
// Express API only — Vite (port 4000) serves the frontend and proxies /api/* here.
// Supabase (KDS tickets + device_sessions) is queried directly from the browser.
//
// Usage:  npm run dev        (starts both API + Vite with concurrently)
// ─────────────────────────────────────────────────────────────────────────────

import path    from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes, createHash, scryptSync, timingSafeEqual } from 'node:crypto'
import express from 'express'
import { Prisma, PrismaClient } from '@prisma/client'
import { buildModuleAvailability, PRODUCT_ACTIVE_STATUSES } from './src/lib/module-registry.js'
import nodemailer from 'nodemailer'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const prisma    = new PrismaClient()
const app       = express()
const DEV_ORIGIN = `http://localhost:${process.env.VITE_DEV_PORT || '4000'}`
const DEPLOYMENT_ORIGIN = process.env.DASHBOARD_ALLOWED_ORIGIN
  || process.env.APP_URL
  || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : '')
const ALLOWED_ORIGIN = DEPLOYMENT_ORIGIN || DEV_ORIGIN

app.use(express.json())

function hashLocalPassword(password, salt = randomBytes(16).toString('hex')) {
  return {
    salt,
    hash: scryptSync(password, salt, 64).toString('hex'),
  }
}

function verifyLocalPassword(password, salt, expectedHash) {
  const actual = Buffer.from(hashLocalPassword(password, salt).hash, 'hex')
  const expected = Buffer.from(expectedHash, 'hex')
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

function createMailTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD,
    },
  })
}

// CORS — allow the configured Vite dev server to call the API.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin',  ALLOWED_ORIGIN)
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS')
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-UMI-User-ID,X-KDS-Device-Token,apikey')
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})

// Chrome DevTools probe — silence the 404
app.get('/.well-known/appspecific/com.chrome.devtools.json', (_req, res) => res.json({}))

// Health check — no auth, pings DB to confirm full stack is alive
app.get('/api/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`
    res.json({ ok: true, ts: Date.now() })
  } catch (err) {
    res.status(503).json({ ok: false, error: err.message })
  }
})

// ── KDS device heartbeat ──────────────────────────────────────────────────────
// iPad calls this every 5 s while active. No auth — the device ID is the credential.
// In-memory only: resets on server restart, which is fine for local dev.
const _kdsHeartbeats = new Map() // deviceId → { lastSeen, deviceName, stationId, ip }

app.post('/api/kds/heartbeat', async (req, res) => {
  const { device_id, device_name, station_id, station_name } = req.body || {}
  if (!device_id) return res.status(400).json({ error: 'device_id required' })
  try {
    const rows = await prisma.$queryRaw`SELECT is_active FROM kds.device_sessions WHERE id = ${device_id}::uuid LIMIT 1`
    if (rows[0] && rows[0].is_active !== true) return res.status(403).json(kdsRevokedPayload())
    if (!rows[0]) return res.status(404).json({ error: 'device_session_not_found' })
  } catch (err) {
    console.error('[kds heartbeat]', err.message)
    return res.status(503).json({ error: 'service_unavailable' })
  }
  _kdsHeartbeats.set(device_id, {
    deviceId:    device_id,
    deviceName:  device_name  || 'KDS',
    stationId:   station_id   || null,
    stationName: station_name || null,
    lastSeen:    Date.now(),
    ip:          req.ip,
  })
  res.json({ ok: true, ts: Date.now() })
})

// Returns all known heartbeats. Dashboard merges this with cloud device list.
app.get('/api/kds/heartbeats', (_req, res) => {
  const SLOW_THRESHOLD_MS = 10_000
  const OFFLINE_THRESHOLD_MS = 20_000 // 4 missed 5-s pings = offline
  const now = Date.now()
  const result = Array.from(_kdsHeartbeats.values()).map(h => {
    const ageMs = now - h.lastSeen
    return {
      ...h,
      status: ageMs < SLOW_THRESHOLD_MS ? 'live' : ageMs < OFFLINE_THRESHOLD_MS ? 'slow' : 'offline',
      secondsAgo: Math.floor(ageMs / 1000),
    }
  })
  res.json(result)
})

app.post('/api/auth/local/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase()
  const password = String(req.body.password || '')
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' })

  try {
    const rows = await prisma.$queryRaw`
      SELECT
        c.user_id::text AS "userId",
        c.password_salt AS "passwordSalt",
        c.password_hash AS "passwordHash",
        u.email,
        u.display_name AS "displayName"
      FROM dashboard_compat.local_user_credentials AS c
      JOIN platform.users AS u
        ON u.id = c.user_id
      WHERE lower(c.username) = ${username}
      LIMIT 1
    `
    const credential = rows[0]
    if (!credential || !verifyLocalPassword(password, credential.passwordSalt, credential.passwordHash)) {
      return res.status(401).json({ error: 'Credenciales incorrectas' })
    }

    const tenants = await prisma.$queryRaw`
      SELECT
        t.id::text,
        t.slug,
        t.name,
        array_agg(r.key ORDER BY r.key) FILTER (WHERE r.key IS NOT NULL) AS roles
      FROM platform.tenant_memberships AS tm
      JOIN platform.tenants AS t
        ON t.id = tm.tenant_id
      LEFT JOIN platform.membership_roles AS mr
        ON mr.membership_id = tm.id
      LEFT JOIN platform.roles AS r
        ON r.id = mr.role_id
      WHERE tm.user_id = ${credential.userId}::uuid
        AND tm.status = 'active'
      GROUP BY t.id, t.slug, t.name
      ORDER BY t.slug
    `

    return res.json({
      session: {
        user: {
          id: credential.userId,
          email: credential.email,
          displayName: credential.displayName,
        },
        tenants,
        provider: 'local',
      },
    })
  } catch (err) {
    console.error('[local auth login]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.post('/api/auth/local/forgot-password', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase()
  if (!email) return res.status(400).json({ error: 'email is required' })

  try {
    const rows = await prisma.$queryRaw`
      SELECT u.id::text AS "userId", u.email, u.display_name AS "displayName"
      FROM platform.users AS u
      JOIN dashboard_compat.local_user_credentials AS c ON c.user_id = u.id
      WHERE lower(u.email) = ${email}
      LIMIT 1
    `
    // Always respond 200 to avoid user enumeration
    if (!rows[0]) return res.json({ ok: true })

    const user = rows[0]
    const token = randomBytes(32).toString('hex')
    const tokenHash = createHash('sha256').update(token).digest('hex')
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000) // 15 min

    await prisma.$executeRaw`
      INSERT INTO dashboard_compat.password_reset_tokens (user_id, token_hash, expires_at)
      VALUES (${user.userId}::uuid, ${tokenHash}, ${expiresAt})
    `

    const appUrl = process.env.APP_URL || 'http://localhost:4010'
    const resetLink = `${appUrl}/reset-password?token=${token}`

    const transporter = createMailTransport()
    await transporter.sendMail({
      from: `"Umi Dashboard" <${process.env.EMAIL_FROM || 'hola@umiconsulting.co'}>`,
      to: user.email,
      subject: 'Reestablecer contraseña · Umi Dashboard',
      text: `Hola ${user.displayName || user.email},\n\nRecibimos una solicitud para reestablecer tu contraseña.\n\nEnlace: ${resetLink}\n\nEste enlace expira en 15 minutos. Si no solicitaste esto, puedes ignorar este correo.\n\nUmi Consulting`,
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px 24px;color:#1a1a1a">
          <div style="font-size:18px;font-weight:700;margin-bottom:24px">umi <em style="color:#888">· dash</em></div>
          <h2 style="font-size:20px;font-weight:700;margin:0 0 8px">Reestablecer contraseña</h2>
          <p style="color:#555;margin:0 0 24px">Hola ${user.displayName || user.email}, recibimos una solicitud para reestablecer la contraseña de tu cuenta.</p>
          <a href="${resetLink}" style="display:inline-block;background:#1a1a1a;color:#fff;text-decoration:none;padding:12px 24px;border-radius:10px;font-weight:600;font-size:15px">Reestablecer contraseña</a>
          <p style="color:#888;font-size:12px;margin-top:24px">Este enlace expira en 15 minutos. Si no solicitaste esto, puedes ignorar este correo.</p>
        </div>
      `,
    })

    return res.json({ ok: true })
  } catch (err) {
    console.error('[forgot-password]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.post('/api/auth/local/reset-password', async (req, res) => {
  const token    = String(req.body.token    || '').trim()
  const password = String(req.body.password || '')
  if (!token || !password) return res.status(400).json({ error: 'token and password are required' })
  if (password.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' })

  try {
    const tokenHash = createHash('sha256').update(token).digest('hex')
    const rows = await prisma.$queryRaw`
      SELECT id::text, user_id::text AS "userId", expires_at AS "expiresAt", used_at AS "usedAt"
      FROM dashboard_compat.password_reset_tokens
      WHERE token_hash = ${tokenHash}
      LIMIT 1
    `
    const record = rows[0]
    if (!record) return res.status(400).json({ error: 'Enlace inválido o expirado' })
    if (record.usedAt) return res.status(400).json({ error: 'Este enlace ya fue utilizado' })
    if (new Date(record.expiresAt) < new Date()) return res.status(400).json({ error: 'El enlace ha expirado' })

    const { salt, hash } = hashLocalPassword(password)
    await prisma.$executeRaw`
      UPDATE dashboard_compat.local_user_credentials
      SET password_salt = ${salt}, password_hash = ${hash}, updated_at = now()
      WHERE user_id = ${record.userId}::uuid
    `
    await prisma.$executeRaw`
      UPDATE dashboard_compat.password_reset_tokens
      SET used_at = now()
      WHERE id = ${record.id}::uuid
    `

    return res.json({ ok: true })
  } catch (err) {
    console.error('[reset-password]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── helpers ───────────────────────────────────────────────────────────────────

function fmt(centavos) {
  return new Intl.NumberFormat('es-MX', {
    style: 'currency', currency: 'MXN',
    minimumFractionDigits: 0, maximumFractionDigits: 0,
  }).format((centavos ?? 0) / 100)
}

async function getTenant(slug) {
  return prisma.tenant.findUnique({ where: { slug } })
}

async function getTenantById(tenantId) {
  if (!tenantId) return null
  try {
    const rows = await prisma.$queryRaw`
      SELECT id::text, slug, name, timezone
      FROM platform.tenants
      WHERE id = ${tenantId}::uuid
      LIMIT 1
    `
    return rows[0] ? {
      id: rows[0].id,
      slug: rows[0].slug,
      name: rows[0].name,
      timezone: rows[0].timezone,
    } : null
  } catch {
    return null
  }
}

async function getLocationForTenant(tenantId, requestedLocationId = null) {
  if (!tenantId) return null
  const rows = requestedLocationId
    ? await prisma.$queryRaw`
        SELECT id::text, slug, name
        FROM platform.locations
        WHERE tenant_id = ${tenantId}::uuid
          AND id = ${requestedLocationId}::uuid
          AND status = 'active'
        LIMIT 1
      `
    : await prisma.$queryRaw`
        SELECT id::text, slug, name
        FROM platform.locations
        WHERE tenant_id = ${tenantId}::uuid
          AND status = 'active'
        ORDER BY
          CASE WHEN lower(name) = 'chapultepec' THEN 0 ELSE 1 END,
          created_at ASC
        LIMIT 1
      `
  return rows[0] ?? null
}

async function getDashboardContext(slug, requestedLocationId = null) {
  const tenant = await getTenant(slug)
  if (!tenant) return null

  const location = await getLocationForTenant(tenant.id, requestedLocationId)
  return {
    tenant,
    tenantId: tenant.id,
    locationId: location?.id ?? null,
    businessId: tenant.id,
    cashTenantId: tenant.id,
    cashSlug: tenant.slug,
  }
}

function getCurrentUserId(req) {
  const localUserId = String(req.get('X-UMI-User-ID') || '').trim()
  if (localUserId) return localUserId
  return null
}

function normalizeRoleKey(roles) {
  if (!roles?.length) return null
  if (roles.includes('super_admin')) return 'super_admin'
  if (roles.includes('owner')) return 'owner'
  if (roles.includes('admin')) return 'admin'
  if (roles.includes('developer')) return 'developer'
  if (roles.includes('tech_assist')) return 'tech_assist'
  if (roles.includes('staff')) return 'staff'
  return roles[0]
}

async function requireTenantAccess(req, res, tenantId) {
  const userId = getCurrentUserId(req)
  if (!userId) {
    res.status(401).json({ error: 'authentication_required' })
    return null
  }

  const rows = await prisma.$queryRaw`
    SELECT
      tm.id::text AS "membershipId",
      t.id::text AS "tenantId",
      t.slug,
      t.name,
      t.timezone,
      array_remove(array_agg(DISTINCT r.key), NULL) AS roles,
      array_remove(array_agg(DISTINCT p.key), NULL) AS permissions
    FROM platform.tenant_memberships AS tm
    JOIN platform.tenants AS t
      ON t.id = tm.tenant_id
    LEFT JOIN platform.membership_roles AS mr
      ON mr.membership_id = tm.id
    LEFT JOIN platform.roles AS r
      ON r.id = mr.role_id
    LEFT JOIN platform.role_permissions AS rp
      ON rp.role_id = r.id
    LEFT JOIN platform.permissions AS p
      ON p.id = rp.permission_id
    WHERE tm.user_id = ${userId}::uuid
      AND tm.tenant_id = ${tenantId}::uuid
      AND tm.status = 'active'
      AND t.status = 'active'
    GROUP BY tm.id, t.id
    LIMIT 1
  `

  const access = rows[0]
  if (!access) {
    res.status(404).json({ error: 'tenant_not_found' })
    return null
  }

  const role = normalizeRoleKey(access.roles || [])
  return {
    tenant: {
      id: access.tenantId,
      slug: access.slug,
      name: access.name,
      timezone: access.timezone,
    },
    membership: {
      id: access.membershipId,
      role,
      roles: access.roles || [],
      permissions: role === 'super_admin' ? ['*'] : (access.permissions || []),
    },
  }
}

async function loadProducts(tenantId) {
  const rows = await prisma.$queryRaw`
    SELECT
      product_key AS "productKey",
      status,
      location_id::text AS "locationId",
      config
    FROM platform.product_instances
    WHERE tenant_id = ${tenantId}::uuid
      AND location_id IS NULL
    ORDER BY product_key
  `
  return Object.fromEntries(rows.map((row) => [
    row.productKey,
    {
      status: row.status,
      locationId: row.locationId,
      config: row.config || {},
    },
  ]))
}

async function loadLocations(tenantId) {
  return prisma.$queryRaw`
    SELECT id::text, slug, name, timezone, status
    FROM platform.locations
    WHERE tenant_id = ${tenantId}::uuid
    ORDER BY
      CASE WHEN lower(name) = 'chapultepec' THEN 0 ELSE 1 END,
      created_at ASC
  `
}

async function buildCapabilities(req, res, tenantId, selectedLocationId = null) {
  const access = await requireTenantAccess(req, res, tenantId)
  if (!access) return null
  const [products, locations] = await Promise.all([
    loadProducts(tenantId),
    loadLocations(tenantId),
  ])
  const selectedLocation = selectedLocationId
    ? locations.find((location) => location.id === selectedLocationId) || null
    : locations.find((location) => location.status === 'active') || locations[0] || null
  const base = {
    tenant: access.tenant,
    selectedLocation,
    locations,
    membership: access.membership,
    products,
  }
  return {
    ...base,
    modules: buildModuleAvailability(base),
  }
}

async function requireProduct(req, res, tenantId, productKey) {
  const capabilities = await buildCapabilities(req, res, tenantId, req.query.locationId || null)
  if (!capabilities) return null
  const status = capabilities.products?.[productKey]?.status
  if (!PRODUCT_ACTIVE_STATUSES.has(status)) {
    res.status(403).json({ error: 'product_not_active', product: productKey, status: status || 'missing' })
    return null
  }
  return capabilities
}

async function requireLegacyProduct(req, res, productKey) {
  const rows = await prisma.$queryRaw`
    SELECT pi.status
    FROM platform.tenants AS t
    LEFT JOIN platform.product_instances AS pi
      ON pi.tenant_id = t.id
      AND pi.product_key = ${productKey}
      AND pi.location_id IS NULL
    WHERE t.slug = ${req.params.slug}
    LIMIT 1
  `
  const status = rows[0]?.status
  if (!PRODUCT_ACTIVE_STATUSES.has(status)) {
    res.status(403).json({ error: 'product_not_active', product: productKey, status: status || 'missing' })
    return false
  }
  return true
}

async function requireLocationAccess(req, res, tenantId, locationId) {
  if (!locationId) return null
  const location = await getLocationForTenant(tenantId, locationId)
  if (!location) {
    res.status(404).json({ error: 'location_not_found' })
    return null
  }
  return location
}

async function tenantSlugForRoute(req, res, productKey = 'dashboard') {
  const tenantId = req.params.tenantId
  const capabilities = await requireProduct(req, res, tenantId, productKey)
  if (!capabilities) return null
  if (req.query.locationId) {
    const location = await requireLocationAccess(req, res, tenantId, req.query.locationId)
    if (!location) return null
  }
  return capabilities.tenant.slug
}

function notFound(res) {
  return res.status(404).json({ error: 'Tenant no encontrado' })
}

function businessNotLinked(res) {
  return res.status(404).json({ error: 'No conversaflow business linked to this tenant' })
}

const DEFAULT_PERMISSIONS = {
  ADMIN: { scan: true, topup: true, analytics: true, settings: true, staff: true, giftcards: true, kds: true },
  STAFF: { scan: true, topup: true, analytics: false, settings: false, staff: false, giftcards: false, kds: true },
}

function normalizeRole(role) {
  return role === 'ADMIN' ? 'ADMIN' : 'STAFF'
}

function staffDto(row) {
  return {
    id: row.id,
    name: row.name,
    phone: row.phone,
    email: row.email,
    role: row.role,
    status: row.status,
    permissions: row.permissions ?? DEFAULT_PERMISSIONS[row.role] ?? DEFAULT_PERMISSIONS.STAFF,
    createdAt: row.createdAt?.toISOString?.() ?? row.createdAt,
    updatedAt: row.updatedAt?.toISOString?.() ?? row.updatedAt,
    invitedAt: row.invitedAt?.toISOString?.() ?? row.invitedAt,
    disabledAt: row.disabledAt?.toISOString?.() ?? row.disabledAt,
  }
}

function parsePagination(query, defaultLimit = 20) {
  const page = Math.max(1, parseInt(query.page || '1') || 1)
  const limit = Math.max(1, Math.min(parseInt(query.limit || String(defaultLimit)) || defaultLimit, 100))
  return { page, limit, skip: (page - 1) * limit }
}

function redirectWithQuery(req, res, targetPath) {
  const qs = new URLSearchParams(req.query).toString()
  return res.redirect(307, qs ? `${targetPath}?${qs}` : targetPath)
}

function normalizeCustomerPhone(phone) {
  const digits = String(phone || '').replace(/\D+/g, '')
  if (!digits) return null
  if (digits.length === 10) return `+52${digits}`
  if (digits.length === 11 && digits.startsWith('1')) return `+52${digits.slice(-10)}`
  if (digits.length === 12 && digits.startsWith('52')) return `+${digits}`
  if (digits.length === 13 && digits.startsWith('521')) return `+52${digits.slice(-10)}`
  if (digits.startsWith('0') && digits.length > 10) return `+52${digits.slice(-10)}`
  return `+${digits}`
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value || ''))
}

function productAvailable(capabilities, productKey) {
  return PRODUCT_ACTIVE_STATUSES.has(capabilities?.products?.[productKey]?.status)
}

function iso(value) {
  return value?.toISOString?.() ?? value ?? null
}

function centsToMoney(cents) {
  return fmt(cents || 0)
}

function platformCustomerDto(row, capabilities) {
  const identityList = Array.isArray(row.identities) ? row.identities : []
  const cashAvailable = productAvailable(capabilities, 'cash')
  const conversaflowAvailable = productAvailable(capabilities, 'conversaflow')
  const kdsAvailable = productAvailable(capabilities, 'kds')
  const hasCash = Number(row.loyalty_count || 0) > 0
  const hasWhatsapp = Number(row.conversation_count || 0) > 0 || identityList.some((identity) => identity.identity_type === 'whatsapp')
  const hasOrders = Number(row.orders_count || 0) > 0
  const needsReview = Number(row.merge_candidate_count || 0) > 0 || Number(row.data_quality_count || 0) > 0
  const factsCount = Number(row.memory_count || 0)
  const lastTouchAt = iso(row.last_touch_at || row.updated_at || row.created_at)

  return {
    id: row.id,
    displayName: row.display_name || row.normalized_phone || row.phone || row.email || 'Unknown customer',
    phone: row.phone || row.normalized_phone || '',
    normalizedPhone: row.normalized_phone || normalizeCustomerPhone(row.phone),
    email: row.email || '',
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    lastTouchAt,
    status: needsReview ? 'needs_review' : hasOrders || hasCash || hasWhatsapp ? 'active' : 'new',
    products: {
      whatsapp: { available: conversaflowAvailable, active: hasWhatsapp, source: hasWhatsapp ? 'conversaflow' : 'none', conversations: Number(row.conversation_count || 0), activeConversations: Number(row.active_conversations || 0) },
      cash: { available: cashAvailable, active: hasCash, source: hasCash ? 'cash' : 'none' },
      orders: { available: kdsAvailable || conversaflowAvailable, active: hasOrders, source: hasOrders ? 'commerce' : 'none' },
      giftCards: { available: cashAvailable, active: Number(row.gift_card_count || 0) > 0, source: Number(row.gift_card_count || 0) > 0 ? 'cash' : 'none' },
    },
    value: {
      orders: Number(row.orders_count || 0),
      totalSpendCents: Number(row.total_spend_cents || 0),
      totalSpend: centsToMoney(Number(row.total_spend_cents || 0)),
      visits: Number(row.total_visits || 0),
      walletBalanceCents: Number(row.wallet_balance_cents || 0),
      walletBalance: centsToMoney(Number(row.wallet_balance_cents || 0)),
    },
    memory: {
      factsCount,
      embeddingHealth: factsCount > 0 ? 'context_ready' : 'no_memory_yet',
      summary: factsCount > 0 ? `${factsCount} memory item${factsCount === 1 ? '' : 's'}` : 'No extracted facts yet',
    },
    dataQuality: {
      mergeCandidates: Number(row.merge_candidate_count || 0),
      findings: Number(row.data_quality_count || 0),
      needsReview,
    },
    identities: identityList,
  }
}

async function loadPlatformCustomers(capabilities, options = {}) {
  const page = Math.max(1, parseInt(options.page || '1') || 1)
  const limit = Math.max(1, Math.min(parseInt(options.limit || '20') || 20, 100))
  const search = String(options.search || '').trim().slice(0, 80)
  const filter = String(options.filter || '').trim().slice(0, 24)
  const contactId = String(options.contactId || '').trim()
  const contactUuid = isUuid(contactId) ? contactId : capabilities.tenant.id
  const skip = (page - 1) * limit
  const tenantId = capabilities.tenant.id

  const rows = await prisma.$queryRaw`
    SELECT
      c.id::text,
      c.display_name,
      c.phone,
      c.email,
      c.created_at,
      c.updated_at,
      COALESCE(phone_identity.normalized_value, c.phone) AS normalized_phone,
      COALESCE(identities.items, '[]'::jsonb) AS identities,
      COALESCE(cash_summary.loyalty_count, 0)::int AS loyalty_count,
      COALESCE(cash_summary.total_visits, 0)::int AS total_visits,
      COALESCE(cash_summary.wallet_balance_cents, 0)::int AS wallet_balance_cents,
      COALESCE(cash_summary.gift_card_count, 0)::int AS gift_card_count,
      COALESCE(conversation_summary.conversation_count, 0)::int AS conversation_count,
      COALESCE(conversation_summary.active_conversations, 0)::int AS active_conversations,
      COALESCE(order_summary.orders_count, 0)::int AS orders_count,
      COALESCE(order_summary.total_spend_cents, 0)::int AS total_spend_cents,
      COALESCE(memory_summary.memory_count, 0)::int AS memory_count,
      COALESCE(quality_summary.data_quality_count, 0)::int AS data_quality_count,
      COALESCE(merge_summary.merge_candidate_count, 0)::int AS merge_candidate_count,
      last_touch.last_touch_at
    FROM platform.contacts AS c
    LEFT JOIN LATERAL (
      SELECT ci.normalized_value
      FROM platform.contact_identities AS ci
      WHERE ci.contact_id = c.id
        AND ci.identity_type IN ('phone', 'whatsapp')
        AND ci.normalized_value IS NOT NULL
      ORDER BY CASE WHEN ci.identity_type = 'phone' THEN 0 ELSE 1 END, ci.created_at ASC
      LIMIT 1
    ) AS phone_identity ON true
    LEFT JOIN LATERAL (
      SELECT jsonb_agg(
        jsonb_build_object(
          'id', ci.id::text,
          'identity_type', ci.identity_type,
          'identity_value', ci.identity_value,
          'normalized_value', ci.normalized_value,
          'provider', ci.provider,
          'verification_status', ci.verification_status,
          'confidence', ci.confidence
        )
        ORDER BY ci.identity_type, ci.created_at
      ) AS items
      FROM platform.contact_identities AS ci
      WHERE ci.contact_id = c.id
    ) AS identities ON true
    LEFT JOIN LATERAL (
      SELECT
        count(la.id) AS loyalty_count,
        COALESCE(sum(lc.total_visits), 0) AS total_visits,
        COALESCE(sum(lc.balance_cents), 0) AS wallet_balance_cents,
        count(gc.id) AS gift_card_count,
        max(GREATEST(lc.updated_at, la.updated_at)) AS last_cash_at
      FROM cash.loyalty_accounts AS la
      LEFT JOIN cash.loyalty_cards AS lc ON lc.loyalty_account_id = la.id
      LEFT JOIN cash.gift_cards AS gc ON gc.recipient_contact_id = c.id
      WHERE la.contact_id = c.id
    ) AS cash_summary ON true
    LEFT JOIN LATERAL (
      SELECT
        count(cv.id) AS conversation_count,
        count(cv.id) FILTER (WHERE cv.status IN ('open', 'pending', 'active')) AS active_conversations,
        max(cv.updated_at) AS last_conversation_at
      FROM conversaflow.conversations AS cv
      WHERE cv.contact_id = c.id
    ) AS conversation_summary ON true
    LEFT JOIN LATERAL (
      SELECT
        count(o.id) AS orders_count,
        COALESCE(sum(o.total_cents), 0) AS total_spend_cents,
        max(COALESCE(o.placed_at, o.created_at)) AS last_order_at
      FROM commerce.orders AS o
      WHERE o.contact_id = c.id
    ) AS order_summary ON true
    LEFT JOIN LATERAL (
      SELECT count(mi.id) AS memory_count, max(mi.updated_at) AS last_memory_at
      FROM conversaflow.memory_items AS mi
      WHERE mi.contact_id = c.id
    ) AS memory_summary ON true
    LEFT JOIN LATERAL (
      SELECT count(dq.id) AS data_quality_count, max(dq.created_at) AS last_quality_at
      FROM observability.data_quality_findings AS dq
      WHERE dq.tenant_id = c.tenant_id
        AND dq.status = 'open'
        AND dq.subject_id = c.id::text
    ) AS quality_summary ON true
    LEFT JOIN LATERAL (
      SELECT count(mc.id) AS merge_candidate_count, max(mc.created_at) AS last_merge_at
      FROM platform.contact_merge_candidates AS mc
      WHERE mc.tenant_id = c.tenant_id
        AND mc.confidence IN ('candidate', 'high')
        AND (mc.left_contact_id = c.id OR mc.right_contact_id = c.id)
    ) AS merge_summary ON true
    LEFT JOIN LATERAL (
      SELECT max(ts) AS last_touch_at
      FROM (VALUES
        (c.updated_at),
        (cash_summary.last_cash_at),
        (conversation_summary.last_conversation_at),
        (order_summary.last_order_at),
        (memory_summary.last_memory_at),
        (quality_summary.last_quality_at),
        (merge_summary.last_merge_at)
      ) AS touch(ts)
    ) AS last_touch ON true
    WHERE c.tenant_id = ${tenantId}::uuid
      AND (${contactId} = '' OR c.id = ${contactUuid}::uuid)
      AND (
        ${filter} = ''
        OR (${filter} = 'whatsapp' AND COALESCE(conversation_summary.conversation_count, 0) > 0)
        OR (${filter} = 'cash' AND COALESCE(cash_summary.loyalty_count, 0) > 0)
        OR (${filter} = 'memory' AND COALESCE(memory_summary.memory_count, 0) > 0)
        OR (${filter} = 'review' AND (COALESCE(quality_summary.data_quality_count, 0) > 0 OR COALESCE(merge_summary.merge_candidate_count, 0) > 0))
      )
      AND (
        ${search} = ''
        OR c.display_name ILIKE ${`%${search}%`}
        OR c.phone ILIKE ${`%${search}%`}
        OR c.email ILIKE ${`%${search}%`}
        OR phone_identity.normalized_value ILIKE ${`%${search}%`}
      )
    ORDER BY last_touch.last_touch_at DESC NULLS LAST, c.created_at DESC
    LIMIT ${limit}
    OFFSET ${skip}
  `
  const countRows = await prisma.$queryRaw`
    SELECT count(*)::int AS count
    FROM platform.contacts AS c
    LEFT JOIN LATERAL (
      SELECT ci.normalized_value
      FROM platform.contact_identities AS ci
      WHERE ci.contact_id = c.id
        AND ci.identity_type IN ('phone', 'whatsapp')
        AND ci.normalized_value IS NOT NULL
      LIMIT 1
    ) AS phone_identity ON true
    WHERE c.tenant_id = ${tenantId}::uuid
      AND (${contactId} = '' OR c.id = ${contactUuid}::uuid)
      AND (
        ${filter} = ''
        OR (${filter} = 'whatsapp' AND EXISTS (SELECT 1 FROM conversaflow.conversations AS cv WHERE cv.contact_id = c.id))
        OR (${filter} = 'cash' AND EXISTS (SELECT 1 FROM cash.loyalty_accounts AS la WHERE la.contact_id = c.id))
        OR (${filter} = 'memory' AND EXISTS (SELECT 1 FROM conversaflow.memory_items AS mi WHERE mi.contact_id = c.id))
        OR (${filter} = 'review' AND (
          EXISTS (SELECT 1 FROM observability.data_quality_findings AS dq WHERE dq.tenant_id = c.tenant_id AND dq.status = 'open' AND dq.subject_id = c.id::text)
          OR EXISTS (SELECT 1 FROM platform.contact_merge_candidates AS mc WHERE mc.tenant_id = c.tenant_id AND mc.confidence IN ('candidate', 'high') AND (mc.left_contact_id = c.id OR mc.right_contact_id = c.id))
        ))
      )
      AND (
        ${search} = ''
        OR c.display_name ILIKE ${`%${search}%`}
        OR c.phone ILIKE ${`%${search}%`}
        OR c.email ILIKE ${`%${search}%`}
        OR phone_identity.normalized_value ILIKE ${`%${search}%`}
      )
  `
  const customers = rows.map((row) => platformCustomerDto(row, capabilities))
  const total = Number(countRows[0]?.count || customers.length)
  return { customers, total, page, totalPages: Math.max(1, Math.ceil(total / limit)), source: 'platform.contacts' }
}

async function loadPlatformCustomerDetail(capabilities, contactId) {
  if (!isUuid(contactId)) return null
  const list = await loadPlatformCustomers(capabilities, { page: 1, limit: 1, search: '', contactId })
  const customer = list.customers[0] || null
  if (!customer) return null
  const [timeline, conversations, orders, cash, identity] = await Promise.all([
    loadPlatformCustomerTimeline(capabilities, contactId),
    loadPlatformCustomerConversations(capabilities, contactId),
    loadPlatformCustomerOrders(capabilities, contactId),
    loadPlatformCustomerCash(capabilities, contactId),
    loadPlatformCustomerIdentity(capabilities, contactId),
  ])
  return { customer, timeline, conversations, orders, cash, identity }
}

async function loadPlatformCustomerTimeline(capabilities, contactId) {
  const rows = await prisma.$queryRaw`
    SELECT * FROM (
      SELECT 'whatsapp_message' AS type, m.id::text AS id, m.created_at AS occurred_at, m.role AS label, COALESCE(m.body, m.payload->>'content', '') AS detail, 'conversaflow' AS product
      FROM conversaflow.messages AS m
      WHERE m.contact_id = ${contactId}::uuid AND m.tenant_id = ${capabilities.tenant.id}::uuid
      UNION ALL
      SELECT 'order' AS type, o.id::text AS id, COALESCE(o.placed_at, o.created_at) AS occurred_at, o.status AS label, COALESCE(o.order_number, o.source_ref, o.id::text) AS detail, 'orders' AS product
      FROM commerce.orders AS o
      WHERE o.contact_id = ${contactId}::uuid AND o.tenant_id = ${capabilities.tenant.id}::uuid
      UNION ALL
      SELECT 'memory' AS type, mi.id::text AS id, mi.updated_at AS occurred_at, mi.memory_type AS label, mi.content AS detail, 'memory' AS product
      FROM conversaflow.memory_items AS mi
      WHERE mi.contact_id = ${contactId}::uuid AND mi.tenant_id = ${capabilities.tenant.id}::uuid
      UNION ALL
      SELECT 'data_quality' AS type, dq.id::text AS id, dq.created_at AS occurred_at, dq.severity AS label, dq.finding_key AS detail, 'data' AS product
      FROM observability.data_quality_findings AS dq
      WHERE dq.tenant_id = ${capabilities.tenant.id}::uuid AND dq.subject_id = ${contactId}
    ) AS timeline
    ORDER BY occurred_at DESC
    LIMIT 80
  `
  return rows.map((row) => ({ ...row, occurredAt: iso(row.occurred_at) }))
}

async function loadPlatformCustomerConversations(capabilities, contactId) {
  const rows = await prisma.$queryRaw`
    SELECT
      cv.id::text,
      cv.status,
      cv.opened_at,
      cv.closed_at,
      cv.updated_at,
      cv.metadata,
      count(m.id)::int AS "messageCount",
      max(m.created_at) AS "lastMessageAt"
    FROM conversaflow.conversations AS cv
    LEFT JOIN conversaflow.messages AS m ON m.conversation_id = cv.id
    WHERE cv.contact_id = ${contactId}::uuid
      AND cv.tenant_id = ${capabilities.tenant.id}::uuid
    GROUP BY cv.id
    ORDER BY cv.updated_at DESC
    LIMIT 40
  `
  return rows.map((row) => ({
    id: row.id,
    status: row.status,
    openedAt: iso(row.opened_at),
    closedAt: iso(row.closed_at),
    updatedAt: iso(row.updated_at),
    lastMessageAt: iso(row.lastMessageAt),
    messageCount: Number(row.messageCount || 0),
    summary: row.metadata?.summary || row.metadata?.current_state || '',
  }))
}

async function loadPlatformCustomerOrders(capabilities, contactId) {
  const rows = await prisma.$queryRaw`
    SELECT
      id::text,
      order_number,
      source_product,
      status,
      channel,
      total_cents,
      placed_at,
      created_at,
      updated_at
    FROM commerce.orders
    WHERE contact_id = ${contactId}::uuid
      AND tenant_id = ${capabilities.tenant.id}::uuid
    ORDER BY COALESCE(placed_at, created_at) DESC
    LIMIT 40
  `
  return rows.map((row) => ({
    id: row.id,
    orderNumber: row.order_number,
    sourceProduct: row.source_product,
    status: row.status,
    channel: row.channel,
    totalCents: Number(row.total_cents || 0),
    total: centsToMoney(Number(row.total_cents || 0)),
    placedAt: iso(row.placed_at || row.created_at),
    updatedAt: iso(row.updated_at),
  }))
}

async function loadPlatformCustomerCash(capabilities, contactId) {
  const rows = await prisma.$queryRaw`
    SELECT
      la.id::text AS "loyaltyAccountId",
      la.status,
      lc.id::text AS "loyaltyCardId",
      lc.card_number,
      lc.balance_cents,
      lc.total_visits,
      lc.visits_this_cycle,
      lc.pending_rewards,
      lc.created_at,
      lc.updated_at
    FROM cash.loyalty_accounts AS la
    LEFT JOIN cash.loyalty_cards AS lc ON lc.loyalty_account_id = la.id
    WHERE la.contact_id = ${contactId}::uuid
      AND la.tenant_id = ${capabilities.tenant.id}::uuid
    ORDER BY la.created_at DESC
    LIMIT 1
  `
  const row = rows[0]
  if (!row) return { available: productAvailable(capabilities, 'cash'), source: 'cash', account: null }
  return {
    available: productAvailable(capabilities, 'cash'),
    source: 'cash',
    account: {
      loyaltyAccountId: row.loyaltyAccountId,
      status: row.status,
      loyaltyCardId: row.loyaltyCardId,
      cardNumber: row.card_number,
      balanceCents: Number(row.balance_cents || 0),
      balance: centsToMoney(Number(row.balance_cents || 0)),
      totalVisits: Number(row.total_visits || 0),
      visitsThisCycle: Number(row.visits_this_cycle || 0),
      pendingRewards: Number(row.pending_rewards || 0),
      createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
    },
  }
}

async function loadPlatformCustomerIdentity(capabilities, contactId) {
  const [identities, candidates, findings] = await Promise.all([
    prisma.$queryRaw`
      SELECT id::text, identity_type, identity_value, normalized_value, provider, verification_status, confidence, metadata, created_at
      FROM platform.contact_identities
      WHERE contact_id = ${contactId}::uuid
        AND tenant_id = ${capabilities.tenant.id}::uuid
      ORDER BY identity_type, created_at
    `,
    prisma.$queryRaw`
      SELECT id::text, left_contact_id::text, right_contact_id::text, match_type, confidence, detail, created_at, resolved_at
      FROM platform.contact_merge_candidates
      WHERE tenant_id = ${capabilities.tenant.id}::uuid
        AND (left_contact_id = ${contactId}::uuid OR right_contact_id = ${contactId}::uuid)
      ORDER BY created_at DESC
      LIMIT 20
    `,
    prisma.$queryRaw`
      SELECT id::text, severity, finding_key, detail, status, created_at, resolved_at
      FROM observability.data_quality_findings
      WHERE tenant_id = ${capabilities.tenant.id}::uuid
        AND subject_id = ${contactId}
      ORDER BY created_at DESC
      LIMIT 20
    `,
  ])
  return {
    identities: identities.map((row) => ({ ...row, createdAt: iso(row.created_at) })),
    mergeCandidates: candidates.map((row) => ({ ...row, createdAt: iso(row.created_at), resolvedAt: iso(row.resolved_at) })),
    findings: findings.map((row) => ({ ...row, createdAt: iso(row.created_at), resolvedAt: iso(row.resolved_at) })),
  }
}


async function callKdsPairingBackend(action, body) {
  const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceRoleKey) {
    const err = new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required for KDS pairing')
    err.status = 500
    throw err
  }

  const edgeRes = await fetch(`${supabaseUrl.replace(/\/$/, '')}/functions/v1/kds-pairing`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${serviceRoleKey}`,
      'apikey': serviceRoleKey,
    },
    body: JSON.stringify(Object.assign({ action }, body || {})),
  })
  const payload = await edgeRes.json().catch(() => ({}))
  if (!edgeRes.ok) {
    const err = new Error(payload.error || `kds-pairing failed with ${edgeRes.status}`)
    err.status = edgeRes.status
    err.payload = payload
    throw err
  }
  return payload
}

function _sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex')
}


function kdsRevokedPayload() {
  return {
    error: 'device_revoked',
    message: 'This KDS device has been removed. Pair it again from the dashboard.',
  }
}

function kdsTokenMissingPayload() {
  return {
    error: 'device_revoked',
    message: 'This KDS device has been removed. Pair it again from the dashboard.',
  }
}

async function verifyLocalKdsDevice(req) {
  const token = String(req.get('X-KDS-Device-Token') || '').trim()
  if (!token) {
    const err = new Error('device_token_missing')
    err.status = 401
    err.payload = kdsTokenMissingPayload()
    throw err
  }

  const rows = await prisma.$queryRaw`
    SELECT *
    FROM kds.device_sessions
    WHERE token_hash = ${_sha256Hex(token)}
    LIMIT 1
  `
  const row = rows[0]
  if (!row || row.is_active !== true) {
    const err = new Error('device_revoked')
    err.status = 403
    err.payload = kdsRevokedPayload()
    throw err
  }

  const deviceId = String(row.id || row.device_id)
  await prisma.$executeRaw`
    UPDATE kds.device_sessions
    SET last_seen_at = now()
    WHERE id = ${deviceId}::uuid
  `

  return {
    deviceId,
    tenantId: row.tenant_id ? String(row.tenant_id) : null,
    businessId: row.business_id ? String(row.business_id) : (row.tenant_id ? String(row.tenant_id) : null),
    locationId: row.location_id ? String(row.location_id) : null,
    stationId: row.station_id ? String(row.station_id) : null,
    deviceName: row.device_name || null,
  }
}

// ── KDS device pairing (iPad-facing, no auth — PIN is the credential) ────────
// Routes to the canonical kds-pairing edge function (S4.2 dedup).
app.post('/api/kds/pairing', async (req, res) => {
  const action = String((req.body || {}).action || '').trim()
  if (action !== 'kds_start' && action !== 'kds_status') {
    return res.status(400).json({ error: 'unknown_action' })
  }
  try {
    const payload = await callKdsPairingBackend(action, req.body || {})
    return res.json(payload)
  } catch (err) {
    console.error('[kds pairing public]', err.message)
    return res.status(err.status || 500).json({ error: err.message })
  }
})

app.post('/api/kds/board', async (req, res) => {
  const action = String((req.body || {}).action || '').trim()
  if (!['snapshot', 'events', 'session_status'].includes(action)) {
    return res.status(400).json({ error: 'unknown_action' })
  }

  try {
    const device = await verifyLocalKdsDevice(req)

    if (action === 'session_status') {
      return res.json({ ok: true, device_id: device.deviceId })
    }

    if (action === 'events') {
      return res.json({ ok: true, data: [] })
    }

    {
      const rows = await prisma.$queryRaw`
        SELECT
          t.id::text AS ticket_id,
          t.id::text AS source_transaction_id,
          t.tenant_id::text AS business_id,
          'whatsapp'::text AS source_channel,
          t.status::text,
          t.station_id::text,
          s.name AS station_name,
          t.customer_name,
          t.customer_phone,
          NULL::text AS pickup_person,
          t.customer_note,
          NULL::text AS cancellation_reason,
          NULL::text AS partial_cancellation_reason,
          (t.total_cents::numeric / 100.0) AS total_amount,
          t.created_at,
          t.updated_at,
          NULL::bigint AS last_event_sequence,
          COALESCE(
            jsonb_agg(
              jsonb_build_object(
                'ticket_item_id', i.id::text,
                'name', i.name,
                'quantity', i.quantity,
                'variant_name', i.variant_name,
                'notes', i.notes,
                'is_cancelled', i.is_cancelled,
                'unit_price', (i.unit_price_cents::numeric / 100.0),
                'display_order', i.display_order
              )
              ORDER BY i.display_order ASC
            ) FILTER (WHERE i.id IS NOT NULL),
            '[]'::jsonb
          ) AS items
        FROM kds.tickets AS t
        LEFT JOIN kds.stations AS s
          ON s.id = t.station_id
        LEFT JOIN kds.ticket_items AS i
          ON i.ticket_id = t.id
        WHERE t.tenant_id = ${device.tenantId}::uuid
          AND (${device.locationId}::uuid IS NULL OR t.location_id IS NOT DISTINCT FROM ${device.locationId}::uuid)
          AND (${device.stationId}::uuid IS NULL OR t.station_id IS NOT DISTINCT FROM ${device.stationId}::uuid OR t.station_id IS NULL)
          AND t.status::text IN ('new', 'accepted', 'preparing', 'ready', 'partial_cancelled')
        GROUP BY t.id, s.id
        ORDER BY t.created_at ASC
        LIMIT 200
      `
      return res.json({ ok: true, data: rows })
    }
  } catch (err) {
    console.error('[kds board local]', err.message)
    return res.status(err.status || 500).json(err.payload || { error: err.message })
  }
})

app.post('/api/kds/command', async (req, res) => {
  const action = String((req.body || {}).action || '').trim()
  if (!action) return res.status(400).json({ error: 'missing_action' })

  try {
    const device = await verifyLocalKdsDevice(req)

    if (action === 'transition_ticket') {
      const targetStatus = req.body.target_status
      const ticketId = String(req.body.ticket_id || '').trim()
      if (!ticketId || !ORDER_STATUS_MAP.all.includes(targetStatus)) {
        return res.status(400).json({ error: 'missing_required_fields' })
      }

      const rows = await prisma.$queryRaw`
        UPDATE kds.tickets
        SET status = ${targetStatus}, updated_at = now()
        WHERE id = ${ticketId}::uuid
          AND tenant_id = ${device.tenantId}::uuid
          AND (${device.locationId}::uuid IS NULL OR location_id IS NOT DISTINCT FROM ${device.locationId}::uuid)
          AND (${device.stationId}::uuid IS NULL OR station_id IS NOT DISTINCT FROM ${device.stationId}::uuid OR station_id IS NULL)
        RETURNING id::text AS ticket_id, status
      `
      if (!rows[0]) return res.status(404).json({ error: 'Ticket not found' })
      return res.json({ ok: true, data: rows[0] })
    }

    if (action === 'partial_cancel_items') {
      const ticketId = String(req.body.ticket_id || '').trim()
      const itemIds = Array.isArray(req.body.item_ids) ? req.body.item_ids : []
      if (!ticketId || itemIds.length === 0) return res.status(400).json({ error: 'missing_required_fields' })

      {
        const [, rows] = await prisma.$transaction([
          prisma.$executeRaw`
            UPDATE kds.ticket_items
            SET is_cancelled = true
            WHERE ticket_id = ${ticketId}::uuid
              AND id IN (${Prisma.join(itemIds.map((id) => Prisma.sql`${String(id)}::uuid`))})
              AND EXISTS (
                SELECT 1
                FROM kds.tickets AS t
                WHERE t.id = kds.ticket_items.ticket_id
                  AND t.tenant_id = ${device.tenantId}::uuid
                  AND (${device.locationId}::uuid IS NULL OR t.location_id IS NOT DISTINCT FROM ${device.locationId}::uuid)
                  AND (${device.stationId}::uuid IS NULL OR t.station_id IS NOT DISTINCT FROM ${device.stationId}::uuid OR t.station_id IS NULL)
              )
          `,
          prisma.$queryRaw`
            UPDATE kds.tickets
            SET status = 'partial_cancelled', updated_at = now()
            WHERE id = ${ticketId}::uuid
              AND tenant_id = ${device.tenantId}::uuid
              AND (${device.locationId}::uuid IS NULL OR location_id IS NOT DISTINCT FROM ${device.locationId}::uuid)
              AND (${device.stationId}::uuid IS NULL OR station_id IS NOT DISTINCT FROM ${device.stationId}::uuid OR station_id IS NULL)
            RETURNING id::text AS ticket_id, status
          `,
        ])
        if (!rows[0]) return res.status(404).json({ error: 'Ticket not found' })
        return res.json({ ok: true, data: rows[0] })
      }
    }

    return res.status(400).json({ error: 'unknown_action' })
  } catch (err) {
    console.error('[kds command local]', err.message)
    return res.status(err.status || 500).json(err.payload || { error: err.message })
  }
})

app.get('/api/me/tenants', async (req, res) => {
  try {
    const userId = getCurrentUserId(req)
    if (!userId) return res.status(401).json({ error: 'authentication_required' })

    const rows = await prisma.$queryRaw`
      SELECT
        t.id::text,
        t.slug,
        t.name,
        t.timezone,
        array_remove(array_agg(DISTINCT r.key), NULL) AS roles
      FROM platform.tenant_memberships AS tm
      JOIN platform.tenants AS t
        ON t.id = tm.tenant_id
      LEFT JOIN platform.membership_roles AS mr
        ON mr.membership_id = tm.id
      LEFT JOIN platform.roles AS r
        ON r.id = mr.role_id
      WHERE tm.user_id = ${userId}::uuid
        AND tm.status = 'active'
        AND t.status = 'active'
      GROUP BY t.id
      ORDER BY t.slug
    `

    return res.json({ tenants: rows })
  } catch (err) {
    console.error('[me tenants]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/capabilities', async (req, res) => {
  try {
    const capabilities = await buildCapabilities(req, res, req.params.tenantId, req.query.locationId || null)
    if (!capabilities) return null
    return res.json(capabilities)
  } catch (err) {
    console.error('[tenant capabilities]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/settings', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    return res.json({
      id: capabilities.tenant.id,
      name: capabilities.tenant.name,
      slug: capabilities.tenant.slug,
      timezone: capabilities.tenant.timezone,
      subscriptionStatus: capabilities.products.dashboard?.status?.toUpperCase?.() || 'ACTIVE',
      primaryColor: capabilities.products.dashboard?.config?.primaryColor || '#B5605A',
      secondaryColor: capabilities.products.dashboard?.config?.secondaryColor || '#E8C9A3',
      products: capabilities.products,
      locations: capabilities.locations,
    })
  } catch (err) {
    console.error('[tenant settings GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.patch('/api/tenants/:tenantId/settings', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const d = req.body || {}
    await prisma.$executeRaw`
      UPDATE platform.tenants
      SET
        name = CASE WHEN ${d.name !== undefined} THEN ${d.name} ELSE name END,
        timezone = CASE WHEN ${d.timezone !== undefined} THEN ${d.timezone} ELSE timezone END,
        updated_at = now()
      WHERE id = ${capabilities.tenant.id}::uuid
    `
    return res.json({ ok: true })
  } catch (err) {
    console.error('[tenant settings PATCH]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/locations', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    return res.json({ locations: capabilities.locations })
  } catch (err) {
    console.error('[tenant locations GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.patch('/api/tenants/:tenantId/locations/:locationId', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const location = await requireLocationAccess(req, res, req.params.tenantId, req.params.locationId)
    if (!location) return null
    const d = req.body || {}
    const rows = await prisma.$queryRaw`
      UPDATE platform.locations
      SET
        name = CASE WHEN ${d.name !== undefined} THEN ${d.name} ELSE name END,
        timezone = CASE WHEN ${d.timezone !== undefined} THEN ${d.timezone} ELSE timezone END,
        status = CASE WHEN ${d.status !== undefined} THEN ${d.status} ELSE status END,
        updated_at = now()
      WHERE id = ${location.id}::uuid
        AND tenant_id = ${capabilities.tenant.id}::uuid
      RETURNING id::text, slug, name, timezone, status
    `
    return res.json({ location: rows[0] })
  } catch (err) {
    console.error('[tenant locations PATCH]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/customers', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const payload = await loadPlatformCustomers(capabilities, req.query)
    return res.json(payload)
  } catch (err) {
    console.error('[tenant customers GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/customers/:contactId', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const detail = await loadPlatformCustomerDetail(capabilities, req.params.contactId)
    if (!detail) return res.status(404).json({ error: 'customer_not_found' })
    return res.json(detail)
  } catch (err) {
    console.error('[tenant customer detail GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/customers/:contactId/timeline', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const timeline = await loadPlatformCustomerTimeline(capabilities, req.params.contactId)
    return res.json({ timeline })
  } catch (err) {
    console.error('[tenant customer timeline GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/customers/:contactId/conversations', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const conversations = await loadPlatformCustomerConversations(capabilities, req.params.contactId)
    return res.json({ conversations })
  } catch (err) {
    console.error('[tenant customer conversations GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/customers/:contactId/orders', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const orders = await loadPlatformCustomerOrders(capabilities, req.params.contactId)
    return res.json({ orders })
  } catch (err) {
    console.error('[tenant customer orders GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/customers/:contactId/cash', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const cash = await loadPlatformCustomerCash(capabilities, req.params.contactId)
    return res.json(cash)
  } catch (err) {
    console.error('[tenant customer cash GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/customers/:contactId/identity', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const identity = await loadPlatformCustomerIdentity(capabilities, req.params.contactId)
    return res.json(identity)
  } catch (err) {
    console.error('[tenant customer identity GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/tenants/:tenantId/insights/customer-platform', async (req, res) => {
  try {
    const capabilities = await requireProduct(req, res, req.params.tenantId, 'dashboard')
    if (!capabilities) return null
    const customersPayload = await loadPlatformCustomers(capabilities, { page: 1, limit: 100 })
    const customers = customersPayload.customers || []
    const whatsappCustomers = customers.filter((customer) => customer.products?.whatsapp?.active).length
    const cashCustomers = customers.filter((customer) => customer.products?.cash?.active).length
    const needsReview = customers.filter((customer) => customer.dataQuality?.needsReview).length
    const memoryReady = customers.filter((customer) => customer.memory?.factsCount > 0).length
    const activeConversations = customers.reduce((sum, customer) => sum + (customer.products?.whatsapp?.activeConversations || 0), 0)
    return res.json({
      source: customersPayload.source,
      generatedAt: new Date().toISOString(),
      metrics: {
        totalCustomers: customersPayload.total,
        whatsappCustomers,
        cashCustomers,
        memoryReady,
        needsReview,
        activeConversations,
      },
      insights: [
        {
          key: 'customer-growth',
          label: 'Customer base',
          value: customersPayload.total,
          action: 'Open Customers',
          target: '/customers',
          status: customersPayload.total > 0 ? 'ready' : 'empty',
        },
        {
          key: 'whatsapp-health',
          label: 'WhatsApp customers',
          value: whatsappCustomers,
          action: 'Review WhatsApp tab',
          target: '/customers?filter=whatsapp',
          status: productAvailable(capabilities, 'conversaflow') ? 'ready' : 'unavailable',
        },
        {
          key: 'memory-health',
          label: 'Memory context ready',
          value: memoryReady,
          action: 'Review customers without memory',
          target: '/customers?filter=memory',
          status: memoryReady > 0 ? 'ready' : 'needs_attention',
        },
        {
          key: 'identity-quality',
          label: 'Identity review',
          value: needsReview,
          action: 'Review Data tabs',
          target: '/customers?filter=review',
          status: needsReview > 0 ? 'needs_attention' : 'ready',
        },
      ],
    })
  } catch (err) {
    console.error('[tenant customer insights GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.all('/api/tenants/:tenantId/conversaflow/conversations', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'conversaflow')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/conversations`)
})

app.all('/api/tenants/:tenantId/conversaflow/hours', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'conversaflow')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/hours`)
})

app.all('/api/tenants/:tenantId/staff', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'dashboard')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/staff`)
})

app.all('/api/tenants/:tenantId/staff/:staffId', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'dashboard')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/staff/${req.params.staffId}`)
})

app.all('/api/tenants/:tenantId/kds/orders', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/orders`)
})

app.all('/api/tenants/:tenantId/kds/orders/:ticketId/transition', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/orders/${req.params.ticketId}/transition`)
})

app.all('/api/tenants/:tenantId/kds/devices', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/devices`)
})

app.all('/api/tenants/:tenantId/kds/stations', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/stations`)
})

app.all('/api/tenants/:tenantId/kds/devices/provision', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/devices/provision`)
})

app.all('/api/tenants/:tenantId/kds/devices/pairing', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/devices/pairing`)
})

app.all('/api/tenants/:tenantId/kds/devices/pairing-pin', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/devices/pairing-pin`)
})

app.all('/api/tenants/:tenantId/kds/devices/pairing/:pairingId/:action', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/devices/pairing/${req.params.pairingId}/${req.params.action}`)
})

app.all('/api/tenants/:tenantId/kds/devices/:deviceId/revoke', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/devices/${req.params.deviceId}/revoke`)
})

app.all('/api/tenants/:tenantId/kds/devices/:deviceId', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/devices/${req.params.deviceId}`)
})

app.all('/api/tenants/:tenantId/kds/ticker', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'kds')
  if (!slug) return null
  return redirectWithQuery(req, res, `/api/${slug}/admin/ticker`)
})

app.all('/api/tenants/:tenantId/cash/:resource', async (req, res) => {
  const slug = await tenantSlugForRoute(req, res, 'cash')
  if (!slug) return null
  const resourceMap = {
    stats: 'stats',
    analytics: 'analytics',
    customers: 'customers',
    members: 'customers',
    'reward-config': 'reward-config',
    'gift-cards': 'gift-cards',
  }
  const legacyResource = resourceMap[req.params.resource]
  if (!legacyResource) return res.status(404).json({ error: 'cash_route_not_found' })
  return redirectWithQuery(req, res, `/api/${slug}/admin/${legacyResource}`)
})

// ── settings ──────────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/settings', async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)
    return res.json({
      name:                  tenant.name,
      city:                  tenant.city,
      primaryColor:          tenant.primaryColor,
      secondaryColor:        tenant.secondaryColor,
      logoUrl:               tenant.logoUrl,
      stripImageUrl:         tenant.stripImageUrl,
      passStyle:             tenant.passStyle,
      promoMessage:          tenant.promoMessage,
      promoStartsAt:         tenant.promoStartsAt?.toISOString() ?? null,
      promoEndsAt:           tenant.promoEndsAt?.toISOString()   ?? null,
      promoDays:             tenant.promoDays,
      selfRegistration:      tenant.selfRegistration,
      birthdayRewardEnabled: tenant.birthdayRewardEnabled,
      birthdayRewardName:    tenant.birthdayRewardName,
      cardPrefix:            tenant.cardPrefix,
      slug:                  tenant.slug,
    })
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
})

app.patch('/api/:slug/admin/settings', async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)
    const d = req.body
    {
      if (d.name !== undefined) {
        await prisma.$executeRaw`
          UPDATE platform.tenants
          SET name = ${d.name}, updated_at = now()
          WHERE id = ${tenant.id}::uuid
        `
      }

      const brandingPatch = {}
      if (d.primaryColor !== undefined) brandingPatch.primary_color = d.primaryColor
      if (d.secondaryColor !== undefined) brandingPatch.secondary_color = d.secondaryColor || null
      if (d.logoUrl !== undefined) brandingPatch.logo_url = d.logoUrl || null
      if (d.stripImageUrl !== undefined) brandingPatch.strip_image_url = d.stripImageUrl || null
      if (d.promoMessage !== undefined) brandingPatch.promo_message = d.promoMessage || null
      if (d.promoStartsAt !== undefined) brandingPatch.promo_starts_at = d.promoStartsAt || null
      if (d.promoEndsAt !== undefined) brandingPatch.promo_ends_at = d.promoEndsAt || null
      if (d.promoDays !== undefined) brandingPatch.promo_days = d.promoDays || null
      if (d.birthdayRewardEnabled !== undefined) brandingPatch.birthday_reward_enabled = d.birthdayRewardEnabled
      if (d.birthdayRewardName !== undefined) brandingPatch.birthday_reward_name = d.birthdayRewardName

      const updatesProgram =
        d.cardPrefix !== undefined ||
        d.passStyle !== undefined ||
        d.primaryColor !== undefined ||
        d.secondaryColor !== undefined ||
        d.logoUrl !== undefined ||
        d.stripImageUrl !== undefined ||
        d.promoMessage !== undefined ||
        d.promoStartsAt !== undefined ||
        d.promoEndsAt !== undefined ||
        d.promoDays !== undefined ||
        d.birthdayRewardEnabled !== undefined ||
        d.birthdayRewardName !== undefined

      if (updatesProgram) {
        await prisma.$executeRaw`
          UPDATE cash.wallet_programs
          SET
            card_prefix = CASE WHEN ${d.cardPrefix !== undefined} THEN ${d.cardPrefix} ELSE card_prefix END,
            pass_style = CASE WHEN ${d.passStyle !== undefined} THEN ${d.passStyle} ELSE pass_style END,
            branding = branding || ${JSON.stringify(brandingPatch)}::jsonb,
            updated_at = now()
          WHERE tenant_id = ${tenant.id}::uuid
        `
      }
      return res.json({ ok: true })
    }
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
})

// ── stats ─────────────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/stats', async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)

    const dayStart = new Date()
    dayStart.setHours(0, 0, 0, 0)

    const [visitsToday, topupsToday, pendingRewards] = await Promise.all([
      prisma.visit.count({
        where: { card: { tenantId: tenant.id }, scannedAt: { gte: dayStart } },
      }),
      prisma.transaction.aggregate({
        where: { card: { tenantId: tenant.id }, type: 'TOPUP', createdAt: { gte: dayStart } },
        _sum: { amountCentavos: true }, _count: true,
      }),
      prisma.loyaltyCard.aggregate({
        where: { tenantId: tenant.id, pendingRewards: { gt: 0 } },
        _sum: { pendingRewards: true },
      }),
    ])

    return res.json({
      visitsToday,
      topupsTodayCount: topupsToday._count,
      topupsTodayMXN:   fmt(topupsToday._sum.amountCentavos ?? 0),
      pendingRewards:   pendingRewards._sum.pendingRewards ?? 0,
    })
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
})

// ── analytics ─────────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/analytics', async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)

    const now = new Date()
    const thirtyDaysAgo = new Date(now); thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30); thirtyDaysAgo.setHours(0,0,0,0)
    const eightWeeksAgo = new Date(now); eightWeeksAgo.setDate(eightWeeksAgo.getDate() - 56); eightWeeksAgo.setHours(0,0,0,0)
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1)

    const [
      recentVisits, topCards, recentUsers, allCards,
      topupsThisMonth, rewardsThisMonth, activeCustomersLast30,
      totalCustomers, totalPurchasesAgg, allVisitsSums, activeRewardConfig,
    ] = await Promise.all([
      prisma.visit.findMany({ where: { card: { tenantId: tenant.id }, scannedAt: { gte: thirtyDaysAgo } }, select: { scannedAt: true } }),
      prisma.loyaltyCard.findMany({ where: { tenantId: tenant.id }, orderBy: { totalVisits: 'desc' }, take: 10, include: { user: { select: { id: true, name: true } } } }),
      prisma.user.findMany({ where: { tenantId: tenant.id, role: 'CUSTOMER', createdAt: { gte: eightWeeksAgo } }, select: { createdAt: true } }),
      prisma.loyaltyCard.findMany({ where: { tenantId: tenant.id }, select: { balanceCentavos: true } }),
      prisma.transaction.aggregate({ where: { card: { tenantId: tenant.id }, type: 'TOPUP', createdAt: { gte: monthStart } }, _sum: { amountCentavos: true } }),
      prisma.rewardRedemption.count({ where: { card: { tenantId: tenant.id }, redeemedAt: { gte: monthStart } } }),
      prisma.visit.findMany({ where: { card: { tenantId: tenant.id }, scannedAt: { gte: thirtyDaysAgo } }, select: { cardId: true }, distinct: ['cardId'] }),
      prisma.user.count({ where: { tenantId: tenant.id, role: 'CUSTOMER' } }),
      prisma.transaction.aggregate({ where: { card: { tenantId: tenant.id }, type: 'PURCHASE' }, _sum: { amountCentavos: true } }),
      prisma.loyaltyCard.aggregate({ where: { tenantId: tenant.id }, _sum: { totalVisits: true } }),
      prisma.rewardConfig.findFirst({ where: { tenantId: tenant.id, isActive: true }, orderBy: { activatedAt: 'desc' } }),
    ])

    const visitCountByDay = {}
    for (const v of recentVisits) {
      const ds = v.scannedAt.toISOString().slice(0, 10)
      visitCountByDay[ds] = (visitCountByDay[ds] ?? 0) + 1
    }
    const visitsByDay = []
    for (let i = 29; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i)
      const ds = d.toISOString().slice(0, 10)
      visitsByDay.push({ date: ds, count: visitCountByDay[ds] ?? 0 })
    }

    const topCustomers = topCards.map(c => ({
      id: c.userId, name: c.user?.name ?? 'Sin nombre',
      cardNumber: c.cardNumber, totalVisits: c.totalVisits, balanceMXN: fmt(c.balanceCentavos),
    }))

    const MONTHS = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic']
    const todayDow  = now.getDay()
    const daysToMon = todayDow === 0 ? 6 : todayDow - 1
    const thisWeekMon = new Date(now); thisWeekMon.setDate(now.getDate() - daysToMon); thisWeekMon.setHours(0,0,0,0)
    const weekBuckets = []
    for (let i = 7; i >= 0; i--) {
      const ws = new Date(thisWeekMon); ws.setDate(thisWeekMon.getDate() - i * 7)
      weekBuckets.push({ weekStart: ws, label: `${MONTHS[ws.getMonth()]} ${ws.getDate()}` })
    }
    const newCustomersByWeek = weekBuckets.map(({ weekStart, label }, idx) => {
      const next = idx < weekBuckets.length - 1 ? weekBuckets[idx + 1].weekStart : new Date(now.getTime() + 86400000)
      const count = recentUsers.filter(u => u.createdAt >= weekStart && u.createdAt < next).length
      return { week: label, count }
    })

    const totalBalanceCentavos = allCards.reduce((s, c) => s + c.balanceCentavos, 0)
    const trueAvg     = totalCustomers > 0 ? Math.round(((allVisitsSums._sum.totalVisits ?? 0) / totalCustomers) * 10) / 10 : 0
    const retentionRate = totalCustomers > 0 ? Math.round((activeCustomersLast30.length / totalCustomers) * 100) : 0
    const totalRevenueCentavos = Math.abs(totalPurchasesAgg._sum.amountCentavos ?? 0)
    const totalAllTimeVisits   = allVisitsSums._sum.totalVisits ?? 0
    const avgTicketCentavos    = totalAllTimeVisits > 0 ? Math.round(totalRevenueCentavos / totalAllTimeVisits) : 0
    const visitsRequired       = activeRewardConfig?.visitsRequired ?? 10
    const rewardCostCentavos   = activeRewardConfig?.rewardCostCentavos ?? 0
    const revenuePerCycle      = avgTicketCentavos * visitsRequired
    const marginPerCycle       = revenuePerCycle - rewardCostCentavos
    const marginPercent        = revenuePerCycle > 0 ? Math.round((marginPerCycle / revenuePerCycle) * 100) : null

    return res.json({
      visitsByDay, topCustomers, newCustomersByWeek,
      totalBalance:             fmt(totalBalanceCentavos),
      topupsThisMonth:          fmt(topupsThisMonth._sum.amountCentavos ?? 0),
      rewardsRedeemedThisMonth: rewardsThisMonth,
      avgVisitsPerCustomer:     trueAvg,
      retentionRate,
      profitability: {
        avgTicketMXN: fmt(avgTicketCentavos), revenuePerCycleMXN: fmt(revenuePerCycle),
        rewardCostMXN: fmt(rewardCostCentavos), marginPerCycleMXN: fmt(marginPerCycle),
        marginPercent, visitsRequired, rewardCostConfigured: rewardCostCentavos > 0,
      },
    })
  } catch (err) {
    console.error('[analytics]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── customers ─────────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/customers', async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)

    const page   = Math.max(1, parseInt(req.query.page  || '1')  || 1)
    const limit  = Math.max(1, Math.min(parseInt(req.query.limit || '20') || 20, 100))
    const search = (req.query.search || '').trim().slice(0, 50)
    const sort   = req.query.sort || 'recent'
    const skip   = (page - 1) * limit

    const where = search
      ? { tenantId: tenant.id, role: 'CUSTOMER', OR: [
          { name: { contains: search } }, { phone: { contains: search } },
          { email: { contains: search } }, { card: { cardNumber: { contains: search } } },
        ] }
      : { tenantId: tenant.id, role: 'CUSTOMER' }

    const purchaseInclude = {
      visits:       { orderBy: { scannedAt: 'desc' }, take: 1 },
      transactions: { where: { type: 'PURCHASE' }, select: { amountCentavos: true } },
    }

    const toCustomer = u => {
      const ltvCentavos = (u.card?.transactions ?? []).reduce((s, t) => s + Math.abs(t.amountCentavos), 0)
      return {
        id: u.id, name: u.name, phone: u.phone, email: u.email,
        cardNumber:      u.card?.cardNumber   ?? '',
        cardId:          u.card?.id           ?? '',
        balanceMXN:      fmt(u.card?.balanceCentavos ?? 0),
        balanceCentavos: u.card?.balanceCentavos ?? 0,
        totalVisits:     u.card?.totalVisits     ?? 0,
        visitsThisCycle: u.card?.visitsThisCycle ?? 0,
        pendingRewards:  u.card?.pendingRewards  ?? 0,
        lastVisit:       u.card?.visits[0]?.scannedAt?.toISOString() ?? null,
        createdAt:       u.createdAt.toISOString(),
        ltvCentavos, ltvMXN: fmt(ltvCentavos),
      }
    }

    if (sort === 'inactive' || sort === 'ltv') {
      const [allUsers, total] = await Promise.all([
        prisma.user.findMany({ where, include: { card: { include: purchaseInclude } } }),
        prisma.user.count({ where }),
      ])
      if (sort === 'inactive') {
        allUsers.sort((a, b) => {
          const ad = a.card?.visits[0]?.scannedAt ?? null
          const bd = b.card?.visits[0]?.scannedAt ?? null
          if (!ad && !bd) return 0; if (!ad) return -1; if (!bd) return 1
          return ad.getTime() - bd.getTime()
        })
      } else {
        allUsers.sort((a, b) => {
          const al = (a.card?.transactions ?? []).reduce((s, t) => s + Math.abs(t.amountCentavos), 0)
          const bl = (b.card?.transactions ?? []).reduce((s, t) => s + Math.abs(t.amountCentavos), 0)
          return bl - al
        })
      }
      return res.json({ customers: allUsers.slice(skip, skip + limit).map(toCustomer), total, page, totalPages: Math.ceil(total / limit) })
    }

    const orderBy =
      sort === 'visits'  ? { card: { totalVisits: 'desc' } }
      : sort === 'balance' ? { card: { balanceCentavos: 'desc' } }
      : { createdAt: 'desc' }

    const [users, total] = await Promise.all([
      prisma.user.findMany({ where, include: { card: { include: purchaseInclude } }, orderBy, skip, take: limit }),
      prisma.user.count({ where }),
    ])

    return res.json({ customers: users.map(toCustomer), total, page, totalPages: Math.ceil(total / limit) })
  } catch (err) {
    console.error('[customers]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── reward-config ─────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/reward-config', async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)
    const [active, history] = await Promise.all([
      prisma.rewardConfig.findFirst({ where: { tenantId: tenant.id, isActive: true }, orderBy: { activatedAt: 'desc' } }),
      prisma.rewardConfig.findMany({ where: { tenantId: tenant.id, isActive: false }, orderBy: { activatedAt: 'desc' }, take: 10 }),
    ])
    return res.json({ active, history })
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
})

const handleRewardConfigUpdate = async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)
    const { visitsRequired, rewardName, rewardDescription, rewardCostCentavos } = req.body
    if (!visitsRequired || !rewardName) return res.status(400).json({ error: 'visitsRequired and rewardName are required' })
    const newConfig = await prisma.$transaction(async tx => {
      await tx.rewardConfig.updateMany({ where: { tenantId: tenant.id, isActive: true }, data: { isActive: false } })
      return tx.rewardConfig.create({
        data: { tenantId: tenant.id, visitsRequired: parseInt(visitsRequired), rewardName, rewardDescription: rewardDescription ?? null, rewardCostCentavos: rewardCostCentavos ?? 0, isActive: true },
      })
    })
    return res.json({ ok: true, newConfig })
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
}

app.put('/api/:slug/admin/reward-config',   handleRewardConfigUpdate)
app.patch('/api/:slug/admin/reward-config', handleRewardConfigUpdate)

// ── staff ─────────────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/staff', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    {
      const rows = await prisma.$queryRaw`
        SELECT
          id::text,
          name,
          phone,
          email,
          CASE WHEN lower(name) = 'admin' THEN 'ADMIN' ELSE 'STAFF' END AS role,
          status,
          NULL::jsonb AS permissions,
          NULL::timestamptz AS "invitedAt",
          NULL::timestamptz AS "disabledAt",
          created_at AS "createdAt",
          updated_at AS "updatedAt"
        FROM platform.staff_members
        WHERE tenant_id = ${ctx.tenantId}::uuid
        ORDER BY
          CASE WHEN lower(name) = 'admin' THEN 0 ELSE 1 END,
          CASE status WHEN 'active' THEN 0 WHEN 'invited' THEN 1 ELSE 2 END,
          created_at ASC
      `
      return res.json({ staff: rows.map(staffDto) })
    }
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
})

app.post('/api/:slug/admin/staff', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const role = normalizeRole(req.body.role)
    const name = String(req.body.name || '').trim()
    const phone = String(req.body.phone || '').trim() || null
    const email = String(req.body.email || '').trim() || null
    const status = req.body.status === 'active' ? 'active' : 'invited'
    const permissions = req.body.permissions && typeof req.body.permissions === 'object'
      ? req.body.permissions
      : DEFAULT_PERMISSIONS[role]

    if (!name) return res.status(400).json({ error: 'name is required' })
    if (!phone && !email) return res.status(400).json({ error: 'phone or email is required' })

    {
      const rows = await prisma.$queryRaw`
        INSERT INTO platform.staff_members (
          tenant_id,
          location_id,
          name,
          phone,
          email,
          status
        )
        VALUES (
          ${ctx.tenantId}::uuid,
          ${ctx.locationId}::uuid,
          ${name},
          ${phone},
          ${email},
          ${status}
        )
        RETURNING
          id::text,
          name,
          phone,
          email,
          CASE WHEN lower(name) = 'admin' THEN 'ADMIN' ELSE 'STAFF' END AS role,
          status,
          NULL::jsonb AS permissions,
          NULL::timestamptz AS "invitedAt",
          NULL::timestamptz AS "disabledAt",
          created_at AS "createdAt",
          updated_at AS "updatedAt"
      `
      return res.status(201).json({ staff: staffDto(rows[0]) })
    }
  } catch (err) {
    if (err.code === 'P2010' || /unique/i.test(err.message)) {
      return res.status(409).json({ error: 'Staff member already exists for this business' })
    }
    return res.status(500).json({ error: err.message })
  }
})

app.patch('/api/:slug/admin/staff/:staffId', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const hasName = Object.prototype.hasOwnProperty.call(req.body, 'name')
    const hasPhone = Object.prototype.hasOwnProperty.call(req.body, 'phone')
    const hasEmail = Object.prototype.hasOwnProperty.call(req.body, 'email')
    const hasRole = Object.prototype.hasOwnProperty.call(req.body, 'role')
    const hasStatus = Object.prototype.hasOwnProperty.call(req.body, 'status')
    const hasPermissions = Object.prototype.hasOwnProperty.call(req.body, 'permissions')
    const status = hasStatus && ['active', 'invited', 'disabled'].includes(req.body.status) ? req.body.status : null

    {
      const rows = await prisma.$queryRaw`
        UPDATE platform.staff_members
        SET
          name = CASE WHEN ${hasName} THEN ${String(req.body.name || '').trim()} ELSE name END,
          phone = CASE WHEN ${hasPhone} THEN NULLIF(${String(req.body.phone || '').trim()}, '') ELSE phone END,
          email = CASE WHEN ${hasEmail} THEN NULLIF(${String(req.body.email || '').trim()}, '') ELSE email END,
          status = CASE WHEN ${hasStatus} THEN COALESCE(${status}, status) ELSE status END,
          updated_at = now()
        WHERE id = ${req.params.staffId}::uuid
          AND tenant_id = ${ctx.tenantId}::uuid
        RETURNING
          id::text,
          name,
          phone,
          email,
          CASE WHEN lower(name) = 'admin' THEN 'ADMIN' ELSE 'STAFF' END AS role,
          status,
          NULL::jsonb AS permissions,
          NULL::timestamptz AS "invitedAt",
          CASE WHEN status = 'disabled' THEN updated_at ELSE NULL END AS "disabledAt",
          created_at AS "createdAt",
          updated_at AS "updatedAt"
      `
      if (!rows[0]) return res.status(404).json({ error: 'Staff member not found' })
      return res.json({ staff: staffDto(rows[0]) })
    }
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
})

app.delete('/api/:slug/admin/staff/:staffId', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    {
      const rows = await prisma.$queryRaw`
        UPDATE platform.staff_members
        SET status = 'disabled', updated_at = now()
        WHERE id = ${req.params.staffId}::uuid
          AND tenant_id = ${ctx.tenantId}::uuid
        RETURNING id::text
      `
      if (!rows[0]) return res.status(404).json({ error: 'Staff member not found' })
      return res.json({ ok: true })
    }
  } catch (err) {
    return res.status(500).json({ error: err.message })
  }
})

// ── business hours (linked to conversaflow.businesses) ────────────────────────

const DAY_NUM_TO_ID   = { '0':'sun','1':'mon','2':'tue','3':'wed','4':'thu','5':'fri','6':'sat' }
const DAY_ID_TO_NUM   = { sun:'0', mon:'1', tue:'2', wed:'3', thu:'4', fri:'5', sat:'6' }

function openTimesToHours(openTimes) {
  const result = {}
  const days = openTimes?.days ?? {}
  for (const [numStr, val] of Object.entries(days)) {
    const id = DAY_NUM_TO_ID[numStr]
    if (!id) continue
    result[id] = val.closed ? { open: false, from: '00:00', to: '00:00' } : { open: true, from: val.open || '08:00', to: val.close || '20:00' }
  }
  for (const id of Object.values(DAY_NUM_TO_ID)) {
    if (!result[id]) result[id] = { open: true, from: '08:00', to: '20:00' }
  }
  return result
}

function hoursToOpenTimes(hours, timezone) {
  const days = {}
  for (const [id, h] of Object.entries(hours)) {
    const num = DAY_ID_TO_NUM[id]
    if (!num) continue
    days[num] = h.open ? { open: h.from, close: h.to } : { closed: true }
  }
  return { days, timezone: timezone || 'America/Mexico_City' }
}

app.get('/api/:slug/admin/hours', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) {
      const dflt = Object.fromEntries(Object.values(DAY_NUM_TO_ID).map(id => [id, { open: true, from: '08:00', to: '20:00' }]))
      return res.json({ hours: dflt, timezone: 'America/Mexico_City', businessId: null })
    }
    {
      const rows = await prisma.$queryRaw`
        SELECT weekly_hours, timezone
        FROM commerce.business_hours
        WHERE tenant_id = ${ctx.tenantId}::uuid
          AND location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid
        ORDER BY created_at DESC
        LIMIT 1
      `
      const dflt = Object.fromEntries(Object.values(DAY_NUM_TO_ID).map(id => [id, { open: true, from: '08:00', to: '20:00' }]))
      const weeklyHours = rows[0]?.weekly_hours
      const hours = weeklyHours?.days ? openTimesToHours(weeklyHours) : (weeklyHours && Object.keys(weeklyHours).length ? weeklyHours : dflt)
      return res.json({ hours, timezone: rows[0]?.timezone || ctx.tenant.timezone || 'America/Mexico_City', businessId: ctx.tenantId })
    }
  } catch (err) {
    console.error('[hours GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.patch('/api/:slug/admin/hours', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)
    const { hours, timezone } = req.body
    if (!hours) return res.status(400).json({ error: 'hours required' })
    {
      const updated = await prisma.$queryRaw`
        UPDATE commerce.business_hours
        SET
          weekly_hours = ${JSON.stringify(hours)}::jsonb,
          timezone = ${timezone || ctx.tenant.timezone || 'America/Mexico_City'},
          updated_at = now()
        WHERE tenant_id = ${ctx.tenantId}::uuid
          AND location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid
        RETURNING id::text
      `
      if (!updated[0]) {
        await prisma.$executeRaw`
          INSERT INTO commerce.business_hours (tenant_id, location_id, timezone, weekly_hours)
          VALUES (
            ${ctx.tenantId}::uuid,
            ${ctx.locationId}::uuid,
            ${timezone || ctx.tenant.timezone || 'America/Mexico_City'},
            ${JSON.stringify(hours)}::jsonb
          )
        `
      }
      return res.json({ ok: true })
    }
  } catch (err) {
    console.error('[hours PATCH]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── KDS orders ────────────────────────────────────────────────────────────────

const ORDER_STATUS_MAP = {
  active: ['new', 'accepted', 'preparing', 'ready'],
  completed: ['completed'],
  cancelled: ['cancelled'],
  all: ['new', 'accepted', 'preparing', 'ready', 'completed', 'cancelled'],
}

app.get('/api/:slug/orders', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const filter = req.query.filter || 'active'
    const statuses = ORDER_STATUS_MAP[filter] || ORDER_STATUS_MAP.all

    {
      const rows = await prisma.$queryRaw`
        SELECT
          t.id::text AS ticket_id,
          t.status::text,
          t.customer_name,
          t.customer_phone,
          t.station_id::text,
          s.name AS station_name,
          t.customer_note,
          (t.total_cents::numeric / 100.0) AS total_amount,
          t.created_at,
          t.updated_at,
          count(i.id)::int AS items_count,
          COALESCE(
            jsonb_agg(
              jsonb_build_object(
                'ticket_item_id', i.id::text,
                'name', i.name,
                'quantity', i.quantity,
                'variant_name', i.variant_name,
                'notes', i.notes,
                'unit_price', (i.unit_price_cents::numeric / 100.0),
                'is_cancelled', i.is_cancelled
              )
              ORDER BY i.display_order ASC
            ) FILTER (WHERE i.id IS NOT NULL),
            '[]'::jsonb
          ) AS items
        FROM kds.tickets AS t
        LEFT JOIN kds.stations AS s
          ON s.id = t.station_id
        LEFT JOIN kds.ticket_items AS i
          ON i.ticket_id = t.id
        WHERE t.tenant_id = ${ctx.tenantId}::uuid
          AND (${ctx.locationId}::uuid IS NULL OR t.location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
          AND t.status::text IN (${Prisma.join(statuses)})
        GROUP BY t.id, s.id
        ORDER BY t.created_at DESC
        LIMIT 100
      `
      return res.json({ orders: rows })
    }
  } catch (err) {
    console.error('[orders GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.post('/api/:slug/orders/:ticketId/transition', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const targetStatus = req.body.target_status || req.body.to_status
    if (!ORDER_STATUS_MAP.all.includes(targetStatus)) {
      return res.status(400).json({ error: 'Invalid target status' })
    }

    {
      const rows = await prisma.$queryRaw`
        UPDATE kds.tickets
        SET status = ${targetStatus}, updated_at = now()
        WHERE id = ${req.params.ticketId}::uuid
          AND tenant_id = ${ctx.tenantId}::uuid
          AND (${ctx.locationId}::uuid IS NULL OR location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
        RETURNING id::text AS ticket_id, status
      `
      if (!rows[0]) return res.status(404).json({ error: 'Ticket not found' })
      return res.json({ ok: true, ticket: rows[0] })
    }
  } catch (err) {
    console.error('[orders transition]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── KDS devices ───────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/devices', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    {
      const rows = await prisma.$queryRaw`
        SELECT
          ds.id::text AS device_id,
          ds.device_name,
          ds.station_id::text,
          s.name AS station_name,
          ds.created_at,
          ds.last_seen_at AS last_used_at,
          ds.is_active,
          COALESCE(open_counts.open_count, 0)::int AS open
        FROM kds.device_sessions AS ds
        LEFT JOIN kds.stations AS s
          ON s.id = ds.station_id
        LEFT JOIN (
          SELECT station_id, count(*) AS open_count
          FROM kds.tickets
          WHERE tenant_id = ${ctx.tenantId}::uuid
            AND (${ctx.locationId}::uuid IS NULL OR location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
            AND status IN ('new', 'accepted', 'preparing', 'ready')
          GROUP BY station_id
        ) AS open_counts
          ON open_counts.station_id IS NOT DISTINCT FROM ds.station_id
        WHERE ds.tenant_id = ${ctx.tenantId}::uuid
          AND (${ctx.locationId}::uuid IS NULL OR ds.location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
          AND ds.is_active = true
        ORDER BY ds.last_seen_at DESC NULLS LAST, ds.created_at DESC
      `
      return res.json({ devices: rows })
    }
  } catch (err) {
    console.error('[devices GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/:slug/admin/stations', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const rows = await prisma.$queryRaw`
      SELECT id::text, station_key, name, status
      FROM kds.stations
      WHERE tenant_id = ${ctx.tenantId}::uuid
        AND (${ctx.locationId}::uuid IS NULL OR location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
        AND status = 'active'
      ORDER BY name ASC
    `
    return res.json({ stations: rows })
  } catch (err) {
    console.error('[stations GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.get('/api/:slug/admin/devices/pairing', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const payload = await callKdsPairingBackend('admin_list', {
      tenant_id: ctx.tenantId,
      location_id: ctx.locationId,
    })
    return res.json(payload)
  } catch (err) {
    console.error('[pairing list]', err.message)
    return res.status(err.status || 500).json(err.payload || { error: err.message })
  }
})

app.post('/api/:slug/admin/devices/pairing-pin', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const deviceName = String(req.body.device_name || req.body.deviceName || '').trim()
    const stationId = String(req.body.station_id || req.body.stationId || '').trim()
    if (!deviceName || !stationId) return res.status(400).json({ error: 'device_name and station_id are required' })

    const payload = await callKdsPairingBackend('admin_create_pin', {
      tenant_id: ctx.tenantId,
      location_id: ctx.locationId,
      station_id: stationId,
      device_name: deviceName,
    })
    return res.status(201).json(payload)
  } catch (err) {
    console.error('[pairing pin]', err.message)
    return res.status(err.status || 500).json(err.payload || { error: err.message })
  }
})

app.post('/api/:slug/admin/devices/pairing/:pairingId/approve', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)
    const userId = getCurrentUserId(req)
    if (!userId) return res.status(401).json({ error: 'authentication_required' })

    const payload = await callKdsPairingBackend('admin_approve', {
      tenant_id: ctx.tenantId,
      pairing_id: req.params.pairingId,
      admin_user_id: userId,
    })
    return res.json(payload)
  } catch (err) {
    console.error('[pairing approve]', err.message)
    return res.status(err.status || 500).json(err.payload || { error: err.message })
  }
})

app.post('/api/:slug/admin/devices/pairing/:pairingId/deny', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const payload = await callKdsPairingBackend('admin_deny', {
      tenant_id: ctx.tenantId,
      pairing_id: req.params.pairingId,
    })
    return res.json(payload)
  } catch (err) {
    console.error('[pairing deny]', err.message)
    return res.status(err.status || 500).json(err.payload || { error: err.message })
  }
})

app.post('/api/:slug/admin/devices/provision', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const deviceName = String(req.body.device_name || req.body.deviceName || '').trim()
    const stationId = String(req.body.station_id || req.body.stationId || '').trim() || null
    if (!deviceName) return res.status(400).json({ error: 'device_name is required' })

    {
      const rows = await prisma.$queryRaw`
        WITH token AS (
          SELECT encode(gen_random_bytes(32), 'hex') AS value
        ),
        inserted AS (
          INSERT INTO kds.device_sessions (tenant_id, location_id, device_name, station_id, token_hash)
          SELECT
            ${ctx.tenantId}::uuid,
            ${ctx.locationId}::uuid,
            ${deviceName},
            ${stationId}::uuid,
            encode(sha256(token.value::bytea), 'hex')
          FROM token
          RETURNING id::text AS device_id, tenant_id::text, device_name, station_id::text, created_at, is_active
        )
        SELECT inserted.*, token.value AS token
        FROM inserted, token
      `
      return res.status(201).json({ device: rows[0] })
    }
  } catch (err) {
    console.error('[devices provision]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.post('/api/:slug/admin/devices/:deviceId/revoke', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const reason = String(req.body.reason || 'removed_from_dashboard').trim() || 'removed_from_dashboard'
    const revokedBy = getCurrentUserId(req)

    {
      const rows = await prisma.$queryRaw`
        UPDATE kds.device_sessions
        SET
          is_active = false,
          revoked_at = COALESCE(revoked_at, now()),
          revoked_by = COALESCE(${revokedBy}::uuid, revoked_by),
          revocation_reason = ${reason}
        WHERE id = ${req.params.deviceId}::uuid
          AND tenant_id = ${ctx.tenantId}::uuid
          AND (${ctx.locationId}::uuid IS NULL OR location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
        RETURNING id::text AS device_id, revoked_at
      `
      if (!rows[0]) return res.status(404).json({ error: 'Device not found' })
      _kdsHeartbeats.delete(req.params.deviceId)
      return res.json({ ok: true, device_id: rows[0].device_id, revoked_at: rows[0].revoked_at })
    }
  } catch (err) {
    console.error('[devices revoke]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

app.patch('/api/:slug/admin/devices/:deviceId', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    const isActive = req.body.is_active ?? req.body.isActive
    const revokedBy = getCurrentUserId(req)
    const shouldRevoke = isActive === false
    {
      const rows = await prisma.$queryRaw`
        UPDATE kds.device_sessions
        SET
          is_active = COALESCE(${typeof isActive === 'boolean' ? isActive : null}, is_active),
          revoked_at = CASE
            WHEN ${shouldRevoke} THEN COALESCE(revoked_at, now())
            ELSE revoked_at
          END,
          revoked_by = CASE
            WHEN ${shouldRevoke} THEN COALESCE(${revokedBy}::uuid, revoked_by)
            ELSE revoked_by
          END,
          revocation_reason = CASE
            WHEN ${shouldRevoke} THEN COALESCE(${req.body.revocation_reason || req.body.reason || 'removed_from_dashboard'}, revocation_reason)
            ELSE revocation_reason
          END,
          device_name = CASE
            WHEN ${Object.prototype.hasOwnProperty.call(req.body, 'device_name')} THEN ${String(req.body.device_name || '').trim()}
            ELSE device_name
          END,
          station_id = CASE
            WHEN ${Object.prototype.hasOwnProperty.call(req.body, 'station_id')} THEN NULLIF(${String(req.body.station_id || '').trim()}, '')::uuid
            ELSE station_id
          END
        WHERE id = ${req.params.deviceId}::uuid
          AND tenant_id = ${ctx.tenantId}::uuid
          AND (${ctx.locationId}::uuid IS NULL OR location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
        RETURNING id::text
      `
      if (!rows[0]) return res.status(404).json({ error: 'Device not found' })
      if (shouldRevoke) _kdsHeartbeats.delete(req.params.deviceId)
      return res.json({ ok: true })
    }
  } catch (err) {
    console.error('[devices PATCH]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── dashboard activity feed ──────────────────────────────────────────────────

app.get('/api/:slug/admin/ticker', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)

    {
      const rows = await prisma.$queryRaw`
        SELECT
          e.sequence::text,
          e.kind::text,
          e.status::text,
          e.occurred_at,
          e.payload,
          t.customer_name,
          s.name AS station_name,
          (t.total_cents::numeric / 100.0) AS total_amount
        FROM kds.ticket_events AS e
        LEFT JOIN kds.tickets AS t
          ON t.id = e.ticket_id
        LEFT JOIN kds.stations AS s
          ON s.id = t.station_id
        WHERE e.tenant_id = ${ctx.tenantId}::uuid
          AND (${ctx.locationId}::uuid IS NULL OR t.location_id IS NOT DISTINCT FROM ${ctx.locationId}::uuid)
        ORDER BY e.sequence DESC
        LIMIT 20
      `

      const events = rows.map(row => ({
        id: row.sequence,
        time: row.occurred_at?.toLocaleTimeString?.('es-MX', { hour: '2-digit', minute: '2-digit' }) ?? '',
        kind: row.kind === 'status_changed' ? 'kds' : 'ord',
        text: row.status
          ? `${row.station_name || 'KDS'} marcó ticket ${row.status}`
          : `${row.customer_name || 'Pedido WhatsApp'} actualizado`,
        actor: row.total_amount ? `$ ${Number(row.total_amount).toLocaleString('es-MX')} MXN` : null,
      }))
      return res.json({ events })
    }
  } catch (err) {
    console.error('[ticker GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── gift cards ────────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/gift-cards', async (req, res) => {
  try {
    if (!(await requireLegacyProduct(req, res, 'cash'))) return null
    const tenant = await getTenant(req.params.slug)
    if (!tenant) return notFound(res)
    const { page, limit, skip } = parsePagination(req.query)
    const [giftCards, total] = await Promise.all([
      prisma.giftCard.findMany({
        where: { tenantId: tenant.id },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.giftCard.count({ where: { tenantId: tenant.id } }),
    ])
    return res.json({
      giftCards: giftCards.map(g => ({
        id: g.id,
        code: g.code,
        amountCentavos: g.amountCentavos,
        amountMXN: fmt(g.amountCentavos),
        senderName: g.senderName,
        recipientName: g.recipientName,
        recipientEmail: g.recipientEmail,
        recipientPhone: g.recipientPhone,
        message: g.message,
        isRedeemed: g.isRedeemed,
        redeemedAt: g.redeemedAt?.toISOString() ?? null,
        expiresAt: g.expiresAt?.toISOString() ?? null,
        createdAt: g.createdAt.toISOString(),
      })),
      total,
      page,
      totalPages: Math.ceil(total / limit),
    })
  } catch (err) {
    console.error('[gift-cards GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── conversations ────────────────────────────────────────────────────────────

app.get('/api/:slug/admin/conversations', async (req, res) => {
  try {
    const ctx = await getDashboardContext(req.params.slug, req.query.locationId || null)
    if (!ctx) return notFound(res)
    if (!ctx.businessId) return businessNotLinked(res)
    const { page, limit, skip } = parsePagination(req.query)

    {
      const rows = await prisma.$queryRaw`
        SELECT
          c.id::text,
          c.status,
          NULL::text AS "currentState",
          c.metadata->>'summary' AS summary,
          c.opened_at AS "createdAt",
          co.display_name AS "customerName",
          co.phone AS "customerPhone",
          count(m.id)::int AS "messageCount",
          max(coalesce(m.created_at, m.received_at)) AS "lastMessageAt"
        FROM conversaflow.conversations AS c
        LEFT JOIN platform.contacts AS co
          ON co.id = c.contact_id
        LEFT JOIN conversaflow.messages AS m
          ON m.conversation_id = c.id
        WHERE c.tenant_id = ${ctx.tenantId}::uuid
        GROUP BY c.id, co.id
        ORDER BY COALESCE(max(coalesce(m.created_at, m.received_at)), c.opened_at) DESC
        OFFSET ${skip}
        LIMIT ${limit}
      `
      const countRows = await prisma.$queryRaw`
        SELECT count(*)::int AS total
        FROM conversaflow.conversations
        WHERE tenant_id = ${ctx.tenantId}::uuid
      `
      return res.json({
        conversations: rows,
        total: countRows[0]?.total ?? 0,
        page,
        totalPages: Math.ceil((countRows[0]?.total ?? 0) / limit),
      })
    }
  } catch (err) {
    console.error('[conversations GET]', err.message)
    return res.status(500).json({ error: err.message })
  }
})

// ── start ─────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '4001')

if (!process.env.VERCEL && process.env.UMI_DASHBOARD_DISABLE_LISTEN !== '1') {
  prisma.$connect().then(() => {
    app.listen(PORT, () => {
      const db = process.env.DATABASE_URL
        ? process.env.DATABASE_URL.replace(/:([^:@]+)@/, ':***@')
        : '⚠  DATABASE_URL not set'
      console.log('')
      console.log(`  Umi Dashboard API  →  http://localhost:${PORT}`)
      console.log(`  umi-cash DB        →  ${db}`)
      console.log(`  Frontend (Vite)    →  http://localhost:${process.env.VITE_DEV_PORT || '4000'}`)
      console.log('')
    })
  }).catch(err => {
    console.error('Failed to connect to database:', err.message)
    process.exit(1)
  })
}

export { app, prisma }
export default app
