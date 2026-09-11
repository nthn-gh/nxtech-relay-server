/**
 * NXTech POS Pro relay — AI-assisted resume generation (Premium feature).
 *
 * Reuses the same sync_token auth as sync.js (resolveShopFromSyncToken) --
 * this route lives under a different path (/resume/generate) but is
 * authenticated exactly the same way as every other app-facing route.
 * resolveShopFromSyncToken()'s own query (sync.js) doesn't select
 * shops.tier, so the Premium-tier check below does its own follow-up
 * lookup rather than modifying that shared function.
 *
 * Rate limiting deliberately does NOT use rateLimiter.js. That module is
 * in-memory only and resets to zero on every process restart -- fine for
 * the existing free routes, but an OpenAI call costs real money per
 * request, so a restart mid-day silently re-opening a shop's quota is a
 * real cost risk here in a way it isn't elsewhere in this relay. Enforced
 * instead via a durable COUNT(*) against resume_generations, scoped to
 * the current UTC calendar day -- survives restarts.
 */
import { db, nowIso } from './db.js'
import { resolveShopFromSyncToken, readJsonBody, sendJson } from './sync.js'

// 8KB -- generous for structured resume input (each field already
// individually capped below), still bounded, matching the readJsonBody
// idiom used by every other route in this relay.
const MAX_RESUME_BODY_BYTES = 8192

const DAILY_QUOTA_PREMIUM = 30

const OPENAI_MODEL = 'gpt-4.1-mini'
const OPENAI_URL = 'https://api.openai.com/v1/chat/completions'

const SYSTEM_PROMPT = `You are a professional resume writer. Given structured information about a candidate (name, contact info, work experience, education, skills, and target role), write a clean, professional, ATS-friendly resume in plain text.

Correct grammar and tighten phrasing where helpful, but do NOT invent facts, dates, employers, job titles, schools, or credentials that are not present in the supplied information. If information for a section is missing or thin, keep that section brief rather than fabricating content to fill it out.

Output ONLY the resume text itself -- no commentary, no explanations, no markdown formatting (no #, *, -, or other markdown syntax), no preamble or sign-off.`

function startOfUtcDayIso() {
  const now = new Date()
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString()
}

function buildUserPrompt(fields) {
  return [
    `Name: ${fields.name}`,
    `Contact: ${fields.contact}`,
    `Target role: ${fields.targetRole}`,
    `Work experience:\n${fields.experience}`,
    `Education:\n${fields.education}`,
    `Skills:\n${fields.skills}`
  ].join('\n\n')
}

// POST /resume/generate  Authorization: Bearer <sync_token>
// { name, contact, targetRole, experience, education, skills }
export async function handleResumeGenerate(req, res) {
  const shop = resolveShopFromSyncToken(req)
  if (!shop) return sendJson(res, 401, { ok: false, error: 'Invalid or revoked sync token.' })

  const shopRow = db.prepare('SELECT tier FROM shops WHERE id = ?').get(shop.shop_id)
  if (!shopRow || shopRow.tier !== 'premium') {
    return sendJson(res, 403, { ok: false, error: 'AI resume generation is a Premium feature.' })
  }

  let body
  try {
    body = await readJsonBody(req, MAX_RESUME_BODY_BYTES)
  } catch (err) {
    return sendJson(res, 400, { ok: false, error: err.message })
  }

  const name = String(body.name || '').trim().slice(0, 100)
  const contact = String(body.contact || '').trim().slice(0, 200)
  const targetRole = String(body.targetRole || '').trim().slice(0, 150)
  const experience = String(body.experience || '').trim().slice(0, 3000)
  const education = String(body.education || '').trim().slice(0, 3000)
  const skills = String(body.skills || '').trim().slice(0, 3000)

  if (!name || !experience) {
    return sendJson(res, 400, { ok: false, error: 'name and experience are required.' })
  }

  const dayStart = startOfUtcDayIso()
  const { count } = db
    .prepare('SELECT COUNT(*) AS count FROM resume_generations WHERE shop_id = ? AND created_at >= ?')
    .get(shop.shop_id, dayStart)
  if (count >= DAILY_QUOTA_PREMIUM) {
    return sendJson(res, 429, {
      ok: false,
      error: `Daily resume generation limit reached (${DAILY_QUOTA_PREMIUM}/day). Try again after 00:00 UTC.`
    })
  }

  const fields = { name, contact, targetRole, experience, education, skills }
  const userPrompt = buildUserPrompt(fields)

  let completionText
  try {
    const apiRes = await fetch(OPENAI_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: OPENAI_MODEL,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userPrompt }
        ]
      })
    })

    if (!apiRes.ok) {
      // Never forward or log the raw OpenAI error body -- it's discarded
      // entirely, only the HTTP status is logged. The API key is never in
      // scope to leak here either way (it's only ever sent, never echoed).
      console.error(`[resume] OpenAI API error: HTTP ${apiRes.status}`)
      return sendJson(res, 502, { ok: false, error: 'Resume generation failed. Try again later.' })
    }

    const data = await apiRes.json()
    completionText = data?.choices?.[0]?.message?.content
    if (!completionText || typeof completionText !== 'string') {
      console.error('[resume] OpenAI response missing expected content')
      return sendJson(res, 502, { ok: false, error: 'Resume generation failed. Try again later.' })
    }
  } catch (err) {
    console.error(`[resume] OpenAI request failed: ${err.message}`)
    return sendJson(res, 502, { ok: false, error: 'Resume generation failed. Try again later.' })
  }

  const now = nowIso()
  const inputChars = JSON.stringify(fields).length
  const outputChars = completionText.length

  db.prepare(
    `INSERT INTO resume_generations (shop_id, created_at, input_chars, output_chars)
     VALUES (?, ?, ?, ?)`
  ).run(shop.shop_id, now, inputChars, outputChars)

  return sendJson(res, 200, { ok: true, resume: completionText })
}
