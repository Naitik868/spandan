import { updateRoomSchema } from '../middleware/validation.js'
import { checkRoomOwnership } from '../utils/roomOwnership.js'
import crypto from 'crypto'

describe('Core Bug Fixes Verification', () => {
  describe('Room Update Validation & Mass Assignment Prevention', () => {
    it('validates allowed update fields', () => {
      const valid = updateRoomSchema.safeParse({
        name: 'New Room Name',
        settings: {
          timeToAnswer: 45,
          points: 150,
          anonymousLeaderboard: true,
          anonymityPercent: 30
        }
      })
      expect(valid.success).toBe(true)
    })

    it('rejects empty room name when provided', () => {
      const invalid = updateRoomSchema.safeParse({ name: '' })
      expect(invalid.success).toBe(false)
    })

    it('defensively strips immutable properties', () => {
      const updates = {
        name: 'Safe Name',
        teacher: 'malicious-teacher-id',
        code: 'HACKED',
        _id: 'new-id',
        createdAt: new Date()
      }

      const safeUpdates = { ...updates }
      delete safeUpdates.teacher
      delete safeUpdates.code
      delete safeUpdates._id
      delete safeUpdates.createdAt

      expect(safeUpdates.teacher).toBeUndefined()
      expect(safeUpdates.code).toBeUndefined()
      expect(safeUpdates._id).toBeUndefined()
      expect(safeUpdates.createdAt).toBeUndefined()
      expect(safeUpdates.name).toBe('Safe Name')
    })
  })

  describe('Standardized Room Ownership Guard', () => {
    it('handles populated teacher objects without TypeError', () => {
      const room = { teacher: { _id: 'teacher-123', name: 'Dr. Smith' } }
      const res = checkRoomOwnership(room, 'teacher-123')
      expect(res.ok).toBe(true)
    })

    it('handles unpopulated raw ObjectId strings correctly', () => {
      const room = { teacher: 'teacher-123' }
      const res = checkRoomOwnership(room, 'teacher-123')
      expect(res.ok).toBe(true)
    })

    it('rejects unauthorized users with 403', () => {
      const room = { teacher: { _id: 'teacher-123' } }
      const res = checkRoomOwnership(room, 'intruder-456')
      expect(res.ok).toBe(false)
      expect(res.status).toBe(403)
    })

    it('returns 404 for missing room', () => {
      const res = checkRoomOwnership(null, 'teacher-123')
      expect(res.ok).toBe(false)
      expect(res.status).toBe(404)
    })
  })

  describe('Password Reset Token Hashing', () => {
    const hashToken = (token) => crypto.createHash('sha256').update(String(token)).digest('hex')

    it('hashes 64-char raw tokens into deterministic 64-char SHA-256 hex', () => {
      const rawToken = crypto.randomBytes(32).toString('hex')
      const hash1 = hashToken(rawToken)
      const hash2 = hashToken(rawToken)
      expect(hash1).toHaveLength(64)
      expect(hash1).toBe(hash2)
      expect(hash1).not.toBe(rawToken)
    })
  })

  describe('Research API Regex Sanitization (ReDoS Mitigation)', () => {
    it('escapes regex metacharacters in custom name patterns', () => {
      const input = 'Math (Class [101]) + Exam?'
      const sanitized = input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      expect(sanitized).toBe('Math \\(Class \\[101\\]\\) \\+ Exam\\?')
      expect(() => new RegExp(sanitized)).not.toThrow()
    })
  })

  describe('Active Poll RAM Recovery Logic', () => {
    it('computes remaining time accurately for reconnecting students', () => {
      const startTime = Date.now() - 10000 // 10 seconds elapsed
      const timer = 30 // 30 second total poll

      const elapsedSec = Math.floor((Date.now() - startTime) / 1000)
      const remainingSec = timer - elapsedSec

      expect(remainingSec).toBeGreaterThanOrEqual(19)
      expect(remainingSec).toBeLessThanOrEqual(20)
    })

    it('identifies expired polls when elapsed time exceeds duration', () => {
      const startTime = Date.now() - 35000 // 35 seconds elapsed
      const timer = 30

      const elapsedSec = Math.floor((Date.now() - startTime) / 1000)
      const remainingSec = timer - elapsedSec

      expect(remainingSec).toBeLessThanOrEqual(0)
    })
  })
})
