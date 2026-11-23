/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

// The attributes must match those used when the cookie is set; browsers only remove a cookie
// that a Set-Cookie header identifies with the same name, domain and path.
export const tokenCookieOptions = { httpOnly: true, secure: true, sameSite: 'strict' } as const

export function logout () {
  return (req: Request, res: Response) => {
    res.clearCookie('token', tokenCookieOptions)
    res.status(200).json({ status: 'success' })
  }
}
