/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import { tokenCookieOptions } from '../lib/insecurity'

export function logout () {
  return (req: Request, res: Response) => {
    res.clearCookie('token', tokenCookieOptions)
    res.status(200).json({ status: 'success' })
  }
}
