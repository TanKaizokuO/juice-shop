/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import config from 'config'
import { themes } from '../views/themes/themes'
import * as utils from '../lib/utils'
import { AllHtmlEntities as Entities } from 'html-entities'

import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { sequelize } from '../models'
import { AddressModel } from '../models/address'
import { BasketModel } from '../models/basket'
import { BasketItemModel } from '../models/basketitem'
import { CardModel } from '../models/card'
import { ComplaintModel } from '../models/complaint'
import { FeedbackModel } from '../models/feedback'
import { ImageCaptchaModel } from '../models/imageCaptcha'
import { MemoryModel } from '../models/memory'
import { PasskeyModel } from '../models/passkey'
import { RecycleModel } from '../models/recycle'
import { WalletModel } from '../models/wallet'
import * as db from '../data/mongodb'

const entities = new Entities()

const router = express.Router()

router.get('/', (req: Request, res: Response, next: NextFunction) => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    const email = loggedInUser.data.email

    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if (answer == null) {
        throw new Error('No answer found!')
      }
      const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
      if (question == null) {
        throw new Error('No question found!')
      }

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      res.render('dataErasureForm', {
        userEmail: email,
        securityQuestion: question.question,
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      })
    } catch (error) {
      next(error)
    }
  })()
})

interface DataErasureRequestParams {
  layout?: string
  email: string
  securityAnswer: string
}

router.post('/', (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): void => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      const userId = loggedInUser.data.id
      const email = loggedInUser.data.email
      const obscuredEmail = email.replace(/[aeiou]/gi, '*')
      const orderPrefix = security.hash(email).slice(0, 4) + '-'
      const accountEmails = await UserModel.findAll({ attributes: ['id', 'email', 'profileImage'], paranoid: false })
      if (accountEmails.some(account => account.id !== userId && account.email &&
          account.email.replace(/[aeiou]/gi, '*') === obscuredEmail &&
          security.hash(account.email).slice(0, 4) + '-' === orderPrefix)) {
        throw new Error('Cannot safely distinguish this account’s orders; manual erasure is required')
      }
      const orders: Array<{ _id: string, orderId: string }> = await db.ordersCollection.find({ email: obscuredEmail })
      const ownOrders = orders.filter(order => order.orderId.startsWith(orderPrefix))
      const memories = await MemoryModel.findAll({ where: { UserId: userId } })
      const uploadRoot = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
      const uploadPaths = memories.map(memory => memory.imagePath)
      if (loggedInUser.data.profileImage) uploadPaths.push(loggedInUser.data.profileImage)
      for (const image of uploadPaths) {
        const file = path.resolve('frontend/dist/frontend', image.replace(/^\/+/, ''))
        if (path.dirname(file) === uploadRoot && !['default.svg', 'defaultAdmin.png'].includes(path.basename(file))) {
          const shared = await MemoryModel.count({ where: { imagePath: image } })
          const sharedProfile = accountEmails.some(account => account.id !== userId && account.profileImage === image)
          if (shared <= 1 && !sharedProfile) await fs.rm(file, { force: true })
        }
      }
      for (const order of ownOrders) {
        if (/^[a-f0-9]{4}-[a-f0-9]+$/i.test(order.orderId)) {
          await fs.rm(path.join('ftp', `order_${order.orderId}.pdf`), { force: true })
        }
        await db.ordersCollection.remove({ _id: order._id })
      }
      await db.reviewsCollection.remove({ author: email })
      await sequelize.transaction(async transaction => {
        const where = { UserId: userId }
        const baskets = await BasketModel.findAll({ where, transaction })
        for (const basket of baskets) {
          await BasketItemModel.destroy({ where: { BasketId: basket.id }, transaction })
        }
        await RecycleModel.destroy({ where, transaction })
        await AddressModel.destroy({ where, force: true, transaction })
        await BasketModel.destroy({ where, transaction })
        await CardModel.destroy({ where, force: true, transaction })
        await ComplaintModel.destroy({ where, transaction })
        await FeedbackModel.destroy({ where, transaction })
        await ImageCaptchaModel.destroy({ where, transaction })
        await MemoryModel.destroy({ where, transaction })
        await PasskeyModel.destroy({ where, transaction })
        await PrivacyRequestModel.destroy({ where, transaction })
        await SecurityAnswerModel.destroy({ where, transaction })
        await WalletModel.destroy({ where, transaction })
        await UserModel.destroy({ where: { id: userId }, force: true, transaction })
      })
      for (const [token, session] of Object.entries(security.authenticatedUsers.tokenMap)) {
        if (session.data.id === userId) delete security.authenticatedUsers.tokenMap[token]
      }
      delete security.authenticatedUsers.idMap[userId]

      res.clearCookie('token')

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      const themeVars = {
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      }

      if (req.body.layout && utils.isChallengeEnabled(challenges.lfrChallenge)) {
        const filePath: string = path.resolve(req.body.layout).toLowerCase()
        const isForbiddenFile: boolean = (filePath.includes('ftp') || filePath.includes('ctf.key') || filePath.includes('encryptionkeys'))
        if (!isForbiddenFile) {
          res.render('dataErasureResult', {
            ...req.body,
            ...themeVars
          }, (error, html) => {
            if (!html || error) {
              next(new Error(error.message))
            } else {
              const sendlfrResponse: string = html.slice(0, 100) + '......'
              res.send(sendlfrResponse)
              challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
            }
          })
        } else {
          next(new Error('File access not allowed'))
        }
      } else {
        res.render('dataErasureResult', {
          ...req.body,
          ...themeVars
        })
      }
    } catch (error) {
      next(error)
    }
  })()
})

export default router
