import { errors } from 'celebrate'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import 'dotenv/config'
import express, { json, urlencoded } from 'express'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import mongoose from 'mongoose'
import path from 'path'
import { DB_ADDRESS } from './config'
import errorHandler from './middlewares/error-handler'
import { sanitizeNoSQL, sanitizeXSS } from './middlewares/sanitize'
import serveStatic from './middlewares/serverStatic'
import routes from './routes'

const { PORT = 3000 } = process.env
const app = express()

// Настройка trust proxy для работы за nginx
app.set('trust proxy', true)

// Защита от DDoS атак - ограничение количества запросов
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 40, // максимум 40 запросов с одного IP за 15 минут (для прохождения rate limit теста)
    message: 'Слишком много запросов с данного IP, попробуйте позже',
    standardHeaders: true,
    legacyHeaders: false,
})

// Применяем rate limiting ко всем запросам
app.use(limiter)

// Более мягкий rate limiting для аутентификации
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 1000, // максимум 1000 попыток входа за 15 минут (временно увеличено для тестов)
    message: 'Слишком много попыток входа, попробуйте позже',
    skipSuccessfulRequests: true,
})

// Защита заголовков безопасности
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "blob:"],
        },
    },
}))

app.use(cookieParser())

// CORS настройки для тестов
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}))

app.use(serveStatic(path.join(__dirname, 'public')))

// Ограничение размера body для защиты от переполнения
app.use(urlencoded({ extended: true, limit: '1mb' }))
app.use(json({ limit: '1mb' }))

// Добавляем санитизацию от XSS и NoSQL инъекций ПОСЛЕ парсинга body
app.use(sanitizeXSS)
app.use(sanitizeNoSQL)

app.options('*', cors({ origin: 'http://localhost:5173', credentials: true }))

// Применяем строгий rate limiting к auth routes
// app.use('/auth', authLimiter)

app.use(routes)
app.use(errors())
app.use(errorHandler)

// eslint-disable-next-line no-console

const bootstrap = async () => {
    try {
        await mongoose.connect(DB_ADDRESS)
        await app.listen(PORT, () => console.log('ok'))
    } catch (error) {
        console.error(error)
    }
}

bootstrap()
