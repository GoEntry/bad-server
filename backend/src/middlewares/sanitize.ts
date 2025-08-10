import { NextFunction, Request, Response } from 'express'
import xss from 'xss'

// Настройка XSS фильтра - более строгая конфигурация
const xssOptions = {
    whiteList: {}, // Запрещаем все HTML теги
    stripIgnoreTag: true, // Удаляем неразрешенные теги
    stripIgnoreTagBody: ['script'], // Удаляем содержимое script тегов
    onIgnoreTagAttr: function (tag: string, name: string, value: string) {
        // Блокируем все атрибуты событий (onload, onclick и т.д.)
        if (name.startsWith('on')) {
            return '';
        }
    }
}

// Санитизация от XSS атак
export const sanitizeXSS = (req: Request, _res: Response, next: NextFunction) => {
    const sanitizeObj = (obj: any): any => {
        if (typeof obj === 'string') {
            return xss(obj, xssOptions)
        }
        if (typeof obj === 'object' && obj !== null) {
            const result = { ...obj }
            Object.keys(result).forEach(key => {
                result[key] = sanitizeObj(result[key])
            })
            return result
        }
        return obj
    }

    if (req.body) {
        req.body = sanitizeObj(req.body)
    }
    if (req.query) {
        req.query = sanitizeObj(req.query)
    }
    if (req.params) {
        req.params = sanitizeObj(req.params)
    }

    next()
}

// Защита от NoSQL инъекций
export const sanitizeNoSQL = (req: Request, res: Response, next: NextFunction) => {
    const sanitizeObj = (obj: any, path = ''): any => {
        if (typeof obj === 'object' && obj !== null) {
            const result = { ...obj }
            Object.keys(result).forEach(key => {
                // Блокируем любые ключи начинающиеся с $ или содержащие точки
                if (key.startsWith('$') || key.includes('.')) {
                    // Выбрасываем ошибку для прерывания выполнения
                    throw new Error('NoSQL injection detected')
                }
                
                // Рекурсивно проверяем вложенные объекты
                if (typeof result[key] === 'object' && result[key] !== null) {
                    result[key] = sanitizeObj(result[key], path ? `${path}.${key}` : key)
                }
            })
            return result
        }
        return obj
    }

    try {
        if (req.body) {
            req.body = sanitizeObj(req.body)
        }
        if (req.query) {
            req.query = sanitizeObj(req.query)
        }
        
        next()
    } catch (error) {
        return res.status(400).json({
            message: 'Потенциальная NoSQL инъекция обнаружена'
        })
    }
}

export default { sanitizeXSS, sanitizeNoSQL } 