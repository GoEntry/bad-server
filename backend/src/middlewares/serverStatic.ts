import { NextFunction, Request, Response } from 'express'
import fs from 'fs'
import path from 'path'

export default function serveStatic(baseDir: string) {
    return (req: Request, res: Response, next: NextFunction) => {
        // Определяем полный путь к запрашиваемому файлу
        const filePath = path.resolve(path.join(baseDir, req.path))
        
        // Проверяем, что файл находится в разрешенной директории (защита от Path Traversal)
        const normalizedBaseDir = path.resolve(baseDir)
        if (!filePath.startsWith(normalizedBaseDir)) {
            return next()
        }

        // Проверяем, существует ли файл
        fs.access(filePath, fs.constants.F_OK, (err) => {
            if (err) {
                // Файл не существует отдаем дальше мидлварам
                return next()
            }
            // Файл существует, отправляем его клиенту
            return res.sendFile(filePath, (sendErr) => {
                if (sendErr) {
                    next(sendErr)
                }
            })
        })
    }
}
