import { Request, Express } from 'express'
import multer, { FileFilterCallback } from 'multer'
import path, { join } from 'path'
import crypto from 'crypto'

type DestinationCallback = (error: Error | null, destination: string) => void
type FileNameCallback = (error: Error | null, filename: string) => void

const storage = multer.diskStorage({
    destination: (
        _req: Request,
        _file: Express.Multer.File,
        cb: DestinationCallback
    ) => {
        // Используем правильный путь к папке temp
        const uploadPath = join(__dirname, '../public/temp')
        cb(null, uploadPath)
    },

    filename: (
        _req: Request,
        file: Express.Multer.File,
        cb: FileNameCallback
    ) => {
        // Безопасное именование файлов для предотвращения path traversal
        const ext = path.extname(file.originalname)
        const filename = crypto.randomUUID() + ext
        cb(null, filename)
    },
})

const types = [
    'image/png',
    'image/jpg',
    'image/jpeg',
    'image/gif',
    'image/svg+xml',
]

const fileFilter = (
    _req: Request,
    file: Express.Multer.File,
    cb: FileFilterCallback
) => {
    if (!types.includes(file.mimetype)) {
        return cb(null, false)
    }

    return cb(null, true)
}

// Ограничения размера файлов: минимум 2kb, максимум 10mb
const limits = {
    fileSize: 10 * 1024 * 1024, // 10MB максимум
}

export default multer({ 
    storage, 
    fileFilter, 
    limits
})
