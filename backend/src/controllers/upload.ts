import { NextFunction, Request, Response } from 'express'
import { constants } from 'http2'
import sharp from 'sharp'
import fs from 'fs'
import BadRequestError from '../errors/bad-request-error'

export const uploadFile = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    if (!req.file) {
        return next(new BadRequestError('Файл не загружен'))
    }
    
    try {
        // Проверка минимального размера файла (2KB)
        if (req.file.size < 2048) {
            // Удаляем загруженный файл
            fs.unlinkSync(req.file.path)
            return next(new BadRequestError('Размер файла должен быть больше 2KB'))
        }

        // Проверка максимального размера файла (10MB)
        if (req.file.size > 10 * 1024 * 1024) {
            // Удаляем загруженный файл
            fs.unlinkSync(req.file.path)
            return next(new BadRequestError('Размер файла должен быть меньше 10MB'))
        }

        // Проверка что файл действительно является изображением
        try {
            const metadata = await sharp(req.file.path).metadata()
            if (!metadata.width || !metadata.height) {
                fs.unlinkSync(req.file.path)
                return next(new BadRequestError('Файл не является валидным изображением'))
            }
        } catch (error) {
            // Если sharp не может обработать файл, значит это не изображение
            fs.unlinkSync(req.file.path)
            return next(new BadRequestError('Файл не является валидным изображением'))
        }

        const fileName = `/temp/${req.file.filename}`
            
        return res.status(constants.HTTP_STATUS_CREATED).send({
            fileName,
            originalName: req.file?.originalname,
        })
    } catch (error) {
        // Удаляем файл в случае ошибки
        if (req.file?.path && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path)
        }
        return next(error)
    }
}

export default {}
