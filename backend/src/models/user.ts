/* eslint-disable no-param-reassign */
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import mongoose, { Document, HydratedDocument, Model, Types } from 'mongoose'
import validator from 'validator'
import { ACCESS_TOKEN, REFRESH_TOKEN } from '../config'
import UnauthorizedError from '../errors/unauthorized-error'

export enum Role {
    Customer = 'customer',
    Admin = 'admin',
}

export interface IUser extends Document {
    name: string
    email: string
    password: string
    tokens: { token: string }[]
    roles: Role[]
    phone: string
    totalAmount: number
    orderCount: number
    orders: Types.ObjectId[]
    lastOrderDate: Date | null
    lastOrder: Types.ObjectId | null
}

interface IUserMethods {
    generateAccessToken(): string
    generateRefreshToken(): Promise<string>
    toJSON(): string
    calculateOrderStats(): Promise<void>
}

interface IUserModel extends Model<IUser, {}, IUserMethods> {
    findUserByCredentials: (
        email: string,
        password: string
    ) => Promise<HydratedDocument<IUser, IUserMethods>>
}

const userSchema = new mongoose.Schema<IUser, IUserModel, IUserMethods>(
    {
        name: {
            type: String,
            default: 'Евлампий',
            minlength: [2, 'Минимальная длина поля "name" - 2'],
            maxlength: [30, 'Максимальная длина поля "name" - 30'],
        },
        // в схеме пользователя есть обязательные email и password
        email: {
            type: String,
            required: [true, 'Поле "email" должно быть заполнено'],
            unique: true, // поле email уникально (есть опция unique: true);
            validate: {
                // для проверки email студенты используют validator
                validator: (v: string) => validator.isEmail(v),
                message: 'Поле "email" должно быть валидным email-адресом',
            },
        },
        // поле password не имеет ограничения на длину, т.к. пароль хранится в виде хэша
        password: {
            type: String,
            required: [true, 'Поле "password" должно быть заполнено'],
            minlength: [6, 'Минимальная длина поля "password" - 6'],
            select: false,
        },

        tokens: [
            {
                token: { required: true, type: String },
            },
        ],
        roles: {
            type: [String],
            enum: Object.values(Role),
            default: [Role.Customer],
        },
        phone: {
            type: String,
        },
        lastOrderDate: {
            type: Date,
            default: null,
        },
        lastOrder: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'order',
            default: null,
        },
        totalAmount: { type: Number, default: 0 },
        orderCount: { type: Number, default: 0 },
        orders: [
            {
                type: Types.ObjectId,
                ref: 'order',
            },
        ],
    },
    {
        versionKey: false,
        timestamps: true,
        // Возможно удаление пароля в контроллере создания, т.к. select: false не работает в случае создания сущности https://mongoosejs.com/docs/api/document.html#Document.prototype.toJSON()
        toJSON: {
            virtuals: true,
            transform: (_doc, ret: any) => {
                if ('tokens' in ret) delete ret.tokens
                if ('password' in ret) delete ret.password
                if ('_id' in ret) delete ret._id
                if ('roles' in ret) delete ret.roles
                return ret
            },
        },
    }
)

// пользователь создается — хеш пароль
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next()
    this.password = await bcrypt.hash(this.password, 12)
    return next()
})

// Можно лучше: централизованное создание accessToken и  refresh токена

userSchema.methods.generateAccessToken = function generateAccessToken() {
    const user = this as any
    // Создание accessToken токена возможно в контроллере авторизации
    return jwt.sign(
        {
            _id: user._id.toString(),
            email: user.email,
        },
        ACCESS_TOKEN.secret,
        {
            expiresIn: ACCESS_TOKEN.expiry,
            subject: user._id.toString(),
        }
    )
}

userSchema.methods.generateRefreshToken =
    async function generateRefreshToken() {
        const user = this as any
        // Создание refresh токена возможно в контроллере авторизации/регистрации
        const refreshToken = jwt.sign(
            {
                _id: user._id.toString(),
            },
            REFRESH_TOKEN.secret,
            {
                expiresIn: REFRESH_TOKEN.expiry,
                subject: user._id.toString(),
            }
        )

        // Можно лучше: Создаем хеш refresh токена
        const rTknHash = crypto
            .createHmac('sha256', REFRESH_TOKEN.secret)
            .update(refreshToken)
            .digest('hex')

        // Сохраняем refresh токена в базу данных, можно делать в контроллере авторизации/регистрации
        user.tokens.push({ token: rTknHash })
        await user.save()

        return refreshToken
    }

userSchema.statics.findUserByCredentials = async function findByCredentials(
    email: string,
    password: string
) {
    const user = await this.findOne({ email })
        .select('+password')
        .orFail(() => new UnauthorizedError('Неправильные почта или пароль'))
    const passwdMatch = await bcrypt.compare(password, user.password)
    if (!passwdMatch) {
        return Promise.reject(
            new UnauthorizedError('Неправильные почта или пароль')
        )
    }
    return user
}

userSchema.methods.calculateOrderStats = async function calculateOrderStats() {
    const user = this
    const orderStats = await mongoose.model('order').aggregate([
        { $match: { customer: user._id } },
        {
            $group: {
                _id: null,
                totalAmount: { $sum: '$totalAmount' },
                lastOrderDate: { $max: '$createdAt' },
                orderCount: { $sum: 1 },
                lastOrder: { $last: '$_id' },
            },
        },
    ])

    if (orderStats.length > 0) {
        const stats = orderStats[0]
        user.totalAmount = stats.totalAmount
        user.orderCount = stats.orderCount
        user.lastOrderDate = stats.lastOrderDate
        user.lastOrder = stats.lastOrder
    } else {
        user.totalAmount = 0
        user.orderCount = 0
        user.lastOrderDate = null
        user.lastOrder = null
    }

    await user.save()
}
const UserModel = mongoose.model<IUser, IUserModel>('user', userSchema)

export default UserModel
