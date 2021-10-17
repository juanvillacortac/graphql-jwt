import { arg, inputObjectType, mutationField, nonNull, objectType, queryField, nullable } from 'nexus'
import { compare, hash } from 'bcrypt'
import { getUserFromJWT } from '../lib/utils'
import { sign } from 'jsonwebtoken'
import { Prisma } from '@prisma/client'

export const User = objectType({
  name: 'User',
  definition(t) {
    t.nonNull.int('id')
    t.nonNull.string('email')
    t.nonNull.string('name')
    t.date('createdAt')
  },
})

export const UserTokenPayload = objectType({
  name: 'UserTokenPayload',
  definition(t) {
    t.nonNull.field('user', {
      type: User
    })
    t.nonNull.string('token')
  },
})

export const UserRegisterInput = inputObjectType({
  name: 'UserRegisterInput',
  definition(t) {
    t.nonNull.string('email')
    t.nonNull.string('password')
    t.nonNull.string('name')
  },
})

export const UserLoginInput = inputObjectType({
  name: 'UserLoginInput',
  definition(t) {
    t.nonNull.string('email')
    t.nonNull.string('password')
  },
})

export const UserQuery = queryField('getUser', {
  type: User,
  resolve: (_parent, _args, ctx) => getUserFromJWT(ctx),
})

export const UserRegisterMutation = mutationField('registerUser', {
  type: UserTokenPayload,
  args: {
    data: nonNull(arg({
      type: UserRegisterInput
    }))
  },
  resolve: async (_parent, args, ctx) => {
    try {
      const user = await ctx.prisma.user.create({
        data: {
          name: args.data.name,
          email: args.data.email,
          account: {
            create: {
              hash: await hash(args.data.password, 10)
            }
          }
        }
      })
      return {
        token: sign(user, process.env.JWT_SECRET),
        user,
      }
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        // The .code property can be accessed in a type-safe manner
        if (error.code === 'P2002') {
          throw new Error('Email is taken')
        }
      }
    }
  }
})

export const UserLoginMutation = mutationField('loginUser', {
  type: UserTokenPayload,
  args: {
    data: nonNull(arg({
      type: UserLoginInput
    }))
  },
  resolve: async (_parent, args, ctx) => {
    const account = await ctx.prisma.account.findFirst({
      where: {
        user: {
          email: {
            equals: args.data.email,
          },
        },
      },
      include: {
        user: true,
      }
    })
    if (account && await compare(args.data.password, account.hash)) {
      return {
        token: sign(account.user, process.env.JWT_SECRET),
        user: account.user
      }
    } else {
      throw new Error('Email or password incorrect')
    }
  },
})
