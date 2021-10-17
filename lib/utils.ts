import jwt from 'jsonwebtoken'
import { Context } from './context'

export const getUserFromJWT = async (ctx: Context) => {
  const authHeader = ctx.request.headers['authorization']
  console.log(ctx.request.headers)
  console.log(authHeader)
  const bearerLength = 'Bearer '.length
  if (authHeader && authHeader.length > bearerLength) {
    const token = authHeader.slice(bearerLength)
    const { ok, result } = await new Promise(resolve =>
      jwt.verify(token, process.env.JWT_SECRET, (err, result) => {
        if (err) {
          resolve({
            ok: false,
            result: err
          })
        } else {
          resolve({
            ok: true,
            result,
          })
        }
      })
    )
    if (ok) {
      const user = await ctx.prisma.user.findUnique({
        where: {
          id: result.id,
        }
      })
      return user
    } else {
      throw new Error(result)
    }
  }
  throw new Error('Not authorized')
}
