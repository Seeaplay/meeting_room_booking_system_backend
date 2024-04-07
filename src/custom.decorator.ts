import { SetMetadata, createParamDecorator, ExecutionContext } from '@nestjs/common';

// 登录验证装饰器
export const RequireLogin = () => SetMetadata("require-login", true)

// 权限验证装饰器
export const RequirePermission = (...permissions: string[]) =>
  SetMetadata('require-permission', permissions);


// 获取用户信息装饰器
export const UserInfo = createParamDecorator((data:string, ctx:ExecutionContext) => {
  // 获取请求对象
  const request = ctx.switchToHttp().getRequest();

  // 没有用户信息
  if(!request.user){
    return null
  }

  return data ? request.user[data] : request.user
})