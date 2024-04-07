import { CanActivate, ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { Permission } from './user/entities/permission.entity';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { UnLoginException } from './unlogin.filter';

interface JwtUserData {
  userId: number;
  username: string;
  email: string;
  roles: string[];
  permissions: Permission[];
}

declare module 'express' {
  interface Request {
    user: JwtUserData;
  }
}

// 登录守卫-判断那些接口可以不用登录就能访问
@Injectable()
export class LoginGuard implements CanActivate {

  // 用户访问元数据
  @Inject()
  private reflector: Reflector;

  // jwt 服务
  @Inject(JwtService)
  private jwtService: JwtService;

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // 获取http请求对象
    const request = context.switchToHttp().getRequest();

    // 获取 controller 和 handler  上的 元数据-有数据的需要登录才能访问
    const requireLogin = this.reflector.getAllAndOverride('require-login', [
      context.getClass(),
      context.getHandler(),
    ]);

    // 判断当前接口是否需要登录才能访问
    if (!requireLogin) {
      return true;
    }

    // 获取传递过来的授权信息
    const authorization = request.headers.authorization;

    // 没有授权信息
    if (!authorization) {
      throw new UnLoginException('用户未登录');
    }

    try {
      // 获取token
      const token = authorization.split(' ')[1];
      // 验证token
      const data = this.jwtService.verify<JwtUserData>(token);

      // 请求中添加用户信息
      request.user = {
        userId: data.userId,
        username: data.username,
        email: data.email,
        roles: data.roles,
        permissions: data.permissions,
      };

      return true;
    } catch (e) {
      throw new UnauthorizedException('token 失效，请重新登录');
    }
  }
}
