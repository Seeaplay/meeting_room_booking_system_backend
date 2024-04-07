import { CanActivate, ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';


// 权限守卫-用户校验用户有那些权限
@Injectable()
export class PermissionGuard implements CanActivate {
  
  // 用户访问元数据
  @Inject()
  private reflector: Reflector;
  
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // 获取http请求对象
    const request = context.switchToHttp().getRequest();

    // 判断没有用户信息
    if(!request.user) {
      return true;
    }

    // 获取用户权限
    const permissions = request.user.permissions;

    // 获取 controller 和 handler  上的 元数据-没有就不需要权限校验
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>('require-permission', [
      context.getClass(),
      context.getHandler(),
    ])

    // 没有得到权限
    if(!requiredPermissions){
      return true;
    }

    //  遍历获取到的权限
    for(let i = 0; i < requiredPermissions.length; i++){
      //获取当前权限
      const curPermission = requiredPermissions[i];
      // 判断用户权限中是否包含当前权限
      const found = permissions.find(item => item.code === curPermission);

      // 用户权限中没有当前接口访问权限
      if(!found){
        throw new UnauthorizedException("您没有访问该接口的权限")
      }
    }

    return true;
  }
}
