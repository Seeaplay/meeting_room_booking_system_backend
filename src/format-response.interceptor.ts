import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable, map } from 'rxjs';

// 响应拦截
@Injectable()
export class FormatResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // 获取响应对象
    const response = context.switchToHttp().getResponse()

    // 修改响应对象
    return next.handle().pipe(map((data) => {
      return {
        code: response.statusCode,
        message: "success",
        data
      }
    }));
  }
}
