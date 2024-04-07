import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from '@nestjs/common';
import { Observable, tap } from 'rxjs';

// 接口访问记录拦截器
@Injectable()
export class InvokeRecordInterceptor implements NestInterceptor {

  private readonly logger = new Logger(InvokeRecordInterceptor.name)

  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<any> | Promise<Observable<any>> {
    // 获取请求对象
    const request = context.switchToHttp().getRequest();
    // 获取响应对象
    const response = context.switchToHttp().getResponse();

    // 获取用户代理
    const userAgent = request.headers['user-agent'];

    // 获取请求信息，请求地址、请求方法、请求路径
    const { ip, method, path } = request;

    // 打印日志
    this.logger.debug(
      `${method} ${path} ${ip} ${userAgent}: ${context.getClass().name} ${
        context.getHandler().name
      } invoked...`,
    );
  
    this.logger.debug(
      `user: ${request.user?.userId}, ${request.user?.username}`,
    );

    // 创建时间戳
    const now = Date.now()

    return next.handle().pipe(
      tap((res) => {
        this.logger.debug(
          `${method} ${path} ${ip} ${userAgent}: ${response.statusCode}: ${Date.now() - now}ms`,
        );
        this.logger.debug(`Response: ${JSON.stringify(res)}`);
      })
    );
  }
}
