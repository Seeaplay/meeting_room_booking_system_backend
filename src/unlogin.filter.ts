import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus } from '@nestjs/common';


export class UnLoginException {
  message: string;

  constructor(message){
    this.message = message;
  }
}

// 登录异常
@Catch(UnLoginException)
export class UnloginFilter implements ExceptionFilter {
  catch(exception: UnLoginException, host: ArgumentsHost) {
    // 获取响应对象
    const response = host.switchToHttp().getResponse();

    response.json({
      code: HttpStatus.UNAUTHORIZED,
      message: 'fail',
      data: exception.message || '用户未登录',
    }).end();
  }
}
