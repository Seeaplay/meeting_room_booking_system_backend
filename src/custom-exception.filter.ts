import { ArgumentsHost, Catch, ExceptionFilter, HttpException } from '@nestjs/common';

@Catch(HttpException)
export class CustomExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    // 获取响应对象
    const response = host.switchToHttp().getResponse();
    response.statusCode = exception.getStatus();

    const res = exception.getResponse() as {message: string[]}

    response
      .json({
        code: exception.getStatus(),
        message: 'fail',
        data: res?.message?.join ? res?.message?.join(',') : exception.message,
      })
      .end();
  }
}
