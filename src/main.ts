import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FormatResponseInterceptor } from './format-response.interceptor';
import { InvokeRecordInterceptor } from './invoke-record.interceptor';
import { UnloginFilter } from './unlogin.filter';
import { CustomExceptionFilter } from './custom-exception.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // 配置静态资源
  app.useStaticAssets('uploads', {
    prefix: '/uploads',
  });

  // 配置跨域
  app.enableCors()

  // 全局使用验证管道
  app.useGlobalPipes(new ValidationPipe())
  // 全局使用响应对象
  app.useGlobalInterceptors(new FormatResponseInterceptor());
  // 全局使用接口调用记录
  app.useGlobalInterceptors(new InvokeRecordInterceptor());
  // 全局使用登录异常处理
  app.useGlobalFilters(new UnloginFilter());
  app.useGlobalFilters(new CustomExceptionFilter());

  // 配置生成接口文档
  const config = new DocumentBuilder()
    .setTitle("会议预定系统")
    .setDescription("api 接口文档")
    .setVersion("1.0")
    .addBearerAuth({
      type: "http",
      description: "基于 jwt 的认证"
    })
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-doc', app, document)


  // 获取配置文件
  const configService = app.get(ConfigService)
  await app.listen(configService.get('nest_server_port'));
}
bootstrap();
