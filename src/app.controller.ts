import { Controller, Get, SetMetadata } from '@nestjs/common';
import { AppService } from './app.service';
import { RequireLogin, RequirePermission, UserInfo } from './custom.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}


  @Get('')
  getHello() {
    return "Hello World!";
  }

  @Get('aaa')
  @RequireLogin()
  @RequirePermission('ddd')
  aaaa(@UserInfo('username') username: string, @UserInfo() userinfo) {
    console.log(username);
    console.log(userinfo);
    return 'aaa';
  }

  @Get('bbb')
  bbb() {
    return 'bbb';
  }
}
