import { Controller, Get, Post, Body, Patch, Param, Delete, Query, Inject, UnauthorizedException, ParseIntPipe, BadRequestException, DefaultValuePipe, HttpStatus, UseInterceptors, UploadedFile } from '@nestjs/common';
import { UserService } from './user.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { EmailService } from 'src/email/email.service';
import { RedisService } from 'src/redis/redis.service';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RequireLogin, UserInfo } from 'src/custom.decorator';
import { UserDetailVo } from './vo/user-info.vo';
import { UpdateUserPasswordDto } from './dto/update-user-password.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { generateParseIntPipe } from 'src/utils';
import { ApiBearerAuth, ApiBody, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { LoginUserVo } from './vo/login-user.vo';
import { RefreshTokenVo } from './vo/refresh-token.vo';
import { UserListVo } from './vo/user-list.vo';
import { FileInterceptor } from '@nestjs/platform-express';
import * as path from 'path';
import { storage } from 'src/my-file-storage';

@ApiTags('用户管理模块')
@Controller('user')
export class UserController {
  // 邮箱服务
  @Inject(EmailService)
  private emailService: EmailService;

  // redis服务
  @Inject(RedisService)
  private redisService: RedisService;

  // jwt服务
  @Inject(JwtService)
  private jwtService: JwtService;

  // 环境配置
  @Inject(ConfigService)
  private configService: ConfigService;

  constructor(private readonly userService: UserService) {}

  // 用户登录
  @ApiBody({
    type: LoginUserDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '用户不存在/密码错误',
    type: String,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '用户信息和 token',
    type: LoginUserVo,
  })
  @Post('login')
  async userLogin(@Body() loginUser: LoginUserDto) {
    // 普通用户查询
    const vo = await this.userService.login(loginUser, false);

    // 设置访问令牌
    vo.accessToken = this.jwtService.sign(
      {
        userId: vo.userInfo.id,
        username: vo.userInfo.username,
        email: vo.userInfo.email,
        roles: vo.userInfo.roles,
        permissions: vo.userInfo.permissions,
      },
      {
        // 令牌失效时间
        expiresIn:
          this.configService.get('jwt_access_token_expires_time') || '30m',
      },
    );

    // 设置刷新令牌
    vo.refreshToken = this.jwtService.sign(
      {
        userId: vo.userInfo.id,
      },
      {
        // 令牌失效时间
        expiresIn:
          this.configService.get('jwt_refresh_token_expires_time') || '7d',
      },
    );

    return vo;
  }
  // 普通用户令牌刷新
  @ApiQuery({
    name: 'refreshToken',
    type: String,
    description: '刷新 token',
    required: true,
    example: 'xxxxxxxxyyyyyyyyzzzzz',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'token 已失效，请重新登录',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '刷新成功',
    type: RefreshTokenVo,
  })
  @Get('refresh')
  async refresh(@Query('refreshToken') refreshToken: string) {
    try {
      // 解析/验证刷新令牌
      const data = this.jwtService.verify(refreshToken);

      // 通过id查询用户信息
      const user = await this.userService.findUserById(data.userId, false);

      // 设置访问令牌
      const access_token = this.jwtService.sign(
        {
          userId: user.id,
          username: user.username,
          email: user.email,
          roles: user.roles,
          permissions: user.permissions,
        },
        {
          // 令牌失效时间
          expiresIn:
            this.configService.get('jwt_access_token_expires_time') || '30m',
        },
      );

      // 设置刷新令牌
      const refresh_token = this.jwtService.sign(
        {
          userId: user.id,
        },
        {
          // 令牌失效时间
          expiresIn:
            this.configService.get('jwt_refresh_token_expires_time') || '7d',
        },
      );

      // 返回参数
      const vo = new RefreshTokenVo();
      vo.access_token = access_token;
      vo.refresh_token = refresh_token;

      return vo;
    } catch (error) {
      throw new UnauthorizedException('token 已失效，请重新登录');
    }
  }

  // 管理员登录
  @ApiBody({
    type: LoginUserDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '用户不存在/密码错误',
    type: String,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '用户信息和 token',
    type: LoginUserVo,
  })
  @Post('admin/login')
  async adminLogin(@Body() loginUser: LoginUserDto) {
    // 管理员用户查询
    const vo = await this.userService.login(loginUser, true);

    // 设置访问令牌
    vo.accessToken = this.jwtService.sign(
      {
        userId: vo.userInfo.id,
        username: vo.userInfo.username,
        email: vo.userInfo.email,
        roles: vo.userInfo.roles,
        permissions: vo.userInfo.permissions,
      },
      {
        // 令牌失效时间
        expiresIn:
          this.configService.get('jwt_access_token_expires_time') || '30m',
      },
    );

    // 设置刷新令牌
    vo.refreshToken = this.jwtService.sign(
      {
        userId: vo.userInfo.id,
      },
      {
        // 令牌失效时间
        expiresIn:
          this.configService.get('jwt_refresh_token_expires_time') || '7d',
      },
    );

    return vo;
  }
  // 管理员用户令牌刷新
  @ApiQuery({
    name: 'refreshToken',
    type: String,
    description: '刷新 token',
    required: true,
    example: 'xxxxxxxxyyyyyyyyzzzzz',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'token 已失效，请重新登录',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '刷新成功',
    type: RefreshTokenVo,
  })
  @Get('admin/refresh')
  async adminRefresh(@Query('refreshToken') refreshToken: string) {
    try {
      // 解析/验证刷新令牌
      const data = this.jwtService.verify(refreshToken);

      // 通过id查询用户信息
      const user = await this.userService.findUserById(data.userId, true);

      // 设置访问令牌
      const access_token = this.jwtService.sign(
        {
          userId: user.id,
          username: user.username,
          email: user.email,
          roles: user.roles,
          permissions: user.permissions,
        },
        {
          // 令牌失效时间
          expiresIn:
            this.configService.get('jwt_access_token_expires_time') || '30m',
        },
      );

      // 设置刷新令牌
      const refresh_token = this.jwtService.sign(
        {
          userId: user.id,
        },
        {
          // 令牌失效时间
          expiresIn:
            this.configService.get('jwt_refresh_token_expires_time') || '7d',
        },
      );

      // 返回参数
      const vo = new RefreshTokenVo();
      vo.access_token = access_token;
      vo.refresh_token = refresh_token;

      return vo;
    } catch (error) {
      throw new UnauthorizedException('token 已失效，请重新登录');
    }
  }

  // 注册
  @ApiBody({ type: RegisterUserDto })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '验证码已失效/验证码不正确/用户已存在',
    type: String,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '注册成功/失败',
    type: String,
  })
  @Post('register')
  async register(@Body() registerUser: RegisterUserDto) {
    return await this.userService.register(registerUser);
  }

  // 发送邮箱验证码
  @ApiQuery({
    name: 'address',
    type: String,
    description: '邮箱地址',
    required: true,
    example: 'xxx@xx.com',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '发送成功',
    type: String,
  })
  @Get('register-captcha')
  async captcha(@Query('address') address: string) {
    // 随机生成验证码
    const code = Math.random().toString().slice(2, 8);

    // 保存验证码到redis中，并且5分钟有效
    await this.redisService.set(`captcha_${address}`, code, 5 * 60);

    // 发送验证码到邮箱
    await this.emailService.sendMail({
      to: address,
      subject: '注册验证码',
      html: `<p>你的注册验证码是 ${code}</p>`,
    });

    return '发送成功';
  }

  // 查询用户详细信息
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'success',
    type: UserDetailVo,
  })
  @Get('info')
  @RequireLogin()
  async info(@UserInfo('userId') userId: number) {
    const user = await this.userService.findUserDetailById(userId);

    // 用户返回的数据
    const vo = new UserDetailVo();
    vo.id = user.id;
    vo.email = user.email;
    vo.username = user.username;
    vo.headPic = user.headPic;
    vo.phoneNumber = user.phoneNumber;
    vo.nickName = user.nickName;
    vo.createTime = user.createTime;
    vo.isFrozen = user.isFrozen;

    return vo;
  }

  // 修改用户密码-管理员/普通用户
  @ApiBody({
    type: UpdateUserPasswordDto,
  })
  @ApiResponse({
    type: String,
    description: '验证码已失效/不正确',
  })
  @Post(['update_password', 'admin/update_password'])
  async updatePassword(@Body() passwordDto: UpdateUserPasswordDto) {
    return await this.userService.updatePassword(passwordDto);
  }

  // 修改用户信息-管理员/普通用户
  @ApiBearerAuth()
  @ApiBody({
    type: UpdateUserDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: '验证码已失效/不正确',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: '更新成功',
    type: String,
  })
  @Post(['update', 'admin/update'])
  @RequireLogin()
  async update(
    @UserInfo('userId') userId: number,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    return await this.userService.update(userId, updateUserDto);
  }

  // 发送更新用户信息验证码
  @ApiQuery({
    name: 'address',
    description: '邮箱地址',
    type: String,
  })
  @ApiResponse({
    type: String,
    description: '发送成功',
  })
  @Get('update_password/captcha')
  async updatePasswordCaptcha(@Query('address') address: string) {
    // 随机生成验证码
    const code = Math.random().toString().slice(2, 8);

    // 保存验证码到redis中，并且10分钟有效
    await this.redisService.set(
      `update_password_captcha_${address}`,
      code,
      10 * 60,
    );

    // 发送验证码到邮箱
    await this.emailService.sendMail({
      to: address,
      subject: '更改用户信息验证码',
      html: `<p>你的验证码是 ${code}</p>`,
    });

    return '发送成功';
  }

  // 发送验证码
  @ApiBearerAuth()
  @ApiResponse({
    type: String,
    description: '发送成功',
  })
  @RequireLogin()
  @Get('update/captcha')
  async updateCaptcha(@UserInfo('email') address: string) {
    // 随机生成验证码
    const code = Math.random().toString().slice(2, 8);

    // 保存验证码到redis中，并且10分钟有效
    await this.redisService.set(
      `update_user_captcha_${address}`,
      code,
      10 * 60,
    );

    // 发送验证码到邮箱
    await this.emailService.sendMail({
      to: address,
      subject: '更改用户信息验证码',
      html: `<p>你的验证码是 ${code}</p>`,
    });

    return '发送成功';
  }

  // 冻结用户@ApiBearerAuth()
  @ApiQuery({
    name: 'id',
    description: 'userId',
    type: Number,
  })
  @ApiResponse({
    type: String,
    description: 'success',
  })
  @RequireLogin()
  @Get('freeze')
  async freeze(@Query('id') userId: number) {
    await this.userService.freezeUserById(userId);
    return 'success';
  }

  // 获取用户列表
  @ApiBearerAuth()
  @ApiQuery({
    name: 'pageNo',
    description: '第几页',
    type: Number,
  })
  @ApiQuery({
    name: 'pageSize',
    description: '每页多少条',
    type: Number,
  })
  @ApiQuery({
    name: 'username',
    description: '用户名',
    type: Number,
  })
  @ApiQuery({
    name: 'nickName',
    description: '昵称',
    type: Number,
  })
  @ApiQuery({
    name: 'email',
    description: '邮箱地址',
    type: Number,
  })
  @ApiResponse({
    type: UserListVo,
    description: '用户列表',
  })
  @RequireLogin()
  @Get('list')
  async list(
    @Query('pageNo', new DefaultValuePipe(1), generateParseIntPipe('pageNo'))
    pageNo: number,
    @Query(
      'pageSize',
      new DefaultValuePipe(1),
      generateParseIntPipe('pageSize'),
    )
    pageSize: number,
    @Query('username') username: string,
    @Query('nickName') nickName: string,
    @Query('email') email: string,
  ) {
    return await this.userService.findUsers(
      username,
      nickName,
      email,
      pageNo,
      pageSize,
    );
  }

  @Post('upload')
  @UseInterceptors(
    FileInterceptor('file', {
      dest: 'uploads',
      storage: storage,
      limits: {
        fileSize: 1024 * 1024 * 3
      },
      fileFilter(req, file, callback) {
        const extname = path.extname(file.originalname);
        if (['.png', '.jpg', '.gif'].includes(extname)) {
          callback(null, true);
        } else {
          callback(new BadRequestException('只能上传图片'), false);
        }
      },
    }),
  )
  uploadFile(@UploadedFile() file: Express.Multer.File) {
    console.log('file', file);
    return file.path;
  }

  // 初始化数据
  // @Get('init-data')
  // async initData() {
  //   return await this.userService.initData();
  // }
}
