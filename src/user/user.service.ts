import { HttpException, HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Like, Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { RedisService } from 'src/redis/redis.service';
import { md5 } from 'src/utils';
import { Role } from './entities/role.entity';
import { Permission } from './entities/permission.entity';
import { LoginUserDto } from './dto/login-user.dto';
import { LoginUserVo } from './vo/login-user.vo';
import { UpdateUserPasswordDto } from './dto/update-user-password.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserListVo } from './vo/user-list.vo';

@Injectable()
export class UserService {
  // 日志
  private logger = new Logger();

  // 用户数据库
  @InjectRepository(User)
  private userRepository: Repository<User>;

  // 角色数据库
  @InjectRepository(Role)
  private roleRepository: Repository<Role>;

  // 权限数据库
  @InjectRepository(Permission)
  private permissionRepository: Repository<Permission>;

  // redis
  @Inject(RedisService)
  private redisService: RedisService;

  constructor() {}

  // 登录
  async login(loginUserDto: LoginUserDto, isAdmin: boolean) {
    // 查询用户-级联查询 roles 和 roles.permissions
    const user = await this.userRepository.findOne({
      where: {
        username: loginUserDto.username,
        isAdmin,
      },
      relations: ['roles', 'roles.permissions'],
    });

    // 用户不存在
    if (!user) {
      throw new HttpException('用户不存在', HttpStatus.BAD_REQUEST);
    }

    // 密码错误
    if (user.password !== md5(loginUserDto.password)) {
      throw new HttpException('密码错误', HttpStatus.BAD_REQUEST);
    }

    // 返回用户数据
    const vo = new LoginUserVo();
    vo.userInfo = {
      id: user.id,
      username: user.username,
      nickName: user.nickName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      headPic: user.headPic,
      createTime: user.createTime.getTime(),
      isFrozen: user.isFrozen,
      isAdmin: user.isAdmin,
      roles: user.roles.map((item) => item.name),
      permissions: user.roles.reduce((arr, item) => {
        item.permissions.forEach((permission) => {
          if (arr.indexOf(permission) === -1) {
            arr.push(permission);
          }
        });
        return arr;
      }, []),
    };

    return vo;
  }

  // 注册
  async register(user: RegisterUserDto) {
    const captcha = await this.redisService.get(`captcha_${user.email}`);

    // 没有验证码
    if (!captcha) {
      throw new HttpException('验证码失效', HttpStatus.BAD_REQUEST);
    }

    // 验证码错误
    if (user.captcha !== captcha) {
      throw new HttpException('验证码不正确', HttpStatus.BAD_REQUEST);
    }

    // 获取用户
    const foundUser = await this.userRepository.findOneBy({
      username: user.username,
    });

    // 用户存在
    if (foundUser) {
      throw new HttpException('用户已存在', HttpStatus.BAD_REQUEST);
    }

    // 创建用户实例
    const newUser = new User();
    newUser.username = user.username;
    newUser.password = md5(user.password);
    newUser.email = user.email;
    newUser.nickName = user.nickName;

    try {
      // 保存用户
      await this.userRepository.save(newUser);

      return '注册成功';
    } catch (error) {
      this.logger.error(error, UserService);
      return '注册失败';
    }
  }

  // 初始化数据
  async initData() {
    const user1 = new User();
    user1.username = 'zhangsan';
    user1.password = md5('111111');
    user1.email = 'xxx@xx.com';
    user1.isAdmin = true;
    user1.nickName = '张三';
    user1.phoneNumber = '13233323333';

    const user2 = new User();
    user2.username = 'lisi';
    user2.password = md5('222222');
    user2.email = 'yy@yy.com';
    user2.nickName = '李四';

    const role1 = new Role();
    role1.name = '管理员';

    const role2 = new Role();
    role2.name = '普通用户';

    const permission1 = new Permission();
    permission1.code = 'ccc';
    permission1.description = '访问 ccc 接口';

    const permission2 = new Permission();
    permission2.code = 'ddd';
    permission2.description = '访问 ddd 接口';

    user1.roles = [role1];
    user2.roles = [role2];

    role1.permissions = [permission1, permission2];
    role2.permissions = [permission1];

    await this.permissionRepository.save([permission1, permission2]);
    await this.roleRepository.save([role1, role2]);
    await this.userRepository.save([user1, user2]);
  }

  // 通过id查询用户信息
  async findUserById(userId: number, isAdmin: boolean) {
    // 获取用户
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
        isAdmin,
      },
      relations: ['roles', 'roles.permissions'],
    });

    return {
      id: user.id,
      username: user.username,
      isAdmin: user.isAdmin,
      email: user.email,
      roles: user.roles.map((item) => item.name),
      permissions: user.roles.reduce((arr, item) => {
        item.permissions.forEach((permission) => {
          if (arr.indexOf(permission) === -1) {
            arr.push(permission);
          }
        });
        return arr;
      }, []),
    };
  }

  // 通过 id 查询用户详细信息
  async findUserDetailById(userId: number) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    return user;
  }

  // 修改用户密码
  async updatePassword(passwordDto: UpdateUserPasswordDto) {
    // 查找验证码
    const captcha = await this.redisService.get(
      `update_password_captcha_${passwordDto.email}`,
    );

    // 没有验证码
    if (!captcha) {
      throw new HttpException('验证码已失效', HttpStatus.BAD_REQUEST);
    }

    // 验证码错误
    if (passwordDto.captcha !== captcha) {
      throw new HttpException('验证码不正确', HttpStatus.BAD_REQUEST);
    }

    // 查询用户
    const foundUser = await this.userRepository.findOneBy({
      username: passwordDto.username,
    });

    // 验证邮箱
    if(foundUser.email !== passwordDto.email){
      throw new HttpException('邮箱不正确', HttpStatus.BAD_REQUEST);
    }

    foundUser.password = md5(passwordDto.password);

    try {
      // 保存用户信息
      await this.userRepository.save(foundUser);

      return '密码修改成功';
    } catch (e) {
      this.logger.error(e, UserService);
      return '密码修改失败';
    }
  }

  // 修改用户信息
  async update(userId: number, updateUserDto: UpdateUserDto) {
    // 查找验证码
    const captcha = await this.redisService.get(
      `update_user_captcha_${updateUserDto.email}`,
    );

    // 没有验证码
    if (!captcha) {
      throw new HttpException('验证码已失效', HttpStatus.BAD_REQUEST);
    }

    // 验证码错误
    if (updateUserDto.captcha !== captcha) {
      throw new HttpException('验证码不正确', HttpStatus.BAD_REQUEST);
    }

    // 查询用户
    const foundUser = await this.userRepository.findOneBy({
      id: userId,
    });

    if (updateUserDto.nickName) {
      foundUser.nickName = updateUserDto.nickName;
    }
    if (updateUserDto.headPic) {
      foundUser.headPic = updateUserDto.headPic;
    }

    try {
      // 保存用户信息
      await this.userRepository.save(foundUser);

      return '用户信息修改成功';
    } catch (e) {
      this.logger.error(e, UserService);
      return '用户信息修改失败';
    }
  }

  // 冻结用户
  async freezeUserById(id: number) {
    const user = await this.userRepository.findOneBy({
      id,
    });

    // 冻结用户
    user.isFrozen = true;

    await this.userRepository.save(user);
  }

  // 查询用户列表
  async findUsers(
    username: string,
    nickName: string,
    email: string,
    pageNo: number,
    pageSize: number,
  ) {
    // 分页计算
    const skipCount = (pageNo - 1) * pageSize;

    // 查询条件
    const condition: Record<string, any> = {};

    if(username){
      condition.username = Like(`${username}%`)
    }
    if (nickName) {
      condition.nickName = Like(`${nickName}%`);
    }
    if (email) {
      condition.email = Like(`${email}%`);
    }


    // 条件查询用户列表
    const [users, totalCount] = await this.userRepository.findAndCount({
      // 返回字段
      select: [
        'id',
        'username',
        'nickName',
        'email',
        'phoneNumber',
        'isFrozen',
        'headPic',
        'createTime',
      ],
      skip: skipCount,
      take: pageSize,
      where: condition
    });
    
    const vo = new UserListVo();
    vo.users = users;
    vo.totalCount = totalCount;

    return vo;
  }
}
