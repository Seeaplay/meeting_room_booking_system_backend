import { BadRequestException, ParseIntPipe } from "@nestjs/common";
import * as crypto from "crypto";

// 加密
export function md5(str){
  const hash = crypto.createHash("md5");
  hash.update(str);

  return hash.digest("hex");
}

// 生成一个用于解析整数的管道函数
export function generateParseIntPipe(name){
  return new ParseIntPipe({
    exceptionFactory() {
      throw new BadRequestException(name + ' 应该传数字');
    },
  });
}