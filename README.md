###项目介绍
旨在提供基础运维能力，包含，重装、服务器初始化、隔离。

###Api文档
1) 操作系统重装
   - 路由: `/api/v1/reset`
   - 请求参数: 
     |  参数名称    |  类型   |  含义  |
     | -------- | -----: | :----: |
     | ip | string | 机器ip |
     | assert | string | 资产编号，ip和资产编号至少填一个 |
     | os         | string | 操作系统，tlinux1，tlinux2 或其他|
     | operator   | string | 机器负责人rtx |
     | passwd     | stirng | 机器密码 |
     | raidType | stirng | RAID级别，空字符串则表示保持原有Raid |
     | partition | bool | 是否分区 |
     | manual | bool | 重装失败是否转人工 |
     
   - 返回结果:
     | 参数名称    |  类型   |  含义  |
     | --------   | -----:   | :----: |
     | code    |  int   |  非0表示响应失败  |
     | msg    |  string   |  uwork重启单号  |

2) 操作系统重装结果查询
   - 路由: `/api/v1/reset_status`
   
   - 请求参数: 
     |  参数名称    |  类型   |  含义  |
     | -------- | -----: | :----: |
     | ip | string | 机器ip |
     | assert | string | 资产编号，ip和资产编号至少填一个 |
     | instanceId | string | 重启单号 |
     
   - 返回结果:
     | 参数名称    |  类型   |  含义  |
     | --------   | -----:   | :----: |
     | code    |  int   |  非0表示响应失败  |
     | msg    |  string   |  uwork重启单号或者错误信息  |
     

3) 机器初始化  
   - 路由: `/api/v1/init_server`  
    
   - 请求参数:
     |  参数名称    |  类型   |  含义  |
     | -------- | -----: | :----: |
     | ip | string | 机器ip |
     | user | string | 登录用户 |
     | pass | string | 登录用户 |
     | bakpass | string | 备用密码 |
     | host | string | 机器ip |
     | port | string | 端口 |

   - 返回结果:

     | 参数名称    |  类型   |  含义  | 
     | --------   | -----:   | :----: |
     | code    |  int   |  非0表示接口响应失败  | 
     | msg    |  string   |  成功和错误信息  | 

4) 机器隔离 
   - 路由: `/api/v1/isolate`  
    
   - 请求参数:
     |  参数名称    |  类型   |  含义  |
     | -------- | -----: | :----: |
     | ip | string | 机器ip |
     | user | string | 登录用户 |
     | pass | string | 登录用户 |
     | bakpass | string | 备用密码 |
     | host | string | 机器ip |
     | port | string | 端口 |
   
   - 返回结果:

     | 参数名称    |  类型   |  含义  | 
     | --------   | -----:   | :----: |
     | code    |  int   |  非0表示接口响应失败  | 
     | msg    |  string   |  成功和错误信息  | 

5) 机器取消隔离 
   - 路由: `/api/v1/isolate_cancel`  
    
   - 请求参数:
     |  参数名称    |  类型   |  含义  |
     | -------- | -----: | :----: |
     | ip | string | 机器ip |
     | user | string | 登录用户 |
     | pass | string | 登录用户 |
     | bakpass | string | 备用密码 |
     | host | string | 机器ip |
     | port | string | 端口 |
   
   - 返回结果:

     | 参数名称    |  类型   |  含义  | 
     | --------   | -----:   | :----: |
     | code    |  int   |  非0表示接口响应失败  | 
     | msg    |  string   |  成功和错误信息  | 

6) 获取指定服务起磁盘
   - 路由: `api/v1/disk_info`
    
   - 请求参数
     |  参数名称    |  类型   |  含义  |
     | -------- | -----: | :----: |
     | ip | string | 机器ip |
     | user | string | 登录用户 |
     | pass | string | 登录用户 |
     | bakpass | string | 备用密码 |
     | host | string | 机器ip |
     | port | string | 端口 |
     
   - 返回结果:

    {
         "code": 1,
         "msg": [
             {
                 "file_system": "/dev/vda1",
                 "size": 51473888, // 单位k
                 "used": 9315160,
                 "available": 39520980,
                 "use_percentage": "20%",
                 "mounted": "/"
             },
         ]
     }


​     
​     