package service

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"base_ops/utils"
	"regexp"
	"strconv"
	"strings"
)

func checkAddr(addr *utils.Address) error {
	if addr.Host == "" || addr.Passwd == "" {
		return fmt.Errorf("[ host, passwd ] must input")
	}
	return nil
}

func checkPasswdComplicity(passwd string) error {
	if len(passwd) < 8 {
		return fmt.Errorf("密码至少有8个字符")
	}

	count := 0

	if ok, _ := regexp.MatchString("[a-z]", passwd); ok {
		count++
	}

	if ok, _ := regexp.MatchString("[A-Z]", passwd); ok {
		count++
	}

	if ok, _ := regexp.MatchString(`[~!@#$%^&*()-_\+=<,>\.\?\/]`, passwd); ok {
		count++
	}
	if ok, _ := regexp.MatchString("[0-9]", passwd); ok {
		count++
	}

	if count < 3 {
		return fmt.Errorf("密码到少要包含： 大小写字母， 数字，特殊字符中的三项")
	}
	return nil
}


// 初始化server
func InitServer(c *gin.Context) {
	var addr utils.Address
	if err := c.ShouldBind(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 检查参数
	if err := checkAddr(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 初始化
	s, err := NewInitStepSet(&addr)
	if err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("InitServer failed %s", err.Error()),
		})
		return
	}
	if err := s.Run(); err != nil {
		c.JSON(200, gin.H{
			"code": s.StepErr.Code,
			"msg":  fmt.Sprintf("InitServer failed %s", err.Error()),
		})
		return
	}
	c.JSON(200, gin.H{
		"code": 0,
		"msg":  "InitServer success",
	})
	return
}

// 开始隔离
func IsoServer(c *gin.Context) {
	var addr utils.Address
	if err := c.ShouldBind(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 检查参数
	if err := checkAddr(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 初始化
	s, err := NewIsolationStepSet(&addr)
	if err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("IsoServer failed %s", err.Error()),
		})
		return
	}
	if err := s.Offline(); err != nil {
		c.JSON(200, gin.H{
			"code": s.StepErr.Code,
			"msg":  fmt.Sprintf("IsoServer failed %s", err.Error()),
		})
		return
	}
	c.JSON(200, gin.H{
		"code": 0,
		"msg":  "IsoServer success",
	})
	return
}

// 取消隔离
func IsoServerCancel(c *gin.Context) {
	var addr utils.Address
	if err := c.ShouldBind(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 检查参数
	if err := checkAddr(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 初始化
	s, err := NewIsolationStepSet(&addr)
	if err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("IsoServer failed %s", err.Error()),
		})
		return
	}
	if err := s.Online(); err != nil {
		c.JSON(200, gin.H{
			"code": s.StepErr.Code,
			"msg":  fmt.Sprintf("IsoServer failed %s", err.Error()),
		})
		return
	}
	c.JSON(200, gin.H{
		"code": 0,
		"msg":  "Isolate cancel success",
	})
	return
}

// 重装结果查询
func ReinstallOSStatus(c *gin.Context) {
	var req utils.ReinstallOSStatusQueryOptions
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 检查参数
	if  req.IP == "" &&  req.Asset == ""{
		c.JSON(200, gin.H{
			"code": 1,
			"msg": "ip,asset必须填入一个",
		})
		return
	}
	// 查询结果
	status, err := utils.GetReinstallOSStatus(req)
	if err != nil{
		c.JSON(200, gin.H{
			"code": 1,
			"msg": fmt.Sprintf("重装请求处理失败 %s",err.Error()),
		})
		return
	}
	c.JSON(200, gin.H{
		"code": 0,
		"msg":  status,
	})
	return
}

// 重装
func ReinstallOS(c *gin.Context) {
	var req utils.ReinstallOptions
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 检查参数
	if req.IP == "" && req.Asset == ""{
		c.JSON(200, gin.H{
			"code": 1,
			"msg": "ip和asset必须填入一个",
		})
		return
	}
	// 开始重装
	uworkTicket, err := utils.ReinstallOS(req)
	if err != nil{
		c.JSON(200, gin.H{
			"code": 1,
			"msg": fmt.Sprintf("重装请求处理失败 %s",err.Error()),
		})
		return
	}
	// 重装成功
	c.JSON(200, gin.H{
		"code": 0,
		"msg":  uworkTicket,
	})
	return
}

// 检查磁盘
type DiskInfo struct {
	FileSystem string `json:"file_system"`
	Size int `json:"size"`
	Used int `json:"used"`
	Available int `json:"available"`
	UsePercentage string `json:"use_percentage"`
	Mounted string `json:"mounted"`
}

func CheckoutDisk(c *gin.Context){
	var addr utils.Address
	if err := c.ShouldBind(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	sshClient, err := utils.NewSSHClient(&addr)
	if err != nil{
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("创建ssh连接失败 %s", err.Error()),
		})
		return
	}
	// 替换df命令输出的空格为 &
	var diskInfos []*DiskInfo
	res := sshClient.SingleExec(`df |grep -v Filesystem|awk '{print $1"&"$2"&"$3"&"$4"&"$5"&"$6}'`)
	lines := strings.Split(res.Msg, "\n")
	for _, line := range lines{
		if line == ""{
			continue
		}
		lineInLines := strings.Split(line, "&")
		if len(lineInLines) <= 0{
			c.JSON(200, gin.H{
				"code": 1,
				"msg":  fmt.Sprintf("执行df命令失败 %v", lines),
			})
			return
		}
		size, _ := strconv.Atoi(lineInLines[1])
		Used, _ := strconv.Atoi(lineInLines[2])
		Available, _ := strconv.Atoi(lineInLines[3])
		diskInfos = append(diskInfos, &DiskInfo{
			FileSystem:    lineInLines[0],
			Size:          size,
			Used:          Used,
			Available:     Available,
			UsePercentage: lineInLines[4],
			Mounted:       lineInLines[5],
		})
	}
	c.JSON(200, gin.H{
		"code": 1,
		"msg":  diskInfos,
	})
	return
}

// 修改密码
func ChangePasswd(c *gin.Context) {
	var addr utils.Address
	if err := c.ShouldBind(&addr); err != nil{
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 检查参数
	if err := checkAddr(&addr); err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("param error %s", err.Error()),
		})
		return
	}
	// 检查新密码
	if err := checkPasswdComplicity(addr.NewPasswd); err != nil{
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("新密码格式错误 %s", err.Error()),
		})
		return
	}
	sshClient, err := utils.NewSSHClient(&addr)
	if err != nil {
		c.JSON(200, gin.H{
			"code": 1,
			"msg":  fmt.Sprintf("创建ssh连接失败 %s", err.Error()),
		})
		return
	}
	res := sshClient.SingleExec(fmt.Sprintf(`echo "root:%s" | chpasswd`, addr.NewPasswd))
	if res.Err != nil{
		c.JSON(200, gin.H{
			"code": 10001,
			"msg":  fmt.Sprintf("param error %s", res.Err.Error()),
		})
		return
	}
	c.JSON(200, gin.H{
		"code": 1,
		"msg":  "change passwd success",
	})
	return
}