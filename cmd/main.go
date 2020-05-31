package main

import (
	"flag"
	"github.com/qq1141000259/public_tools/zlog"
	"github.com/gin-gonic/gin"
	"base_ops/apis"
)

var (
	addr    string = ":8099"
	log_dir string = ""
)

func init() {
	flag.StringVar(&addr, "addr", addr, "server listen address")
}

func main() {
	flag.Parse()
	// 初始化zlog
	logCfg := zlog.NewZapConfig()
	logCfg.Alarm = false
	logCfg.ServerName = "base_ops"
	logCfg.Build()
	r := gin.New()
	apis.Install(r)
	r.Run(addr)
	//s,err := reset.NewInitStepSet()
	//if err != nil{
	//	zlog.Error(err.Error())
	//	return
	//}

	// s.DoStep()
	//addr := utils.Address{
	//	User: "root",
	//	Passwd: "xxxx",
	//	Host: "xxxx",
	//	Port: "22",
	//}
	//sshClient, err := utils.NewSSHClient(&addr)
	//if err != nil{
	//	zlog.Fatal(err.Error())
	//}
	//cmds := []string{
	//	"whoami",
	//	"hostname",
	//	"echo 123",
	//}
	//res := sshClient.MultiExec(cmds)
	//fmt.Println(res.Err, res.Msg)
	//// 切换session
	//sshClient.ReSession()
	//ret := sshClient.SingleExec("cat /etc/resolv.conf")
	//fmt.Println(ret.Err, ret.Msg)
	//sshClient.Close(true)
}
