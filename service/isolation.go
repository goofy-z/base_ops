package service

import (
	"errors"
	"fmt"
	"github.com/qq1141000259/public_tools/zlog"
	"base_ops/utils"
	"strings"
)

var (
	AllowIP = []string{
		"10.57.17.230", "100.110.5.28", "10.191.137.29", "10.246.129.12",
		"100.96.31.133", "10.191.137.28", "100.110.5.28", "10.191.137.29",
		"10.254.103.196", "10.254.83.79", "10.223.132.17", "10.136.14.43",
		"10.223.134.15", "10.187.31.148", "10.187.31.147", "10.187.31.148",
		"10.187.31.147", "10.198.159.140", "10.198.31.146", "10.137.138.17",
		"10.189.31.142", "172.27.8.203", "10.139.7.83", "10.170.31.140",
		"10.229.132.230", "10.185.12.211", "100.116.28.153", "10.254.103.221",
	}
	AllowPort = []string{
		"123", "9922", "9966", "9988", "8810", "49000", "56000",
	}
)

type IsoStepSet struct {
	Envs      environment
	addr      *utils.Address
	sshClient *utils.SSHClient
	StepErr   *StepError
	StepFunc  []func()
}

func NewIsolationStepSet(addr *utils.Address) (*IsoStepSet, error) {
	client, err := utils.NewSSHClient(addr)
	if err != nil {
		zlog.Errorf("IP: [%s] ssh建立连接失败 err: %s", addr.Host, err.Error())
		return nil, err
	}
	// 初始化StepSet
	return &IsoStepSet{sshClient: client, addr: addr, StepErr: &StepError{}}, nil
}

// 开始隔离
func (s *IsoStepSet) Offline() error{
	defer s.sshClient.Close(true)
	if err := s.sshClient.NewTerminal(); err != nil {
		return err
	}
	s.iptableDrop()
	if s.StepErr.Err != nil{
		return s.StepErr.Err
	}
	return nil
}

// 取消隔离
func (s *IsoStepSet) Online() error{
	defer s.sshClient.Close(true)
	res := s.sshClient.SingleExec(`iptables-restore </tmp/iptables-rule.txt && echo "ok"`)
	if !strings.Contains(res.Msg, "ok"){
		zlog.Errorf("【取消隔离】—— 回复iptables失败，IP: %s , 原因: %s", s.addr.Host, res.Msg)
		return errors.New("iptables 恢复失败")
	}
	s.sshClient.SingleExec(`rm -f /tmp/iptables-rule.txt`)
	return nil
}

// 删除iptable, 远程执行drop链操作会使连接断开
func (s *IsoStepSet) iptableDrop() {
	var cmds []string
	res := s.sshClient.PtyExec(`[ -f /tmp/iptables-rule.txt ] && echo "ok"`)
	if res.Msg == "ok" || res.Err != nil{
		zlog.Infof(`【开始隔离】—— 文件"iptables-rule"已经存在，不再进行隔离操作`)
		return
	}
	port := strings.Join(AllowPort, ",")
	cmds = append(cmds, `iptables-save >/tmp/iptables-rule.txt`)

	// empty all rule
	cmds = append(cmds, `iptables -P INPUT ACCEPT`)
	cmds = append(cmds, `iptables -P OUTPUT ACCEPT`)
	cmds = append(cmds, `iptables -P FORWARD ACCEPT`)
	// 清空计数器
	cmds = append(cmds, `iptables -Z`)
	// 清空自定义链
	cmds = append(cmds, `iptables -X`)
	// 清空链
	cmds = append(cmds, `iptables -F`)

	// set default policy
	cmds = append(cmds, `iptables -P INPUT DROP`)
	cmds = append(cmds, `iptables -P OUTPUT DROP`)
	cmds = append(cmds, `iptables -P FORWARD DROP`)

	// open need ports
	cmds = append(cmds, fmt.Sprintf(`iptables -A INPUT -i eth1 -p tcp -m multiport  --dports %s -j ACCEPT`, port))
	cmds = append(cmds, fmt.Sprintf(`iptables -A INPUT -i eth1 -p udp -m multiport  --dports %s -j ACCEPT`, port))
	cmds = append(cmds, fmt.Sprintf(`iptables -A INPUT -i eth1 -p tcp -m multiport  --sports %s -j ACCEPT`, port))
	cmds = append(cmds, fmt.Sprintf(`iptables -A INPUT -i eth1 -p udp -m multiport --sports %s -j ACCEPT`, port))
	cmds = append(cmds, `iptables -A INPUT -p icmp -j ACCEPT`)
	cmds = append(cmds, fmt.Sprintf(`iptables -A OUTPUT -p tcp -m multiport  --dports %s -j ACCEPT`, port))
	cmds = append(cmds, fmt.Sprintf(`iptables -A OUTPUT -p tcp -m multiport  --dports %s -j ACCEPT`, port))
	cmds = append(cmds, fmt.Sprintf(`iptables -A OUTPUT -p udp -m multiport  --sports %s -j ACCEPT`, port))
	cmds = append(cmds, fmt.Sprintf(`iptables -A OUTPUT -p udp -m multiport  --sports %s -j ACCEPT`, port))
	cmds = append(cmds, `iptables -A OUTPUT -p icmp -j ACCEPT`)

	// 增加允许远程登录的ip
	for _, IP := range AllowIP{
		cmds = append(cmds, fmt.Sprintf(`iptables -A INPUT -p tcp -s %s -j ACCEPT`, IP))
		cmds = append(cmds, fmt.Sprintf(`iptables -A OUTPUT -p tcp -d %s -j ACCEPT`, IP))
	}

	// 将命令写到服务器的执行脚本中
	s.sshClient.PtyExec(`echo '#!/bin/bash' > /tmp/isolation.sh`)
	for _, cmd := range cmds{
		s.sshClient.PtyExec(fmt.Sprintf(`echo "%s" >> /tmp/isolation.sh`, cmd))
	}

	// 执行脚本
	ret := s.sshClient.PtyExec(`nohup sh /tmp/isolation.sh &`)
	zlog.Infof("%s :", ret.Msg)
}

