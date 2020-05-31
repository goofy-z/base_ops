package service

import (
	"base_ops/utils"
	"errors"
	"fmt"
	"github.com/qq1141000259/public_tools/zlog"
	"strings"
	"time"
)

const (
	OsError      StepCode = 1
	MonitorError StepCode = 101
	L5Error      StepCode = 102
	KubeletError StepCode = 103
	DowloadError StepCode = 104
	ExtractError StepCode = 105
	SysctlError  StepCode = 201
	MountError   StepCode = 202
	GeneralError StepCode = 203
)

// 步骤集合
type InitStepSet struct {
	Envs      environment
	addr      *utils.Address
	sshClient *utils.SSHClient
	StepErr   *StepError
	StepFunc  []func()
}

// 初始化过程使用的一些变量
type environment struct {
	// 初始化安装包位置
	Dir string
	// 初始化过程日志文件
	Log string
	// 当前日期
	Today string
	// 操作系统
	OSType string
	// init文件
	InitFile string
}

func NewInitStepSet(addr *utils.Address) (*InitStepSet, error) {
	// 创建SSHClient
	//addr := utils.Address{
	//	User:   "root",
	//	Passwd: "xxxx",
	//	Host:   "xxxx",
	//	Port:   "22",
	//}
	zlog.Infof("IP: [%s] 开始执行初始化", addr.Host)
	client, err := utils.NewSSHClient(addr)
	zlog.Infof("IP: [%s] 申请连接成功", addr.Host)
	if err != nil {
		zlog.Errorf("IP: [%s] ssh建立连接失败 err: %s", addr.Host, err.Error())
		return nil, err
	}
	// 初始化StepSet
	return &InitStepSet{sshClient: client, addr: addr, StepErr: &StepError{}}, nil
}

func (s *InitStepSet) handleError() {
	if s.StepErr.Err != nil {
		zlog.Errorf("【初始化】—— 执行步骤%d失败，原因: %s", s.StepErr.Err.Error())
	}
}

func (s *InitStepSet) Run() error {
	s.registryStep()
	defer s.sshClient.Close(true)
	if err := s.sshClient.NewTerminal(); err != nil {
		return err
	}
	zlog.Infof("IP: [%s] 申请pty成功", s.addr.Host)
	for _, fun := range s.StepFunc {
		fun()
		s.StepErr.Step += 1
		if s.StepErr.Code != 0 || s.StepErr.Err != nil{
			errMsg := fmt.Sprintf("[init] IP: %s, Step%d failed, code: %d， msg: %s", s.addr.Host, s.StepErr.Step, s.StepErr.Code, s.StepErr.Msg)
			if s.StepErr.Err != nil{
				errMsg += s.StepErr.Err.Error()
			}
			zlog.Errorf(errMsg)
			return errors.New(fmt.Sprintf("初始化失败: %s", errMsg))
		}
		zlog.Infof("[init] IP: %s step %d success", s.addr.Host, s.StepErr.Step)
	}
	return nil
}

// 注册初始化过程函数
func (s *InitStepSet) registryStep() {
	//s.StepFunc = append(s.StepFunc, s.step0)
	s.StepFunc = append(s.StepFunc, s.step1)
	s.StepFunc = append(s.StepFunc, s.step2)
	s.StepFunc = append(s.StepFunc, s.step3)
	s.StepFunc = append(s.StepFunc, s.step4)
	s.StepFunc = append(s.StepFunc, s.step5)
	s.StepFunc = append(s.StepFunc, s.step6)
	s.StepFunc = append(s.StepFunc, s.step7)
	s.StepFunc = append(s.StepFunc, s.step8)
	s.StepFunc = append(s.StepFunc, s.step9)
	s.StepFunc = append(s.StepFunc, s.step10)
	s.StepFunc = append(s.StepFunc, s.step11)
	s.StepFunc = append(s.StepFunc, s.step12)
	s.StepFunc = append(s.StepFunc, s.step13)
	s.StepFunc = append(s.StepFunc, s.step14)
	s.StepFunc = append(s.StepFunc, s.step15)
}

func (s *InitStepSet) step0() {
	cmd := `wget -q --timeout=3 --tries=2 http://100.110.5.28/pkg/init_scripts.tgz -O /tmp/init_scripts.tgz&&echo "ok"`
	//cmd := `echo "ok"`
	//ret := s.sshClient.PtyExec(cmd)
	//fmt.Println("拉取结果", ret.Msg != "ok", ret.Msg)
	//if ret.Msg != "ok" {
	//	fmt.Println(ret.Msg != "ok")
	//	s.StepErr.Err, s.StepErr.Code = ret.Err, DowloadError
	//	s.StepErr.Msg = "download the init-package failed"
	//	return
	//}
	//cmd = `echo "ok"`
	//ret = s.sshClient.PtyExec(cmd)
	//fmt.Println("拉取结果", ret.Msg != "ok", ret.Msg)
	//if ret.Msg != "ok" {
	//	fmt.Println(ret.Msg != "ok")
	//	s.StepErr.Err, s.StepErr.Code = ret.Err, DowloadError
	//	s.StepErr.Msg = "download the init-package failed"
	//	return
	//}
	ret := s.sshClient.PtyExec(cmd)
	fmt.Println(ret.Msg)
	ret = s.sshClient.PtyExec(cmd)
	fmt.Println(ret.Msg)
	return
}

// 修改DNS
func (s *InitStepSet) step1() {
	cmds := make([]string, 9)
	resolv := ""
	resolv += "nameserver 100.77.0.8" + "\n"
	resolv += "nameserver 9.24.170.50" + "\n"
	resolv += "nameserver 100.117.128.8" + "\n"
	resolv += "nameserver 10.236.0.82" + "\n"
	cmds[0] = fmt.Sprintf(`echo "%s" >/etc/resolv.conf`, resolv)
	cmds[1] = "[ -d /data/service/ ] || mkdir /data/service/"
	cmds[2] = "[ -d /home/scripts/ ] || mkdir /home/scripts/"
	cmds[3] = "[ -d /data/logs/ ] || mkdir /data/logs/"
	cmds[4] = "[ -d /data/tmp/ ] || mkdir /data/tmp/"
	cmds[5] = "[ -d /data/backup/ ] || mkdir /data/backup/"
	cmds[6] = "[ -d /data/userdata/ ] || mkdir /data/userdata/"
	cmds[7] = "[ -d /data/core/ ] || mkdir /data/core/"
	cmds[8] = "chmod -R 777 /data/core/"
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}
	return
}

// 删除cuda包，开启nscd服务
func (s *InitStepSet) step2() {
	cmds := make([]string, 7)
	cmds[0] = "rm -f /tmp/cuda-installer*"
	cmds[1] = "rm -f /tmp/cuda_install*"
	cmds[2] = "rm -f /tmp/template-*"
	cmds[3] = "[ -f /etc/init.d/nscd ] && /etc/init.d/nscd restart"
	cmds[4] = "[ -f init_scripts.tgz ] && /bin/rm -f init_scripts.tgz"
	cmds[5] = "[ -d init_scripts ] && /bin/rm -rf init_scripts"
	//cmds[6] = `wget -q --timeout=3 --tries=2 http://100.110.5.28/pkg/init_scripts.tgz -O /tmp/init_scripts.tgz`
	for _, cmd := range cmds {
	//	fmt.Println(len(cmd))
		s.sshClient.PtyExec(cmd)
	}
	var cmd string
	var ret *utils.ExecResult
	cmd1 := `wget -q --timeout=3 --tries=2 http://100.110.5.28/pkg/init_scripts.tgz -O /tmp/init_scripts.tgz&&echo $?`
	ret = s.sshClient.PtyExec(cmd1)
	if ret.Msg != "0" {
		s.StepErr.Err, s.StepErr.Code = ret.Err, DowloadError
		s.StepErr.Msg = "download the init-package failed"
		return
	}
	cmd = `tar xzf /tmp/init_scripts.tgz -C /tmp && echo "ok"`
	ret = s.sshClient.PtyExec(cmd)
	if ret.Msg != "ok" {
		s.StepErr.Err, s.StepErr.Code = ret.Err, DowloadError
		s.StepErr.Msg = "extract the init-package failed"
		return
	}

	s.Envs.Dir = "/tmp/init_scripts"
	s.Envs.Log = "/tmp/init.log"
	s.Envs.Today = time.Now().Format("20060102")
}

// 检查操作系统

func (s *InitStepSet) step3() {
	var cmd string
	var ret *utils.ExecResult
	switch 1 {
	case 1:
		cmd = `[ -f "/etc/SuSE-release" ]&&echo "ok"`
		ret = s.sshClient.PtyExec(cmd)
		if ret.Msg == "ok" {
			cmd = `grep VERSION /etc/SuSE-release | awk '{ print $3 }'`
			version := s.sshClient.PtyExec(cmd).Msg
			s.Envs.OSType = "suse" + version
			break
		}
		fallthrough
	case 2:
		cmd = `[ -f "/etc/issue" -a -f "/etc/redhat-release" ]&&echo "ok"`
		ret = s.sshClient.PtyExec(cmd)
		if ret.Msg == "ok" {
			cmd = `grep "tlinux" /etc/issue >/dev/null 2>&1&&echo "ok"`
			if s.sshClient.PtyExec(cmd).Msg == "ok" {
				s.Envs.OSType = "tlinux"
				break
			}
		}
	}
	switch s.Envs.OSType {
	case "":
		s.StepErr.Err, s.StepErr.Code = fmt.Errorf("UNKNOW OS type"), DowloadError
		s.StepErr.Msg = "UNKNOW OS type"
		return
	case "suse10", "suse11":
		s.Envs.InitFile = "/etc/init.d/rc.local"
	case "tlinux":
		s.Envs.InitFile = "/etc/rc.d/rc.local"

	}
	if s.Envs.OSType == "" {
		s.StepErr.Err, s.StepErr.Code = fmt.Errorf("UNKNOW OS type"), DowloadError
		s.StepErr.Msg = "UNKNOW OS type"
		return
	}
	cmd = fmt.Sprintf("sed '/########INIT_SCRIPTS_ADD_START########/,/########INIT_SCRIPTS_ADD_END########/d' %s >/tmp/init.file", s.Envs.InitFile)
	s.sshClient.PtyExec(cmd)
	cmd = `echo "########INIT_SCRIPTS_ADD_START########" >> /tmp/init.file`
	s.sshClient.PtyExec(cmd)
}

// add ntpdate cron
func (s *InitStepSet) step4() {
	cmds := make([]string, 7)
	cmds[0] = `crontab -l >/tmp/root.crontab.tmp 2>/dev/null`
	cmds[1] = `sed '/^.*\(sntp\|ntpdate\).*$/d' /tmp/root.crontab.tmp >/tmp/root.crontab`
	cmds[2] = `echo "###ntpdate every 3 hours###" >>/tmp/root.crontab`
	if s.Envs.OSType == "suse11" {
		cmds[3] = `echo "30 */3 * * * /usr/sbin/sntp -P no -r 9.22.139.140  100.115.8.147 && /sbin/hwclock -w >` +
			`/dev/null 2>&1" >>/tmp/root.crontab`
		cmds[4] = `/usr/sbin/sntp -P no -r 9.22.139.140 100.115.8.147 && /sbin/hwclock -w`
		cmds[5] = `echo "### sync system time\n/usr/sbin/sntp -P no -r 9.22.139.140  100.115.8.147 && ` +
			`/sbin/hwclock -w" >> /tmp/init.file`
		cmds[6] = `crontab /tmp/root.crontab`
	} else {
		cmds[3] = `echo "30 */3 * * * /usr/sbin/ntpdate ntp.tencent-cloud.com 9.22.139.140 100.115.8.147 && ` +
			`/sbin/hwclock -w > /dev/null 2>&1" >>/tmp/root.crontab`
		cmds[4] = `echo "### sync system time\n/usr/sbin/ntpdate ntp.tencent-cloud.com 9.22.139.140  100.115.8.147 ` +
			`&& /sbin/hwclock -w" >> /tmp/init.file`
		cmds[5] = `crontab /tmp/root.crontab`
	}
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}
}

// configure kerner values
func (s *InitStepSet) step5() {
	cmds := make([]string, 10)
	cmds[0] = `sed -i '/ipv4/d' /etc/sysctl.conf`
	cmds[1] = `sed -i '/core/d' /etc/sysctl.conf`
	cmds[2] = `sed -i '/kernel.core_uses_pid/d' /etc/sysctl.conf`
	cmds[3] = `sed -i '/kernel.core_pattern/d' /etc/sysctl.conf`
	cmds[4] = `sed -i '/kernel.shmmax/d' /etc/sysctl.conf`
	confStr := "net.core.rmem_default = 16777216" + "\n" + "net.core.rmem_max = 16777216" + "\n" +
		"net.core.wmem_max = 16777216" + "\n" + "net.ipv4.udp_mem = 16777216 8225792 33554432" + "\n" +
		"net.ipv4.udp_rmem_min = 16777216" + "\n" + "net.ipv4.udp_wmem_min = 16777216" + "\n" +
		"net.core.wmem_default = 8388608" + "\n" + "kernel.core_uses_pid = 0" + "\n" +
		"kernel.core_pattern = /data/core/core-%e" + "\n" + "net.ipv4.tcp_rmem = 4096  65536  8388608" + "\n" +
		"net.ipv4.tcp_wmem = 4096  65536  8388608" + "\n" + "#net.ipv4.ip_local_port_range=40000 61000"
	cmds[5] = fmt.Sprintf(`echo "%s" >>/etc/sysctl.conf`, confStr)
	cmds[6] = `sed -i '/net.ipv4.tcp_wan_timestamps/d' /etc/sysctl.conf`
	cmds[7] = `sysctl -a | grep 'net.ipv4.tcp_wan_timestamps' ` +
		`&& echo "net.ipv4.tcp_wan_timestamps = 1" >>/etc/sysctl.conf`
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}
	// 重新加载内核参数，默认从/etc/sysctl.conf加载系统参数
	if ret := s.sshClient.PtyExec(`sysctl -p >/dev/null 2>&1 && echo "ok"`); ret.Msg != "ok" {
		s.StepErr.Err, s.StepErr.Code = fmt.Errorf("configure sysctl error"), SysctlError
		s.StepErr.Msg = "configure sysctl.conf error"
		return
	}
}

// configure oicq scripts
func (s *InitStepSet) step6() {
	cmds := make([]string, 17)
	cmds[0] = `mkdir /data/oicq >/dev/null 2>&1`

	cmds[1] = `rm /home/oicq/oicq /home/oicq >/dev/null 2>&1`
	cmds[2] = `ln -s /data/oicq /home/oicq >/dev/null 2>&1`
	cmds[3] = `useradd oicq -d /data/oicq -s /bin/false >/dev/null 2>&1`
	cmds[4] = `mkdir -p /home/oicq/script /home/oicq/alarm_bin /home/oicq/log >/dev/null 2>&1`
	cmds[5] = fmt.Sprintf("cp %s/backup.sh /home/oicq/script/", s.Envs.Dir)
	cmds[6] = fmt.Sprintf("cp %s/rollback.sh /home/oicq/script/", s.Envs.Dir)
	cmds[7] = fmt.Sprintf("cp %s/check_alive.sh /home/oicq/script/", s.Envs.Dir)
	cmds[8] = fmt.Sprintf("cp %s/alarmtool /home/oicq/alarm_bin/", s.Envs.Dir)
	cmds[9] = fmt.Sprintf("cp %s/alarm /home/oicq/alarm_bin/", s.Envs.Dir)
	cmds[10] = fmt.Sprintf("cp %s/sendwxmsg /home/oicq/alarm_bin/", s.Envs.Dir)
	cmds[11] = fmt.Sprintf(`cp %s/alert /home/oicq/alarm_bin/`, s.Envs.Dir)
	cmds[12] = fmt.Sprintf("cp %s/npa /usr/bin/", s.Envs.Dir)
	cmds[13] = fmt.Sprintf("cp %s/autocleanlog.sh /home/oicq/script/autocleanlog.sh", s.Envs.Dir)
	cmds[14] = `chmod u+x /home/oicq/script/check_alive.sh`
	cmds[15] = `chmod a+x /home/oicq/alarm_bin/* /usr/bin/npa /home/oicq/script/autocleanlog.sh`
	cmds[16] = `chmod +s /usr/bin/npa`
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}
}

// configure oicq scripts
func (s *InitStepSet) step7() {
	cmds := make([]string, 10)
	cmds[0] = "mkdir -p /usr/local/service/monitor/check_dmesg >/dev/null 2>&1"
	cmds[1] = fmt.Sprintf("cp %s/checkdmesg.sh /usr/local/service/monitor/check_dmesg/", s.Envs.Dir)
	cmds[2] = fmt.Sprintf("cp %s/checkdmesg.conf /usr/local/service/monitor/check_dmesg/", s.Envs.Dir)
	cmds[3] = "chmod +x /usr/local/service/monitor/check_dmesg/checkdmesg.sh"
	cmds[4] = "crontab -l >/tmp/root.crontab.tmp 2>/dev/null"
	cmds[5] = "sed '/^.*checkdmesg.*$/d' /tmp/root.crontab.tmp >/tmp/root.crontab"
	cmds[6] = "sed -i '/autocleanlog/d' /tmp/root.crontab.tmp"
	cmdStr := "###  checkdmesg" + "\n" + "0 */10 * * * /usr/local/service/monitor/check_dmesg/checkdmesg.sh >/dev/null 2>&1" + "\n" +
		"###  del /data/core file before day 2" + "\n" + `1 6 * * * /usr/bin/find /data/core -name "core*" -mtime +2 -exec rm {} \; >/dev/null 2>&1` + "\n" +
		"0 * * * * /home/oicq/script/autocleanlog.sh >/tmp/autocleanlog.log 2>&1"
	cmds[7] = fmt.Sprintf(`echo "%s" >> /tmp/root.crontab.tmp`, cmdStr)
	cmds[8] = `crontab /tmp/root.crontab.tmp`
	cmds[9] = `/usr/local/service/monitor/check_dmesg/checkdmesg.sh >/dev/null 2>&1`
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}
}

// 修改 vimrc bashrc hostname
func (s *InitStepSet) step8() {
	var cmds []string
	cmds = append(cmds, fmt.Sprintf("cp %s/vimrc /root/.vimrc", s.Envs.Dir))
	cmds = append(cmds, fmt.Sprintf("cp %s/vimrc /etc/", s.Envs.Dir))
	if isOk := s.sshClient.PtyExec(`[ -f /root/.bashrc ] && echo "ok"`); isOk.Msg != "ok" {
		str := `sed '/########INIT_SCRIPTS_ADD_START########/,/########INIT_SCRIPTS_ADD_END########/d' ` +
			`/root/.bashrc >/tmp/bashrc`
		cmds = append(cmds, str)
	}
	// check if is tlinux2.0,for bashrc PS1
	if isOk := s.sshClient.PtyExec(`grep "SuSE" /etc/motd`); isOk.Msg != "" {
		cmds = append(cmds, `cat <<EOF >>/tmp/bashrc
########INIT_SCRIPTS_ADD_START########
ipL=$(grep IPADDR /etc/sysconfig/network-scripts/ifcfg-eth1 | awk -F"'" '{print $2}')
export PS1="\u@\$ipL:\w# "
export LC_ALL="en_US.UTF8"
export LANG="en_US.UTF8"
########INIT_SCRIPTS_ADD_END########
EOF`)
		s.sshClient.PtyExec(cmds[0])
	} else {
		cmds = append(cmds, `cat <<EOF >>/tmp/bashrc
########INIT_SCRIPTS_ADD_START########
ipL=$(grep IPADDR /etc/sysconfig/network-scripts/ifcfg-eth1 | awk -F"'" '{print $2}')
export PS1="\u@\$ipL:\w# "
export LC_ALL="en_US.UTF8"
export LANG="en_US.UTF8"
########INIT_SCRIPTS_ADD_END########
EOF`)
	}
	cmds = append(cmds, `cat /tmp/bashrc >/root/.bashrc`)
	cmds = append(cmds, `sed -i '/LANG/d' /etc/profile`)
	cmds = append(cmds, `sed -i '/LC_ALL/d' /etc/profile`)
	cmds = append(cmds, `echo 'export LC_ALL="en_US.UTF8"' >> /etc/profile`)
	cmds = append(cmds, `echo 'export LANG="en_US.UTF8"' >> /etc/profile`)
	hostname := s.sshClient.PtyExec(`grep IPADDR /etc/sysconfig/network-scripts/ifcfg-eth1 | awk -F"'" '{print $2}'`).Msg
	switch s.Envs.OSType {
	case "suse10", "suse11":
		cmds = append(cmds, fmt.Sprintf(`echo "%s" >/etc/HOSTNAME`, hostname))
	case "tlinux":
		cmds = append(cmds, fmt.Sprintf(`sed -i "/HOSTNAME=/s/.*/HOSTNAME=%s/g" /etc/sysconfig/network`, hostname))
		cmds = append(cmds, fmt.Sprintf(`echo "%s" >/etc/hostname`, hostname))
		cmds = append(cmds, fmt.Sprintf(`echo "%s" >/etc/HOSTNAME`, hostname))
	case "":
		s.StepErr.Err, s.StepErr.Code= fmt.Errorf("UNKNOW OS type"), DowloadError
		s.StepErr.Msg = "UNKNOW OS type"
		return
	}
	cmds = append(cmds, fmt.Sprintf("hostname %s >/dev/null 2>/dev/null", hostname))
	cmds = append(cmds, fmt.Sprintf(`echo "%s" >/etc/hostname`, hostname))
	cmds = append(cmds, `echo "########INIT_SCRIPTS_ADD_END########" >>/tmp/init.file`)
	cmds = append(cmds, fmt.Sprintf("cat /tmp/init.file > %s", s.Envs.InitFile))
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}

}

// 	安装架构平台部agent
func (s *InitStepSet) step9() {
	var cmds []string
	agent_dinfosec := "agent_dinfosec_v4.8.31.tgz"
	cmds = append(cmds, fmt.Sprintf(`tar zxf %s/%s -C %s`, s.Envs.Dir, agent_dinfosec, s.Envs.Dir))
	cmds = append(cmds, fmt.Sprintf(`[ -d /usr/local/agent%s ] && rm -rf /usr/local/agent%s)`, s.Envs.Today,
		s.Envs.Today))
	cmds = append(cmds, fmt.Sprintf(`[ -d /usr/local/agent ] && mv /usr/local/agent /usr/local/agent%s`, s.Envs.Today))
	cmds = append(cmds, `mv agent /usr/local/`)
	cmds = append(cmds, `[ -d /data/agent_log ] || mkdir /data/agent_log`)
	cmds = append(cmds, `crontab -l >/tmp/root.crontab.tmp 2>/dev/null`)
	cmds = append(cmds, `sed -i '/^.*Check\ JiaPing\ Monitor.*$/d' /tmp/root.crontab.tmp`)
	cmds = append(cmds, `sed -i '/^.*JPmonitor_agentcheckalive.*$/d' /tmp/root.crontab.tmp`)
	cmds = append(cmds, `sed -i '/^#\{68\}/d' /tmp/root.crontab.tmp`)
	cmds = append(cmds, `crontab /tmp/root.crontab.tmp`)
	cmds = append(cmds, `rm /tmp/root.crontab.tmp`)
	tar_dir := fmt.Sprintf(`%s/%s`, s.Envs.Dir, agent_dinfosec)
	cmds = append(cmds, fmt.Sprintf(`[[ -f %s ]] && rm %s`, tar_dir, tar_dir))
	// 重启agent
	agentConf := "/usr/local/agenttools/agent/client.conf"
	cmds = append(cmds, fmt.Sprintf(`mv -f %s %s_%s`, agentConf, agentConf, s.Envs.Today))
	cmds = append(cmds, fmt.Sprintf(`cp %s/client.conf %s`, s.Envs.Dir, agentConf))
	cmds = append(cmds, `./usr/local/agenttools/agent/startagent.sh`)
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}
}

// 安装L5agent
func (s *InitStepSet) step10() {
	var cmds []string
	l5_tar := "l5agent-bit64-4.3.0.tgz"
	l5_dir := "l5agent-bit64-4.3.0"
	l5_pid := s.sshClient.PtyExec(`pidof l5_agent`).Msg
	if l5_pid != "" {
		zlog.Infof("l5_agent 已经安装，开始卸载 进程号: %s", l5_pid)
		// 卸载l5
		l5_bin_path := s.sshClient.PtyExec(fmt.Sprintf(`ls -l /proc/%s | grep cwd | awk -F "->" '{print $2}'`, l5_pid)).Msg
		l5_install_path := strings.TrimRight(l5_bin_path, "/bin")
		zlog.Infof("bin: %s install: %s", l5_bin_path, l5_install_path)
		fmt.Println(s.sshClient.PtyExec(fmt.Sprintf(`%s/uninstall.sh >/dev/null 2>&1`, l5_install_path)).Msg)
		fmt.Println(s.sshClient.PtyExec(`pidof l5_agent`).Msg)
	}
	cmds = append(cmds, "test `pidof l5_agent` && ")
	// 重新安装l5
	s.sshClient.PtyExec(fmt.Sprintf(`tar zxf %s/%s -C /usr/local`, s.Envs.Dir, l5_tar))
	if s.sshClient.PtyExec(fmt.Sprintf(`/usr/local/%s/install.sh >/dev/null 2>&1 && echo "ok"`, l5_dir)).Msg != "ok" {
		err := fmt.Errorf("l5 install failed")
		s.StepErr.Err, s.StepErr.Code = err, L5Error
		s.StepErr.Msg = "l5 agent 安装失败"
		return
	}
}

// 安装monitor agent
func (s *InitStepSet) step11() {
	mnt_tar := "monitor_agent-1.0.35-install.tar.gz"
	mnt_dir := "monitor_agent-1.0.35-install"
	mnt_pid := s.sshClient.PtyExec(`pidof monitor_agent`).Msg
	if mnt_pid != "" {
		// 卸载monitor
		monitor_bin_path := s.sshClient.PtyExec(fmt.Sprintf(`ls -l /proc/%s | grep cwd | awk -F "->" '{print $2}'`, mnt_pid)).Msg
		monitor_install_path := strings.TrimRight(monitor_bin_path, "/bin") + "/admin"
		s.sshClient.PtyExec(fmt.Sprintf(`%s/uninstall.sh >/dev/null 2>&1`, monitor_install_path))
	}
	mnt_tar = "monitor_agent-1.0.35-install.tar.gz"
	s.sshClient.PtyExec(`rm -rf /usr/local/services/monitor_agent >/dev/null 2>&1`)
	s.sshClient.PtyExec(`rm -f /usr/local/agenttools/monitor_agent`)
	s.sshClient.PtyExec(fmt.Sprintf(`tar zxf %s/%s -C /usr/local`, s.Envs.Dir, mnt_tar))
	fmt.Println(fmt.Sprintf(`/usr/local/%s/install.sh >/dev/null 2>&1 && echo "ok"`, mnt_dir))
	s.sshClient.PtyExec(fmt.Sprintf(`/usr/local/%s/install.sh >/dev/null 2>&1 && echo "ok"`, mnt_dir))
	s.sshClient.PtyExec(`ln -s /usr/local/services/monitor_agent /usr/local/agenttools/monitor_agent`)
	if s.sshClient.PtyExec(`/usr/local/services/monitor_agent/admin/restart.sh all >/dev/null 2>&1 | echo $?`).Msg != "0" {
		err := fmt.Errorf("monitor install failed")
		s.StepErr.Err, s.StepErr.Code = err, MonitorError
		s.StepErr.Msg = "monitor agent 安装失败"
		return
	}
}

// 安装iGeneral_client_2
func (s *InitStepSet) step12() {
	s.sshClient.PtyExec(fmt.Sprintf(`tar zxf %s/iGeneral_client_2.tgz -C /usr/local`, s.Envs.Dir))
	if s.sshClient.PtyExec(fmt.Sprintf(`ps -elf | grep nslcd | grep -v grep >/dev/null 2>&1 && echo "ok"`)).Msg != "ok" {
	zlog.Infof("IP: [%s] step12 iGeneral_client_2 没有安装, 安装中。。。", s.addr.Host)
		if s.sshClient.PtyExec(`sh /usr/local/iGeneral_client_2/install.sh >/dev/null 2>&1 & | echo $?`).Msg != "0" {
			err := fmt.Errorf("iGeneral_client_2 install failed")
			s.StepErr.Err, s.StepErr.Code = err, GeneralError
			s.StepErr.Msg = "iGeneral_client_2 agent 安装失败"
			return
		}
	} else {
		zlog.Infof("IP: [%s] step12 iGeneral_client_2 已经安装，更新中。。。", s.addr.Host)
		s.sshClient.PtyExec(`sh /usr/local/iGeneral_client_2/upgrade.sh >/dev/null 2>&1 &`)
	}
}

// 配置 limit.conf
func (s *InitStepSet) step13() {
	var cmds []string
	// 删除默认的用户文件数，线程数，最大内存等资源
	cmds = append(cmds, `sed -i '/ulimit/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/root    soft    nofile    1048576/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/root    hard    nofile    1048576/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       soft    nofile    1048576/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       hard    nofile    1048576/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/root    soft    stack     65536/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/root    hard    stack     65536/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       soft    stack     65536/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       hard    stack     65536/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       soft    core      400000/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       hard    core      unlimited/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       soft    cpu       514195/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       hard    cpu       unlimited/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/root    -       data      unlimited/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       -       memlock   unlimited/d' /etc/security/limits.conf`)
	cmds = append(cmds, `sed -i '/*       -       nproc     unlimited/d' /etc/security/limits.conf`)

	// 重新设置
	cmds = append(cmds, `echo "# set ulimit by init" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "root    soft    nofile    1048576" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "root    hard    nofile    1048576" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       soft    nofile    1048576" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       hard    nofile    1048576" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "root    soft    stack     unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "root    hard    stack     unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       soft    stack     unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       hard    stack     unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       soft    core      unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       hard    core      unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       soft    cpu       unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       hard    cpu       unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "root    -       data      unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       -       memlock   unlimited" >> /etc/security/limits.conf`)
	cmds = append(cmds, `echo "*       -       nproc     unlimited" >> /etc/security/limits.conf`)
	for _, cmd := range cmds {
		s.sshClient.PtyExec(cmd)
	}
}

// 配置 limit.conf
func (s *InitStepSet) step14() {
	s.sshClient.PtyExec(fmt.Sprintf(`cp -av /etc/fstab /etc/fstab.%s`, s.Envs.Today))
	for i := 1; i <= 12; i++ {
		s.sshClient.PtyExec(fmt.Sprintf(`sed -i "/\/data%d/d" /etc/fstab`, i))
	}
	// 关闭交换分区
	s.sshClient.PtyExec(`sed -i "/swap/d" /etc/fstab`)
	s.sshClient.PtyExec(`swapoff -a`)
	s.sshClient.PtyExec(`blkid | grep -vE 'sda|/dev/loop|docker|iso9660|LVM2|block' | tr ':' ' ' | tr '"' ' ' | sort | awk '{ if(NF >4) print $1,"\t\t","/data"NR,"\t",$5,"\t","noatime,acl,user_xattr 1 2"}' >>/etc/fstab`)
	res := s.sshClient.PtyExec(`sed -n '16,$p' /etc/fstab | awk '{print $2}'`)
	for _, dir := range strings.Split(res.Msg, "\n") {
		s.sshClient.PtyExec(fmt.Sprintf(`[ -d ${dir} ] || mkdir %s`, dir))
	}
	s.sshClient.PtyExec(`[ -d /data1 ] || mkdir /data1`)
	s.sshClient.PtyExec(`mount -a >/dev/null 2>&1`)
	now := time.Now().Format("2006-01-02 15:04:05")
	s.sshClient.PtyExec(fmt.Sprintf(`echo "%s" >> /tmp/init_finally`, now))
}

// 配置
func (s *InitStepSet) step15() {
	s.sshClient.PtyExec(`[ -d /data/home ] || mkdir -p /data/home/`)
	ap_pass := s.sshClient.PtyExec(`$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | base64 -w 0 | rev | cut -b 2- | rev)`).Msg
	s.sshClient.PtyExec(`useradd appadmin -d /data/home/appadmin -s /bin/bash >/dev/null 2>&1`)
	s.sshClient.PtyExec(`chage -M 99999 appadmin`)
	s.sshClient.PtyExec(fmt.Sprintf(`echo "appadmin:%s" | chpasswd`, ap_pass))
	s.sshClient.PtyExec(`cat /tmp/bashrc >/data/home/appadmin/.bashrc`)
	// 创建iptables
	s.sshClient.PtyExec(`curl http://100.110.5.28/scripts/iptables.sh | bash -sx >/dev/null 2>&1`)
	s.sshClient.PtyExec(`mkdir /data/ajs`)
	s.sshClient.PtyExec(`wget -q http://xxxxxx/pkg/ajs_work_agent_dc.tgz -O /data/ajs/ajs_work_agent_dc.tgz`)
	s.sshClient.PtyExec(`tar zxf /data/ajs/ajs_work_agent_dc.tgz -C /tmp`)
	res := s.sshClient.PtyExec(`sh /tmp/ajs_work_agent/tools/op/install.sh >/dev/null 2>&1|echo $?`)
	if res.Msg != "0" {
		err := fmt.Errorf("ajs_work_agent agent install failed")
		s.StepErr.Err, s.StepErr.Code = err, GeneralError
		s.StepErr.Msg = "ajs_work_agent agent install failed"
		return
	}
	s.sshClient.PtyExec(`rm -rf /data/ajs`)

	// 安装cuda
	if s.sshClient.PtyExec(`lspci | grep -w NVIDIA >/dev/null && echo "ok"`).Msg == "ok" {
		if s.sshClient.PtyExec(`nvidia-smi >/dev/null 2>&1 && echo "ok"`).Msg != "ok" {
			s.sshClient.PtyExec(`mkdir /data/cuda`)
			s.sshClient.PtyExec(`wget -q http://xxxxx/pkg/cuda-9.1_install.tgz -O cuda-9.1_install.tgz -O /data`)
			s.sshClient.PtyExec(`tar zxf cuda-9.1_install.tgz -C /data`)
			s.sshClient.PtyExec(`tar zxf /data/CUDA/GPU-Driver/cudnn-9.1-linux-x64-v7.tgz -C /data/cuda`)
			s.sshClient.PtyExec(`mv /data/cuda/cuda /data/cuda/cudnn`)
			s.sshClient.PtyExec(`sh /data/gpu_driver_install.sh`)
		}
	}
	// 修改root
	s.sshClient.PtyExec(`if [ "x$NEWPASSWD" != "x" ];then echo "root:$NEWPASSWD" | chpasswd && echo "change root passwd to: '$NEWPASSWD'"; fi`)
}
