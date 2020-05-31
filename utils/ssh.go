package utils

import (
	"bytes"
	"fmt"
	"github.com/qq1141000259/public_tools/zlog"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	auth        []ssh.AuthMethod
	ShellPrompt = []byte{'#', ' '}
)

type SSHClient struct {
	client  *ssh.Client
	addr    *Address
	session *ssh.Session
	ptyIn   *chan<- string
	ptyOut  *<-chan []string
	ptyErr  *singleWriter
}

type Address struct {
	User      string `json:"user,omitempty"`
	Passwd    string `json:"pass,omitempty"`
	BakPasswd string `json:"bakpass,omitempty"`
	NewPasswd string `json:"newpass,omitempty"`
	Host      string `json:"host,omitempty"`
	Port      string `json:"port,omitempty"`
}

func NewSSHClient(addr *Address) (*SSHClient, error) {
	var auths []ssh.AuthMethod
	auths = append(auths, auth...)
	auths = append(auths, ssh.Password(addr.Passwd))
	auths = append(auths, ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		answers = make([]string, len(questions))
		if len(questions) >= 1 {
			answers[0] = addr.Passwd
		}
		if len(questions) >= 2 {
			answers[1] = addr.BakPasswd
		}
		return
	}))

	config := ssh.ClientConfig{
		Timeout:         2000 * time.Millisecond,
		User:            addr.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	config.SetDefaults()
	config.Ciphers = append(config.Ciphers, "aes128-cbc")
	if addr.Port == ""{
		addr.Port = "36000"
	}
	host := fmt.Sprintf("%v:%v", addr.Host, addr.Port)
	cli, err := ssh.Dial("tcp", host, &config)
	if err != nil {
		return nil, err
	}
	sshClient := SSHClient{
		client: cli,
		addr:   addr,
	}
	return &sshClient, nil
}

// 重新获取session
func (s *SSHClient) newSession() error {
	if s.session != nil {
		s.session.Close()
	}
	session, err := s.client.NewSession()
	if err != nil {
		return err
	}
	s.session = session
	return nil
}

type ExecResult struct {
	Err error
	Msg string
}

// 执行单一指令
func (s *SSHClient) SingleExec(cmd string) *ExecResult {
	ret := ExecResult{}
	if err := s.newSession(); err != nil {
		ret.Err, ret.Msg = err, "创建session失败"
		return &ret
	}
	var b singleWriter
	s.session.Stdout = &b
	s.session.Stderr = &b
	if err := s.session.Run(cmd); err != nil {
		ret.Err = err
	}
	ret.Msg = b.b.String()
	return &ret
}

// 执行多条指令(实际上多条命令用管道连接执行)
func (s *SSHClient) MultiExec(cmds []string) *ExecResult {
	ret := ExecResult{}
	if err := s.newSession(); err != nil {
		ret.Err, ret.Msg = err, "创建session失败"
		return &ret
	}
	var b singleWriter
	s.session.Stdout = &b
	s.session.Stderr = &b
	pipe, err := s.session.StdinPipe()
	if err != nil {
		ret.Err = err
		return &ret
	}
	if err := s.session.Shell(); err != nil {
		ret.Err = err
		return &ret
	}
	for _, cmd := range cmds {
		c := fmt.Sprintf("%s\n", cmd)
		pipe.Write([]byte(c))
	}
	pipe.Close()
	ret.Err = s.session.Wait()
	ret.Msg = b.b.String()
	return &ret
}

// 基于交互终端执行命令
func (s *SSHClient) PtyExec(cmd string) *ExecResult {
	ret := ExecResult{}
	*(s.ptyIn) <- cmd
	out := <-*(s.ptyOut)
	ret.Msg = strings.Join(out, "")
	if s.ptyErr.b.String() != "" {
		ret.Err = fmt.Errorf(s.ptyErr.b.String())
	}
	return &ret
	//var errInfo []byte
	//if n, err:=s.ptyErr.Read(errInfo);
}

// 创建交互终端
func (s *SSHClient) NewTerminal() error {
	var err error
	defer func() {
		if err != nil {
			s.session.Close()
		}
	}()
	if err = s.newSession(); err != nil {
		zlog.Errorf("IP: [%s] 创建session失败 %s", s.addr.Host, err.Error())
		return err
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := s.session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		zlog.Errorf("IP: [%s] 创建PTY失败 %s", s.addr.Host, err.Error())
		return err
	}
	wpipe, err := s.session.StdinPipe()
	if err != nil {
		zlog.Errorf("IP: [%s] 创建输入管道失败 %s", s.addr.Host, err.Error())
		return err
	}
	rpipe, err := s.session.StdoutPipe()
	if err != nil {
		zlog.Errorf("IP: [%s] 创建终端输出管道失败 %s", s.addr.Host, err.Error())
		return err
	}

	var b singleWriter
	s.session.Stderr = &b
	s.ptyErr = &b
	if err := s.session.Start("/bin/sh"); err != nil {
		zlog.Errorf("IP: [%s] 终端连接失败 %s", s.addr.Host, err.Error())
		return err
	}

	// 确定分隔符，这样才能从终端返回结果中提取实际命令行输出内容
	shellPrompt, err := guessShellPrompt(rpipe)
	if err != nil || !bytes.Contains(shellPrompt, []byte{'#'}){
		shellPrompt = ShellPrompt
	}
	shellPrompt = ShellPrompt
	in, out := muxShell(wpipe, rpipe, shellPrompt)
	s.ptyIn = &in
	s.ptyOut = &out
	return nil
}

func (s *SSHClient) Close(all bool) {
	s.session.Close()
	// 是否关闭client连接
	if all {
		s.client.Close()
	}
}

type singleWriter struct {
	b  bytes.Buffer
	mu sync.Mutex
}

func (w *singleWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func muxShell(w io.Writer, r io.Reader, matchingByte []byte) (chan<- string, <-chan []string) {
	// 创建输入和输出通道
	in := make(chan string, 1)
	out := make(chan []string, 1)
	var wg sync.WaitGroup
	//wg.Add(1)

	// 发送指令
	go func() {
		for cmd := range in {
			wg.Add(1)
			if strings.Contains(cmd, "wget"){
				fmt.Println("找到wget", cmd)
			}
			w.Write([]byte(cmd + "\n"))
			wg.Wait()
		}
	}()

	// 接收响应
	go func() {
		var buf [65 * 1024]byte
		var t,m int
		for {
			n, err := r.Read(buf[t:]) // 本身r就是一个Channel 会阻塞
			if err != nil {
				close(in)
				close(out)
				return
			}
			t += n
			if isMatch(buf[m:t], t-m, matchingByte) {
				stringResult := string(buf[m:t])
				var lst []string
				var sp []int
				// 需要去除多余的前后空格
				for i, l := range strings.Split(stringResult, "\n"){
					// 找到所有的 shell promot
					if strings.Contains(l, string(matchingByte)){
						sp = append(sp, i)
					}
					lst = append(lst, strings.TrimSpace(l))
				}
				// 提取返回结果，把真正的输出结果返回
				switch len(sp) {
				case 0:
					out <- lst
				case 1:
					if len(lst) == 1{
						out <- lst[0:len(lst)-1]
					} else {
						out <- lst[1:len(lst)-1]
					}
				case 2:
					out <- lst[sp[0] + 1:len(lst)-1]
				default:
					out <- lst[sp[len(sp)-2] + 1:len(lst)-1]
				}
				wg.Done()
				m = t
			}
		}

	}()
	return in, out
}

func Main2() {
	// Create client config
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("xxxxx"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// Connect to ssh server
	conn, err := ssh.Dial("tcp", "xxx:22", config)
	if err != nil {
		log.Fatal("unable to connect: ", err)
	}
	defer conn.Close()
	// Create a session
	session, err := conn.NewSession()
	if err != nil {
		log.Fatal("unable to create session: ", err)
	}
	defer session.Close()
	// Set up terminal modes
	//modes := ssh.TerminalModes{
	//	ssh.ECHO:          0,     // disable echoing
	//	ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
	//	ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	//}
	wpipe, err := session.StdinPipe()
	if err != nil {
		return
	}
	//rpipe, err := session.StdoutPipe()
	//if err != nil {
	//	return
	//}
	// Request pseudo terminal
	var b singleWriter
	session.Stdout = &b
	//if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
	//	log.Fatal("request for pseudo terminal failed: ", err)
	//}
	// Start remote shell
	if err := session.Shell(); err != nil {
		log.Fatal("failed to start shell: ", err)
	}
	_, err = wpipe.Write([]byte("echo '123'\n"))
	wpipe.Close()
	err = session.Wait()
	fmt.Println(b.b.String())
	_, err = wpipe.Write([]byte("echo '456'\n"))
	wpipe.Close()
	err = session.Wait()
	fmt.Println(b.b.String())
}

func readUntil(r io.Reader, matchingByte []byte) (*[]string, error) {
	var buf [65 * 1024]byte
	var t int
	for {
		n, err := r.Read(buf[t:])
		if err != nil {
			return nil, err
		}
		t += n
		if isMatch(buf[:t], t, matchingByte) {
			stringResult := string(buf[:t])
			// 需要去除掉 shell promot的那一行
			var lineFeed string
			if runtime.GOOS == "linux"{
				lineFeed = "\r\n"
			}else {
				lineFeed = "\n"
			}
			lst := strings.Split(stringResult, lineFeed)
			res := lst[:len(lst)-1]
			return &res, nil
		}
	}
}

func isMatch(bytes []byte, t int, matchingBytes []byte) bool {
	if t >= len(matchingBytes) {
		for i := 0; i < len(matchingBytes); i++ {
			if bytes[t-len(matchingBytes)+i] != matchingBytes[i] {
				return false
			}
		}
		return true
	}
	return false
}

func guessShellPrompt(r io.Reader) ([]byte, error) {
	var buf [1024]byte
	var t int
	n, err := r.Read(buf[t:])
	if err != nil {
		return nil, err
	}
	t += n
	return buf[t-2 : t], nil
}

