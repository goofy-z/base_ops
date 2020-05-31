package utils

import (
	"encoding/json"
	"fmt"
	"github.com/qq1141000259/public_tools/zlog"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"
)

const (
	uworkApipoint   = ""
	systemid        = ""
	contentTypeJSON = "application/json"
)

// RaidType  raid type
type RaidType string

func (rt RaidType) String() string {
	return string(rt)
}

const (
	Raid5        RaidType = "RAID5"
	Raid0        RaidType = "RAID0"
	Raid10       RaidType = "RAID1+0"
	RaidNone     RaidType = "NORAID"
	RaidKeepLast RaidType = ""
)

// OSVersion  os versions to install
type OSVersion string

func (os OSVersion) String() string {
	if strings.ToLower(string(os)) == "tlinux1" {
		return string(Tlinux1)
	}
	if strings.ToLower(string(os)) == "tlinux2" {
		return string(Tlinux2)
	}
	return string(os)
}

const (
	Tlinux1             OSVersion = "Tencent tlinux release 1.2 (Final)"
	Tlinux2             OSVersion = "Tencent tlinux release 2.2 (Final)"
	Tlinux1WithTkernel2 OSVersion = "Tencent tlinux release 1.2 (tkernel2)"
)

// uworkRequestHeader  common request header
type uworkRequestHeader struct {
	Action   string      `json:"Action,omitempty"`
	Method   string      `json:"Method,omitempty"`
	FlowID   string      `json:"FlowId,omitempty"`
	SystemID string      `json:"SystemId,omitempty"`
	Starter  string      `json:"Starter,omitempty"`
	Data     interface{} `json:"Data"`
}

// uworkCommonResponse  common response format
type uworkCommonResponse struct {
	Return  int             `json:"Return"`
	Details string          `json:"Details"`
	Data    json.RawMessage `json:"Data"`
}

// 重装ticket
type UworkReinstallOSTicket struct {
	OS        OSVersion `json:"os,omitempty"`
	Operator  string    `json:"operator,omitempty"`
	Passwd    string    `json:"passwd,omitempty"`
	RaidType  RaidType  `json:"raidType,omitempty"` // RAID5, RAID0, RAID1+0, NORAID, RaidKeepLast
	Partition bool      `json:"partition,omitempty"`
	Manual    *bool     `json:"manual,omitempty"`
}

type ReinstallOptions struct {
	IP        string    `json:"ip,omitempty"`
	Asset     string    `json:"asset"`
	OS        OSVersion `json:"os,omitempty"`
	Operator  string    `json:"operator,omitempty"`
	Passwd    string    `json:"passwd,omitempty"`
	RaidType  RaidType  `json:"raidType,omitempty"` // RAID5, RAID0, RAID1+0, NORAID, RaidKeepLast
	Partition bool      `json:"partition,omitempty"`
	Manual    *bool     `json:"manual,omitempty"`
}

func ReinstallOS(opt ReinstallOptions) (ticket string, err error) {
	partition := "0"
	if opt.Partition {
		partition = "1"
	}

	manual := "1"
	if opt.Manual != nil && !*opt.Manual {
		manual = "0"
	}

	data := map[string]string{
		"Operator":  opt.Operator,
		"IP":        opt.IP,
		"AssetId":   opt.Asset,
		"Password":  opt.Passwd,
		"OSVersion": opt.OS.String(),
		"Raid":      opt.RaidType.String(),
		"Partition": partition,
		"Manual":    manual,
	}

	req := &uworkRequestHeader{
		Action:   "ServerSelfInstallOS",
		FlowID:   "38",
		SystemID: systemid,
		Starter:  opt.Operator,
		Data:     data,
	}

	respMap := map[string]int{}
	if err := uworkDoRequest(req, 0, &respMap); err != nil {
		return "", err
	}

	id := respMap["InstanceId"]

	return fmt.Sprintf("%v", id), nil
}


// 重装状态
type ReinstallOSStatusQueryOptions struct {
	IP         string `json:"ip"`
	InstanceID string `json:"instanceId"`
	Asset    string `json:"asset"`
}

type ReinstallStatus string

const (
	ReinstallStausSuccess ReinstallStatus = "1"
	ReinstallStatusFailed ReinstallStatus = "-1"
)

func (r ReinstallStatus) String() string {
	switch r {
	case "1":
		return "重装成功"
	case "0":
		return "重装中"
	case "-1":
		return "重装失败"
	case "-2":
		return "未查到单"
	default:
		return "未知状态"
	}
}

type ReinstallOSStatus struct {
	ServerAssetID   string          `json:"ServerAssetId"`
	ServerIP        string          `json:"ServerIP"`
	InstanceID      string          `json:"InstanceId"`
	ReinstallStatus ReinstallStatus `json:"ReinstallStatus"`
	Message         string          `json:"Message"`
	IsManual        int             `json:"IsManual"`
}

func GetReinstallOSStatus(opts ...ReinstallOSStatusQueryOptions) ([]*ReinstallOSStatus, error) {
	var data []map[string]string
	for _, opt := range opts {
		data = append(data, map[string]string{
			"ServerIP":      opt.IP,
			"ServerAssetId": opt.Asset,
			"InstanceId":    opt.InstanceID,
		})
	}

	req := uworkRequestHeader{
		Action:   "QueryData",
		Method:   "Reinstall",
		FlowID:   "38",
		SystemID: systemid,
		Data:     data,
	}

	var status []*ReinstallOSStatus
	if err := uworkDoRequest(req, 0, &status); err != nil {
		return nil, err
	}

	return status, nil
}


// uwork请求封装
func uworkDoRequest(req interface{}, timeout time.Duration, result interface{}) error {
	d, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if timeout == 0 {
		timeout = 120 * time.Second
	}

	client := http.Client{Timeout: timeout}
	url := uworkApipoint
	zlog.Infof("uwork request body: %s", d)
	resp, err := client.Post(url, contentTypeJSON, strings.NewReader(string(d)))
	if err != nil {
		return err
	}

	if resp.Body == nil {
		return fmt.Errorf("uwork server returned body is nil")
	}

	defer resp.Body.Close()

	respData := uworkCommonResponse{}
	data, _ := ioutil.ReadAll(resp.Body)
	zlog.Infof("uwork response: %s", data)
	if err := json.Unmarshal(data, &respData); err != nil {
		return err
	}

	if respData.Return != 0 {
		return fmt.Errorf("%v: %v", respData.Return, respData.Details)
	}

	if result == nil {
		return nil
	}
	resultValue := reflect.ValueOf(result)
	if resultValue.Kind() != reflect.Ptr || resultValue.IsNil() {
		return &json.InvalidUnmarshalError{Type: reflect.TypeOf(result)}
	}

	return json.Unmarshal(respData.Data, result)
}