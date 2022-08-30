package main

import (
	"encoding/json"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/systray"
	"github.com/Ullaakut/nmap"
	"go-scan/ui"
	"os"
	"strings"
	"sync"
	"time"
)

func Emain() {
	App := app.NewWithID(ui.AppName)
	mainWindow := App.NewWindow(ui.AppName + " " + ui.VerSion)
	//App.SetIcon(ui.Logo)
	ui.MainWindow(mainWindow)
	if desk, ok := App.(desktop.App); ok {
		ui.SetupSystray(desk, mainWindow)
	}
	mainWindow.Resize(fyne.Size{Width: ui.Width, Height: ui.Height})
	mainWindow.SetFixedSize(true)
	mainWindow.CenterOnScreen()
	//mainWindow.SetIcon(ui.Logo)

	// setting intercept not to close app, but hide window,
	// and close only via tray
	mainWindow.SetCloseIntercept(func() {
		ui.Notification(ui.AppName, fmt.Sprintf("%s  minimized!", ui.AppName))
		mainWindow.Hide()
	})

	mainWindow.Show()

	App.Lifecycle().SetOnStarted(func() {
		systray.SetTooltip(ui.AppName)
	})
	App.Run()
	err := os.Unsetenv("FYNE_FONT")
	if err != nil {
		return
	}
}

var (
	ListHostIP []string
	wg         sync.WaitGroup
	rwlock     sync.RWMutex
)

type Port struct {
	Id    uint16 `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}
type HostInfo struct {
	Ip     string  `json:"ip"`
	OsName string  `json:"os_name"`
	Ports  []*Port `json:"ports"`
}

// 初始化连接池
//func initPool(server, pass string, database int) *redis.Pool {
//	return &redis.Pool{
//		// 设置最大空闲
//		MaxIdle: 64,
//		// 设置最大活跃数 0代表无限
//		MaxActive:0,
//		// 闲置空闲时间，单位秒
//		IdleTimeout:3600,
//		Dial: func() (redis.Conn, error) {
//			conn, err := redis.Dial("tcp", server,
//				redis.DialReadTimeout(time.Second*10),
//				redis.DialConnectTimeout(time.Second*30),
//				redis.DialPassword(pass),
//				redis.DialDatabase(database),
//			)
//			if err != nil {
//				fmt.Println("ERROR: fail init redis pool:", err.Error())
//				return nil, fmt.Errorf("ERROR: fail init redis pool: %s", err.Error())
//			}
//			return conn, err
//		},
//	}
//}

func main() {
	start := time.Now()
	// redis创建连接池 ip, pass ,db
	//pool := initPool("192.168.1.5:6379", "", 11)
	////  池子的关闭
	//defer pool.Close()
	//
	////  从池子取连接
	//conn := pool.Get()
	//
	//// 当前一个连接的关闭，用完即放回去池子并不是真的关闭
	//defer conn.Close()

	//go func() {
	//	// 清理在线列表
	//	rep, err := redis.Values(conn.Do("lrange", "iplist", 0, -1))
	//	for _, v := range rep {
	//		_, err = conn.Do("del", v.([]byte))
	//	}
	//	_, err = conn.Do("del", "iplist")
	//	if err != nil {
	//		fmt.Println("del err ", err)
	//	}
	//}()

	// nmap -O 192.168.0.0/24
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("192.168.100.0/24"),
		nmap.WithPingScan(),
	)
	if err != nil {
		fmt.Printf("unable to create nmap scanner: %v", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		fmt.Printf("run nmap scan failed: %v", err)
	}

	for _, host := range result.Hosts {
		// 查询出所有在线 IP
		ip := fmt.Sprintf("%s", host.Addresses[0])
		// 返回给数组
		ListHostIP = append(ListHostIP, ip)
	}

	for _, ip := range ListHostIP {
		// 遍历每个ip 开启多个 goroutine
		go func(ip string) {
			defer wg.Done()
			data := HostsInfo(ip)
			rwlock.RLock()
			if data != "" {
				fmt.Println(ip)
				//_, err = conn.Do("set", ip, data)
				//_, err = conn.Do("rpush", "iplist", ip)
				if err != nil {
					fmt.Println("set err ", err)
				}
			}
			rwlock.RUnlock()
		}(ip)
		wg.Add(1)
	}
	// 等待所有完成
	wg.Wait()
	fmt.Println(time.Now().Sub(start))
}

// 扫描具体信息
func HostsInfo(ips string) (data string) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ips),
		// 开启快速查询  -F
		//nmap.WithFastMode(),
		// 标准查询  -O
		nmap.WithOSDetection(),
	)
	if err != nil {
		fmt.Println("unable to create nmap scanner: %v", err)
	}
	result, _, err := scanner.Run()
	if err != nil {
		fmt.Println("run nmap scan failed: %v", err)
	}
	// 初始化结构体
	hosts := new(HostInfo)

	for _, host := range result.Hosts {
		// 过滤 主机 条件
		for _, match := range host.OS.Matches {
			os_name := match.Name
			if strings.Contains(os_name, "Linux") && !strings.Contains(os_name, "Android") {
				rwlock.Lock()
				hosts.OsName = match.Name
				hosts.Ip = ips
				rwlock.Unlock()
				//    查主机  端口 和服务 信息
				for _, port := range host.Ports {
					if port.Service.Name != "" {
						rwlock.Lock()
						hosts.Ports = append(hosts.Ports, &Port{
							Id:    port.ID,
							State: port.State.State,
							Name:  port.Service.Name,
						})
						rwlock.Unlock()
					}
				}
			}
		}
	}
	if hosts.Ports != nil {
		json_data, _ := json.Marshal(hosts)
		return string(json_data)
	}
	return ""
}
