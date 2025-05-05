package collector

import (
    "bufio"
    "fmt"
    "net"
    "os"
    "strconv"
    "strings"

    "github.com/prometheus/client_golang/prometheus"
    "log/slog"
)

// tcpStateMap 从 /proc/net/tcp 状态码映射到字符串
var tcpStateMap = map[string]string{
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2","06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

// networkConnectionsCollector 实现了 Collector 接口
type networkConnectionsCollector struct {
    desc   *prometheus.Desc
    logger *slog.Logger
}

func init() {
    // 注册 Collector，默认禁用
    registerCollector("network_connections", defaultDisabled, NewNetworkConnectionsCollector)
}

// NewNetworkConnectionsCollector 构造函数
func NewNetworkConnectionsCollector(logger *slog.Logger) (Collector, error) {
    desc := prometheus.NewDesc(
        prometheus.BuildFQName(namespace, "network", "connections"),
        "Number of TCP connections by remote IP, port, protocol, and state.",
        []string{"ip", "port", "protocol", "state"}, nil,
    )
    return &networkConnectionsCollector{desc: desc, logger: logger}, nil
}

// Describe 发送描述符
func (c *networkConnectionsCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.desc
}

// Update 读取 /proc/net/tcp 和 /proc/net/tcp6，统计并输出指标
// Update 方法内替换为：
func (c *networkConnectionsCollector) Update(ch chan<- prometheus.Metric) error {
    counts := make(map[ConnKey]float64)

    for _, filePath := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
        f, err := os.Open(filePath)
        if err != nil {
            if os.IsNotExist(err) {
                continue
            }
            c.logger.Warn("open proc file failed", "path", filePath, "err", err)
            continue
        }
        scanner := bufio.NewScanner(f)
        scanner.Scan() // 跳过表头

        for scanner.Scan() {
            fields := strings.Fields(scanner.Text())
            if len(fields) < 4 {
                continue
            }
            // 使用 local_address 而非 rem_address
            local := fields[1]               // e.g. "0100007F:1A0A":contentReference[oaicite:8]{index=8}
            stateHex := fields[3]            // e.g. "06"

            parts := strings.Split(local, ":")
            if len(parts) != 2 {
                continue
            }

            ip := hexToIP(parts[0])          // 16 进制转字符串 IP:contentReference[oaicite:9]{index=9}
            p, err := strconv.ParseUint(parts[1], 16, 16)
            if err != nil {
                continue
            }
            port := fmt.Sprint(p)

            state := tcpStateMap[stateHex]   // 包含 LISTEN ("0A") 等所有状态:contentReference[oaicite:10]{index=10}
            key := ConnKey{Protocol: "tcp", IP: ip, Port: port, State: state}
            counts[key]++
        }
        f.Close()
    }

    // 输出指标，标签顺序与 Desc 定义保持一致
    for key, val := range counts {
        ch <- prometheus.MustNewConstMetric(
            c.desc, prometheus.GaugeValue, val,
            key.Protocol, key.IP, key.Port, key.State,
        )
    }
    return nil
}


// ConnKey 聚合分组键
type ConnKey struct {
    IP, Port, Protocol, State string
}

// hexToIP 将 8 或 32 字符的十六进制字符串转换成 IP 字符串
func hexToIP(s string) string {
    switch len(s) {
    case 8: // IPv4
        b := make([]byte, 4)
        for i := 0; i < 4; i++ {
            v, _ := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
            b[3-i] = byte(v)
        }
        return net.IP(b).String() // e.g. "127.0.0.1":contentReference[oaicite:5]{index=5}
    case 32: // IPv6
        b := make([]byte, 16)
        for i := 0; i < 16; i++ {
            v, _ := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
            b[15-i] = byte(v)
        }
        return net.IP(b).String()
    default:
        return ""
    }
}
