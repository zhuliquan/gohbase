module github.com/tsuna/gohbase

go 1.13

require (
	github.com/go-zookeeper/zk v1.0.2
	github.com/golang/mock v1.4.3
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4
	github.com/jcmturner/gofork v1.0.0
	github.com/jcmturner/gokrb5/v8 v8.4.2
	github.com/prometheus/client_golang v1.11.0
	github.com/sirupsen/logrus v1.8.1
	go.opentelemetry.io/otel v1.0.1
	go.opentelemetry.io/otel/trace v1.0.1
	google.golang.org/protobuf v1.27.1
	modernc.org/b v1.0.0
	modernc.org/mathutil v1.1.1 // indirect
	modernc.org/strutil v1.1.0 // indirect
)

replace github.com/go-zookeeper/zk => github.com/zhuliquan/zk v1.0.3-0.20220306123430-808a4fdccf2a