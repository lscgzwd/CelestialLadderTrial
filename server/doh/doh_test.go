package doh

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestDoh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := New()
	rsp, err := c.ECSQuery(ctx, "www.aliyun.com", TypeA, "110.242.68.0/24")
	fmt.Printf("err: %+v, res: %+v", err, rsp)
}
