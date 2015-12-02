package vrpc

import (
	"net/rpc"
)

type Client struct {
	rpcClients []*rpc.Client
}

func Dial(network, address string, connections int) (*Client, error) {
	rpcClients := make([]*rpc.Client, connections)
	for i := range rpcClients {
		c, err := rpc.Dial(network, address)
		if err != nil {
			return nil, err
		}
		rpcClients[i] = c
	}
	return &Client{
		rpcClients: rpcClients,
	}, nil
}

func (c *Client) Call(method string, args interface{}, reply interface{}) error {
	return c.rpcClients[0].Call(method, args, reply)
}

type Call struct {
	Method string
	Args   interface{}
	Reply  interface{}
}

func (c *Client) CallMany(calls []*Call) error {
	if len(calls) == 0 {
		return nil
	}

	done := make(chan struct{})
	callChan := make(chan *Call, 4)

	go func() {
		for _, c := range calls {
			select {
			case callChan <- c:
				// ok
			case <-done:
				break
			}
		}
		close(callChan)
	}()

	results := make(chan *rpc.Call, len(calls))
	for _, rc := range c.rpcClients {
		go func(rc *rpc.Client) {
			for call := range callChan {
				rc.Go(call.Method, call.Args, call.Reply, results)
			}
		}(rc)
	}

	var err error
	var received int
	for call := range results {
		err = call.Error
		if err != nil {
			break
		}

		received++
		if received == len(calls) {
			close(results)
			break
		}
	}

	close(done)
	return err
}
