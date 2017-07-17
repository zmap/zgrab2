package zlib

// Controller implements worker interface
type Controller struct {
	success  uint
	failure  uint
	statuses chan status

	//need to put config here...but options struct is in main
	//do we need a config? don't need if runCount is only use
}

type status uint

const (
	status_success status = iota
	status_failure status = iota
)

func (c *Controller) Success() uint {
	return c.success
}

func (c *Controller) Failure() uint {
	return c.failure
}

func (c *Controller) Total() uint {
	return c.success + c.failure
}

func (c *Controller) Done() {
	close(c.statuses)
}

func MakeNewController() Controller {
	w := new(Controller)
	w.statuses = make(chan status, Options[0].Senders*4)
	/* you can uncomment this when you get your shit together
	go func() {
		for s := range w.statuses {
			switch s {
			case status_success:
				w.success++
			case status_failure:
				w.failure++
			default:
				continue
			}
		}
	}() */
	return *w
}
