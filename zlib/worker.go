package zlib

// GrabWorker implements worker interface
type GrabWorker struct {
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

//dafuq does this do

func (g *GrabWorker) Success() uint {
	return g.success
}

func (g *GrabWorker) Failure() uint {
	return g.failure
}

func (g *GrabWorker) Total() uint {
	return g.success + g.failure
}

func (g *GrabWorker) Done() {
	close(g.statuses)
}

func (g *GrabWorker) MakeHandler() Handler {
	return func(v interface{}) interface{} {
		return v
	}
}
