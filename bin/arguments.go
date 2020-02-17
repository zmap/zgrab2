package bin

import "github.com/sirupsen/logrus"

// LoggerArguments holds command-line arguments for logger output.
type LoggerArguments struct {
	Verbose bool `short:"v" long:"verbose" description:"debug-level logging" env:"CENSYS_LOG_VERBOSE"`
}

func (args *LoggerArguments) setUpLogger(logger *logrus.Logger) {
	if args.Verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
}

// InitLogging configures the standard logger with values based on the given
// LoggerArguments. For convenience, it returns a reference to the standard
// logger.
func (args *LoggerArguments) InitLogging() *logrus.Logger {
	logger := logrus.StandardLogger()
	args.setUpLogger(logger)
	return logger
}

// NewLogger calls log.New(), and configures it based on the given
// LoggerArguments.
func (args *LoggerArguments) NewLogger() *logrus.Logger {
	logger := logrus.New()
	args.setUpLogger(logger)
	return logger
}
