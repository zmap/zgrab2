package cli

import "github.com/sirupsen/logrus"

import "os"

// LoggerArguments holds command-line arguments for logger output.
type LoggerArguments struct {
	Verbose     bool   `short:"v" long:"verbose" description:"debug-level logging"`
	LogFilePath string `long:"log-file" description:"File to save log output"`
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
	if args.LogFilePath != "" && args.LogFilePath != "-" {
		outputFile, err := os.Create(args.LogFilePath)
		if err != nil {
			logger.SetLevel(logrus.FatalLevel)
			logger.Fatalf("could not open %s for logging: %s", args.LogFilePath, err)
		}
		logger.SetOutput(outputFile)
		logger.Infof("logging to %s", args.LogFilePath)
	}
	return logger
}

// NewLogger calls log.New(), and configures it based on the given
// LoggerArguments.
func (args *LoggerArguments) NewLogger() *logrus.Logger {
	logger := logrus.New()
	args.setUpLogger(logger)
	return logger
}
