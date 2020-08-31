package burp;

import java.io.PrintWriter;

public class Logger {
    private static int logLevel = 2;
    public static final int SEVERE = 0;
    public static final int WARN = 1;
    public static final int INFO = 2;
    public static final int DEBUG = 3;

    private PrintWriter pw;

    public Logger(PrintWriter pw) {
        this.pw = pw;
    }

    public void debug(String msg) {
        if (logLevel >= Logger.DEBUG) {
            pw.println(msg);
        }
    }

    public void info(String msg) {
        if (logLevel >= Logger.INFO) {
            pw.println(msg);
        }
    }

    public void warn(String msg) {
        if (logLevel >= Logger.WARN) {
            pw.println(msg);
        }
    }

    public void severe(String msg) {
        if (logLevel >= Logger.SEVERE) {
            pw.println(msg);
        }
    }

    public static int getLogLevel() {
        return logLevel;
    }

    public static void setLogLevel(int level) {
        logLevel = level;
    }

}
