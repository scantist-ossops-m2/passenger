/*
 *  Phusion Passenger - https://www.phusionpassenger.com/
 *  Copyright (c) 2010-2018 Phusion Holding B.V.
 *
 *  "Passenger", "Phusion Passenger" and "Union Station" are registered
 *  trademarks of Phusion Holding B.V.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

#include <ios>
#include <algorithm>
#include <stdexcept>
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <cassert>
#include <queue>
#include <sys/time.h>
#include <fcntl.h>
#include <utility>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <boost/json.hpp>
#include <boost/cstdint.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/foreach.hpp>
#include <oxt/thread.hpp>
#include <oxt/detail/context.hpp>

#include <Constants.h>
#include <StaticString.h>
#include <Exceptions.h>
#include <LoggingKit/Logging.h>
#include <LoggingKit/Assert.h>
#include <LoggingKit/Config.h>
#include <LoggingKit/Context.h>
#include <ConfigKit/ConfigKit.h>
#include <FileTools/PathManip.h>
#include <Utils.h>
#include <StrIntTools/StrIntUtils.h>
#include <JsonTools/JsonUtils.h>
#include <SystemTools/SystemTime.h>

namespace Passenger {
namespace LoggingKit {

using namespace std;


#define TRUNCATE_LOGPATHS_TO_MAXCHARS 3 // set to 0 to disable truncation

Context *context = NULL;
AssertionFailureInfo lastAssertionFailure;

void
initialize(const json::value &initialConfig, const ConfigKit::Translator &translator) {
	context = new Context(initialConfig, translator);
}

void
shutdown() {
	delete context;
	context = NULL;
}

Level getLevel() {
	if (OXT_LIKELY(context != NULL)) {
		return context->getConfigRealization()->level;
	} else {
		return Level(DEFAULT_LOG_LEVEL);
	}
}

void
setLevel(Level level) {
	json::object config;
	vector<ConfigKit::Error> errors;
	ConfigChangeRequest req;

	config["level"] = levelToString(level).toString();
	if (context->prepareConfigChange(config, errors, req)) {
		context->commitConfigChange(req);
	} else {
		P_BUG("Error setting log level: " << ConfigKit::toString(errors));
	}
}

Level
parseLevel(const StaticString &name) {
	if (name == "crit" || name == "0") {
		return CRIT;
	} else if (name == "error" || name == "1") {
		return ERROR;
	} else if (name == "warn" || name == "2") {
		return WARN;
	} else if (name == "notice" || name == "3") {
		return NOTICE;
	} else if (name == "info" || name == "4") {
		return INFO;
	} else if (name == "debug" || name == "5") {
		return DEBUG;
	} else if (name == "debug2" || name == "6") {
		return DEBUG2;
	} else if (name == "debug3" || name == "7") {
		return DEBUG3;
	} else {
		return UNKNOWN_LEVEL;
	}
}

StaticString
levelToString(Level level) {
	switch (level) {
	case CRIT:
		return P_STATIC_STRING("crit");
	case ERROR:
		return P_STATIC_STRING("error");
	case WARN:
		return P_STATIC_STRING("warn");
	case NOTICE:
		return P_STATIC_STRING("notice");
	case INFO:
		return P_STATIC_STRING("info");
	case DEBUG:
		return P_STATIC_STRING("debug");
	case DEBUG2:
		return P_STATIC_STRING("debug2");
	case DEBUG3:
		return P_STATIC_STRING("debug3");
	default:
		return P_STATIC_STRING("unknown");
	}
}


const char *
_strdupFastStringStream(const FastStringStream<> &stream) {
	char *buf = (char *) malloc(stream.size() + 1);
	memcpy(buf, stream.data(), stream.size());
	buf[stream.size()] = '\0';
	return buf;
}

bool
_passesLogLevel(const Context *context, Level level, const ConfigRealization **outputConfigRlz) {
	if (OXT_UNLIKELY(context == NULL)) {
		*outputConfigRlz = NULL;
		return Level(DEFAULT_LOG_LEVEL) >= level;
	} else {
		const ConfigRealization *configRlz = context->getConfigRealization();
		*outputConfigRlz = configRlz;
		return configRlz->level >= level;
	}
}

bool
_shouldLogFileDescriptors(const Context *context, const ConfigRealization **outputConfigRlz) {
	if (OXT_UNLIKELY(context == NULL)) {
		return false;
	} else {
		const ConfigRealization *configRlz = context->getConfigRealization();
		*outputConfigRlz = configRlz;
		return configRlz->fileDescriptorLogTargetType != NO_TARGET;
	}
}

void
_prepareLogEntry(FastStringStream<> &sstream, Level level, const char *file, unsigned int line) {
	struct tm the_tm;
	char datetime_buf[32];
	char threadIdBuf[std::max<unsigned int>(
		std::max<unsigned int>(
			2 * sizeof(boost::uintptr_t) + 1,
			2 * sizeof(unsigned int) + 1
		),
		32
	)];
	int datetime_size;
	unsigned int threadIdSize;
	struct timeval tv;
	StaticString logLevelMarkers[] = {
		P_STATIC_STRING("C"),
		P_STATIC_STRING("E"),
		P_STATIC_STRING("W"),
		P_STATIC_STRING("N"),
		P_STATIC_STRING("I"),
		P_STATIC_STRING("D"),
		P_STATIC_STRING("D2"),
		P_STATIC_STRING("D3")
	};

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &the_tm);
	datetime_size = snprintf(datetime_buf, sizeof(datetime_buf),
		"%d-%02d-%02d %02d:%02d:%02d.%04llu",
		the_tm.tm_year + 1900, the_tm.tm_mon + 1, the_tm.tm_mday,
		the_tm.tm_hour, the_tm.tm_min, the_tm.tm_sec,
		(unsigned long long) tv.tv_usec / 100);

	#ifdef OXT_THREAD_LOCAL_KEYWORD_SUPPORTED
		// We only use oxt::get_thread_local_context() if it is fast enough.
		oxt::thread_local_context *ctx = oxt::get_thread_local_context();
		if (OXT_LIKELY(ctx != NULL)) {
			threadIdSize = integerToHexatri(ctx->thread_number,
				threadIdBuf);
		} else {
			threadIdSize = integerToHexatri((boost::uintptr_t) pthread_self(),
				threadIdBuf);
		}
	#else
		threadIdSize = integerToHexatri((boost::uintptr_t) pthread_self(),
			threadIdBuf);
	#endif

	sstream <<
		P_STATIC_STRING("[ ") <<
		logLevelMarkers[int(level)] <<
		P_STATIC_STRING(" ") <<
		StaticString(datetime_buf, datetime_size) <<
		P_STATIC_STRING(" ") <<
		std::dec << getpid() <<
		P_STATIC_STRING("/T") <<
		StaticString(threadIdBuf, threadIdSize) <<
		P_STATIC_STRING(" ");

	if (startsWith(file, P_STATIC_STRING("src/"))) { // special reduncancy filter because most code resides in these paths
		file += sizeof("src/") - 1;
		if (startsWith(file, P_STATIC_STRING("cxx_supportlib/"))) {
			file += sizeof("cxx_supportlib/") - 1;
		}
	}

	if (TRUNCATE_LOGPATHS_TO_MAXCHARS > 0) {
		truncateBeforeTokens(file, P_STATIC_STRING("/\\"), TRUNCATE_LOGPATHS_TO_MAXCHARS, sstream);
	} else {
		sstream << file;
	}

	sstream << P_STATIC_STRING(":") <<
		line << P_STATIC_STRING(" ]: ");
}

static void
writeExactWithoutOXT(int fd, const char *str, unsigned int size) {
	/* We do not use writeExact() here because writeExact()
	 * uses oxt::syscalls::write(), which is an interruption point and
	 * which is slightly more expensive than a plain write().
	 * Logging may block, but in most cases not indefinitely,
	 * so we don't care if the write() here is not an interruption
	 * point. If the write does block indefinitely then it's
	 * probably a FIFO that is not opened on the other side.
	 * In that case we can blame the user.
	 */
	ssize_t ret;
	unsigned int written = 0;
	while (written < size) {
		do {
			ret = write(fd, str + written, size - written);
		} while (ret == -1 && errno == EINTR);
		if (ret == -1) {
			/* The most likely reason why this fails is when the user has setup
			 * Apache to log to a pipe (e.g. to a log rotation script). Upon
			 * restarting the web server, the process that reads from the pipe
			 * shuts down, so we can't write to it anymore. That's why we
			 * just ignore write errors. It doesn't make sense to abort for
			 * something like this.
			 */
			break;
		} else {
			written += ret;
		}
	}
}

void
_writeLogEntry(const ConfigRealization *configRealization, const char *str, unsigned int size) {
	if (OXT_LIKELY(configRealization != NULL)) {
		writeExactWithoutOXT(configRealization->targetFd, str, size);
	} else {
		writeExactWithoutOXT(STDERR_FILENO, str, size);
	}
}

void
_writeFileDescriptorLogEntry(const ConfigRealization *configRealization,
	const char *str, unsigned int size)
{
	assert(configRealization != NULL);
	assert(configRealization->fileDescriptorLogTargetType != UNKNOWN_TARGET);
	assert(configRealization->fileDescriptorLogTargetFd != -1);
	writeExactWithoutOXT(configRealization->fileDescriptorLogTargetFd, str, size);
}

void
Context::saveNewLog(const HashedStaticString &groupName, const char *sourceStr, unsigned int sourceStrLen, const char *message, unsigned int messageLen) {
	boost::lock_guard<boost::mutex> l(syncher); //lock

	unsigned long long timestamp = SystemTime::getUsec();

	LogStore::Cell *c = logStore.lookupCell(groupName);
	if (c == NULL) {
		AppGroupLog appGroupLog;
		appGroupLog.pidLog = TimestampedLogBuffer(LOG_MONITORING_MAX_LINES * 5);
		c = logStore.insert(groupName, appGroupLog);
	}
	AppGroupLog &rec = c->value;

	TimestampedLog ll;
	ll.timestamp = timestamp;
	ll.sourceId = string(sourceStr, sourceStrLen);
	ll.lineText = string(message, messageLen);
	rec.pidLog.push_back(ll);
	//unlock
}

void
Context::saveMonitoredFileLog(const HashedStaticString &groupName,
	const char *sourceStr, unsigned int sourceStrLen,
	const char *content, unsigned int contentLen)
{
	vector<StaticString> lines;
	split(StaticString(content, contentLen), '\n', lines);

	boost::lock_guard<boost::mutex> l(syncher); //lock

	LogStore::Cell *c = logStore.lookupCell(groupName);
	if (c == NULL) {
		AppGroupLog appGroupLog;
		appGroupLog.pidLog = TimestampedLogBuffer(LOG_MONITORING_MAX_LINES * 5);
		c = logStore.insert(groupName, appGroupLog);
	}
	AppGroupLog &rec = c->value;

	HashedStaticString source(sourceStr, sourceStrLen);
	SimpleLogMap::Cell *c2 = rec.watchFileLog.lookupCell(source);
	if (c2 == NULL) {
		SimpleLogBuffer logBuffer(LOG_MONITORING_MAX_LINES);
		c2 = rec.watchFileLog.insert(source, logBuffer);
	}
	c2->value.clear();
	foreach (StaticString line, lines) {
		c2->value.push_back(string(line.data(), line.size()));
	}
	//unlock
}

json::value
Context::convertLog(){
	boost::lock_guard<boost::mutex> l(syncher); //lock
	json::object reply;

	if (!logStore.empty()) {
		Context::LogStore::ConstIterator appGroupIter(logStore);
		while (*appGroupIter != NULL) {
			reply[appGroupIter.getKey()] = json::object();

			json::value &processLog = reply[appGroupIter.getKey()].at("Application process log (combined)");
			if (processLog.is_null()) {
				processLog.emplace_array();
			}
			foreach (TimestampedLog logLine, appGroupIter->value.pidLog) {
				json::object logLineJson;
				logLineJson["source_id"] = logLine.sourceId;
				logLineJson["timestamp"] = (uint64_t) logLine.timestamp;
				logLineJson["line"] = logLine.lineText;
				processLog.get_array().push_back(logLineJson);
			}

			Context::SimpleLogMap::ConstIterator watchFileLogIter(appGroupIter->value.watchFileLog);
			while (*watchFileLogIter != NULL) {
				json::object &appGroup = reply[appGroupIter.getKey()].get_object();
				if (!appGroup.contains(watchFileLogIter.getKey())) {
					appGroup[watchFileLogIter.getKey()] = json::array();
				}
				foreach (string line, watchFileLogIter->value) {
					appGroup[watchFileLogIter.getKey()].get_array().push_back(json::string(line));
				}
				watchFileLogIter.next();
			}

			appGroupIter.next();
		}
	}

	return reply;
	//unlock
}

static void
realLogAppOutput(const HashedStaticString &groupName, int targetFd,
    char *buf, unsigned int bufSize,
	const char *pidStr, unsigned int pidStrLen,
	const char *channelName, unsigned int channelNameLen,
	const char *message, unsigned int messageLen, int appLogFile,
	bool saveLog, bool prefixLogs)
{
	char *pos = buf;
	char *end = buf + bufSize;

	if (prefixLogs) {
		pos = appendData(pos, end, "App ");
		pos = appendData(pos, end, pidStr, pidStrLen);
		pos = appendData(pos, end, " ");
		pos = appendData(pos, end, channelName, channelNameLen);
		pos = appendData(pos, end, ": ");
	}
	pos = appendData(pos, end, message, messageLen);
	pos = appendData(pos, end, "\n");

	if (OXT_UNLIKELY(context != NULL && saveLog)) {
		context->saveNewLog(groupName, pidStr, pidStrLen, message, messageLen);
	}
	if (appLogFile > -1) {
		writeExactWithoutOXT(appLogFile, buf, pos - buf);
	}
	writeExactWithoutOXT(targetFd, buf, pos - buf);
}

void
logAppOutput(const HashedStaticString &groupName, pid_t pid, const StaticString &channelName,
	const char *message, unsigned int size, const StaticString &appLogFile)
{
	int targetFd;
	bool saveLog = false;
	bool prefixLogs = true;

	if (OXT_LIKELY(context != NULL)) {
		const ConfigRealization *configRealization = context->getConfigRealization();
		if (configRealization->level < configRealization->appOutputLogLevel) {
			return;
		}

		targetFd = configRealization->targetFd;
		saveLog = configRealization->saveLog;
		prefixLogs = !configRealization->disableLogPrefix;
	} else {
		targetFd = STDERR_FILENO;
	}

	int fd = -1;
	if (!appLogFile.empty()) {
		fd = open(appLogFile.data(), O_WRONLY | O_APPEND | O_CREAT, 0640);
		if (fd == -1) {
			int e = errno;
			P_ERROR("opening file: " << appLogFile << " for logging " << groupName << " failed. Error: " << strerror(e));
		}
	}
	char pidStr[sizeof("4294967295")];
	unsigned int pidStrLen, totalLen;

	try {
		pidStrLen = integerToOtherBase<pid_t, 10>(pid, pidStr, sizeof(pidStr));
	} catch (const std::length_error &) {
		pidStr[0] = '?';
		pidStr[1] = '\0';
		pidStrLen = 1;
	}

	totalLen = (sizeof("App X Y: \n") - 2) + pidStrLen + channelName.size() + size;
	if (totalLen < 1024) {
		char buf[1024];
		realLogAppOutput(groupName, targetFd,
			buf, sizeof(buf),
			pidStr, pidStrLen,
			channelName.data(), channelName.size(),
			message, size, fd, saveLog, prefixLogs);
	} else {
		DynamicBuffer buf(totalLen);
		realLogAppOutput(groupName, targetFd,
			buf.data, totalLen,
			pidStr, pidStrLen,
			channelName.data(), channelName.size(),
			message, size, fd, saveLog, prefixLogs);
	}
	if(fd > -1){close(fd);}
}


static json::object
normalizeConfig(const json::object &effectiveValues) {
	json::object updates;

	updates["level"] = levelToString(parseLevel(
		getJsonStringField(effectiveValues,"level"))).toString();
	updates["app_output_log_level"] = levelToString(parseLevel(
		getJsonStringField(effectiveValues,"app_output_log_level"))).toString();

	const json::value &effectiveTarget = effectiveValues.at("target");
	if (effectiveTarget.is_string()) {
		updates["target"] = json::object();
		updates["target"].at("path") = absolutizePath(effectiveTarget.as_string());
	} else if (!effectiveValues.at("target").at("path").is_null()) {
		updates["target"] = effectiveTarget;
		updates["target"].at("path") = absolutizePath(getJsonStaticStringField(effectiveTarget,"path"));
	}

	const json::value &effectiveLogTarget= effectiveValues.at("file_descriptor_log_target");
	if (effectiveLogTarget.is_string()) {
		updates["file_descriptor_log_target"] = json::object();
		updates["file_descriptor_log_target"].at("path") =
			absolutizePath(effectiveLogTarget.as_string());
	} else if (effectiveLogTarget.is_object()
			   && !effectiveLogTarget.at("path").is_null())
	{
		updates["file_descriptor_log_target"] = effectiveLogTarget;
		updates["file_descriptor_log_target"].at("path") =
			absolutizePath(getJsonStaticStringField(effectiveLogTarget,"path"));
	}

	return updates;
}


Context::Context(const json::value &initialConfig,
	const ConfigKit::Translator &translator)
	: config(schema, initialConfig.get_object(), translator),
	  gcThread(NULL),
	  shuttingDown(false)
{
	configRlz.store(new ConfigRealization(config));
	configRlz.load()->apply(config, NULL);
	configRlz.load()->finalize();
}

Context::~Context() {
	boost::unique_lock<boost::mutex> l(gcSyncher);

	// If a gc thread exists, tell it to shut down and
	// wait until it has done so.
	shuttingDown = true;
	gcShuttingDownCond.notify_one();
	while (gcThread != NULL) {
		gcHasShutDownCond.wait(l);
	}

	killGcThread();
	gcLockless(false, l);

	delete configRlz.load();
}

ConfigKit::Store
Context::getConfig() const {
	boost::lock_guard<boost::mutex> l(syncher);
	return config;
}

bool
Context::prepareConfigChange(const json::value &updates,
	vector<ConfigKit::Error> &errors, LoggingKit::ConfigChangeRequest &req)
{
	{
		boost::lock_guard<boost::mutex> l(syncher);
		req.config.reset(new ConfigKit::Store(config, updates.get_object(), errors));
	}
	if (!errors.empty()) {
		return false;
	}

	req.configRlz = new ConfigRealization(*req.config);
	return true;
}

void
Context::commitConfigChange(LoggingKit::ConfigChangeRequest &req) BOOST_NOEXCEPT_OR_NOTHROW {
	boost::lock_guard<boost::mutex> l(syncher);
	ConfigRealization *oldConfigRlz = configRlz.load();
	ConfigRealization *newConfigRlz = req.configRlz;

	req.configRlz->apply(*req.config, oldConfigRlz);

	config.swap(*req.config);

	configRlz.store(newConfigRlz, boost::memory_order_release);
	req.configRlz = NULL; // oldConfigRlz will be garbage collected by apply()

	newConfigRlz->finalize();
}

json::value
Context::inspectConfig() const {
	boost::lock_guard<boost::mutex> l(syncher);
	return config.inspect();
}

pair<ConfigRealization*,MonotonicTimeUsec>
Context::peekOldConfig() {
	return oldConfigs.front();
}

void
Context::popOldConfig(ConfigRealization *oldConfig) {
	delete oldConfig;
	oldConfigs.pop();
}

void
Context::createGcThread() {
	if (gcThread == NULL) {
		try {
			gcThread = new oxt::thread(boost::bind(&Context::gcThreadMain, this),
				"LoggingKit config garbage collector thread",
				128 * 1024);
		} catch (const std::exception &e) {
			P_ERROR("Error spawning background thread to garbage collect"
				" old LoggingKit configuration: " << e.what());
		}
	}
}

void
Context::pushOldConfigAndCreateGcThread(ConfigRealization *oldConfigRlz, MonotonicTimeUsec monotonicNow) {
	// Garbage collect old config realization in 5 minutes.
	// There is no way to cheaply find out whether oldConfigRlz
	// is still being used (we don't want to resort to more atomic
	// operations, or conservative garbage collection) but
	// waiting 5 minutes should be good enough.
	MonotonicTimeUsec gcTime = monotonicNow + 5llu * 60llu * 1000000llu;
	boost::unique_lock<boost::mutex> l(gcSyncher);
	oldConfigs.push(make_pair(oldConfigRlz, gcTime));
	createGcThread();
}

bool
Context::oldConfigsExist() {
	return !oldConfigs.empty();
}

void
Context::gcThreadMain() {
	boost::unique_lock<boost::mutex> l(gcSyncher);
	gcLockless(true, l);
}

void
Context::gcLockless(bool wait, boost::unique_lock<boost::mutex> &lock) {
	while (!shuttingDown && oldConfigsExist()) {
		pair<ConfigRealization *, MonotonicTimeUsec> p = peekOldConfig();
		for (MonotonicTimeUsec now = SystemTime::getMonotonicUsecWithGranularity<SystemTime::GRAN_1SEC>();
			 !shuttingDown && wait && now < p.second;
			 now = SystemTime::getMonotonicUsecWithGranularity<SystemTime::GRAN_1SEC>())
		{
			// Wait until it's time to GC this config object,
			// or until the destructor tells us that we're shutting down.
			gcShuttingDownCond.timed_wait(lock, boost::posix_time::microseconds(p.second - now));
		}
		if (!shuttingDown) {
			popOldConfig(p.first);
		}
	}
	killGcThread();
}

void
Context::killGcThread() {
	if (gcThread != NULL) {
		delete gcThread;
		gcThread = NULL;
	}
	gcHasShutDownCond.notify_one();
}

json::value
Schema::createStderrTarget() {
	json::object doc;
	doc["stderr"] = true;
	return doc;
}

void
Schema::validateLogLevel(const string &key, const ConfigKit::Store &store,
	vector<ConfigKit::Error> &errors)
{
	typedef ConfigKit::Error Error;
	Level level = parseLevel(store[key].as_string());
	if (level == UNKNOWN_LEVEL) {
		errors.push_back(Error("'{{" + key + "}}' must be one of"
			" 'crit', 'error', 'warn', 'notice', 'info', 'debug', 'debug2' or 'debug3'"));
	}
}

void
Schema::validateTarget(const string &key, const ConfigKit::Store &store,
	vector<ConfigKit::Error> &errors)
{
	typedef ConfigKit::Error Error;
	json::value value = store[key];
	string keyQuote = "'{{" + key + "}}'";

	if (value.is_null()) {
		return;
	}

	// Allowed formats:
	// "/path-to-file"
	// { "stderr": true }
	// { "path": "/path" }
	// { "path": "/path", "fd": 123 }
	// { "path": "/path", "stderr": true }

	if (value.is_object()) {
		json::object &ovalue = value.get_object();
		if (ovalue.contains("stderr")) {
			if (!ovalue["stderr"].is_bool() || !ovalue["stderr"].as_bool()) {
				errors.push_back(Error("When " + keyQuote
					+ " is an object containing the 'stderr' key,"
					" it must have the 'true' value"));
				return;
			}
		}

		if (ovalue.contains("path")) {
			if (!ovalue["path"].is_string()) {
				errors.push_back(Error("When " + keyQuote
					+ " is an object containing the 'path' key,"
					" it must be a string"));
			}
			if (ovalue.contains("fd")) {
				if (!ovalue["fd"].is_int64()) {
					errors.push_back(Error("When " + keyQuote
						+ " is an object containing the 'fd' key,"
						" it must be an integer"));
				} else if (ovalue["fd"].as_int64() < 0) {
					errors.push_back(Error("When " + keyQuote
						+ " is an object containing the 'fd' key,"
						" it must be 0 or greater"));
				}
			}
			if (ovalue.contains("fd") && ovalue.contains("stderr")) {
				errors.push_back(Error(keyQuote
					+ " may contain either the 'fd' or the"
					" 'stderr' key, but not both"));
			}
		} else if (ovalue.contains("stderr")) {
			if (ovalue.size() > 1) {
				errors.push_back(Error("When " + keyQuote
					+ " is an object containing the 'stderr' key,"
					" it may not contain any other keys"));
			} else if (!ovalue["stderr"].as_bool()) {
				errors.push_back(Error("When " + keyQuote
					+ " is an object containing the 'stderr' key,"
					" it must have the 'true' value"));
			}
		} else {
			errors.push_back(Error("When " + keyQuote
				+ " is an object, it must contain either"
				" the 'stderr' or 'path' key"));
		}
	} else if (!value.is_string()) {
		errors.push_back(Error(keyQuote
			+ " must be either a string or an object"));
	}
}

static json::value
filterTargetFd(const json::value &value) {
	json::object result = value.get_object();
	result.erase("fd");
	return result;
}

Schema::Schema() {
	using namespace ConfigKit;

	add("level", STRING_TYPE, OPTIONAL, DEFAULT_LOG_LEVEL_NAME);
	add("target", ANY_TYPE, OPTIONAL, createStderrTarget())
		.setInspectFilter(filterTargetFd);
	add("file_descriptor_log_target", ANY_TYPE, OPTIONAL)
		.setInspectFilter(filterTargetFd);
	add("redirect_stderr", BOOL_TYPE, OPTIONAL, true);
	add("app_output_log_level", STRING_TYPE, OPTIONAL, DEFAULT_APP_OUTPUT_LOG_LEVEL_NAME);
	add("buffer_logs", BOOL_TYPE, OPTIONAL, false);
	add("disable_log_prefix", BOOL_TYPE, OPTIONAL, false);

	addValidator(boost::bind(validateLogLevel, "level",
		boost::placeholders::_1, boost::placeholders::_2));
	addValidator(boost::bind(validateLogLevel, "app_output_log_level",
		boost::placeholders::_1, boost::placeholders::_2));
	addValidator(boost::bind(validateTarget, "target",
		boost::placeholders::_1, boost::placeholders::_2));
	addValidator(boost::bind(validateTarget, "file_descriptor_log_target",
		boost::placeholders::_1, boost::placeholders::_2));

	addNormalizer(normalizeConfig);

	finalize();
}


ConfigRealization::ConfigRealization(const ConfigKit::Store &store)
	: level(parseLevel(store["level"].as_string())),
	  appOutputLogLevel(parseLevel(store["app_output_log_level"].as_string())),
	  saveLog(store["buffer_logs"].as_bool()),
	  finalized(false),
	  disableLogPrefix(store["disable_log_prefix"].as_bool())
{
	const json::object &storeTarget = store["target"].get_object();
	if (storeTarget.contains("stderr")) {
		targetType = STDERR_TARGET;
		targetFd = STDERR_FILENO;
		targetFdClosePolicy = NEVER_CLOSE;
	} else if (!storeTarget.contains("fd") || storeTarget.at("fd").is_null()) {
		string path = getJsonStringField(storeTarget,"path");
		targetType = FILE_TARGET;
		targetFd = syscalls::open(path.c_str(),
			O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (targetFd == -1) {
			int e = errno;
			throw FileSystemException(
				"Cannot open " + path + " for writing",
				e, path);
		}
		targetFdClosePolicy = ALWAYS_CLOSE;
	} else {
		targetType = FILE_TARGET;
		targetFd = getJsonIntField(storeTarget,"fd");
		// If anything goes wrong before finalization, then
		// the caller is responsible for cleaning up the fd.
		// See the Context class description.
		targetFdClosePolicy = CLOSE_WHEN_FINALIZED;
	}

	const json::object &storeLogTarget = store["file_descriptor_log_target"].get_object();
	if (store["file_descriptor_log_target"].is_null()) {
		fileDescriptorLogTargetType = NO_TARGET;
		fileDescriptorLogTargetFd = -1;
		fileDescriptorLogTargetFdClosePolicy = NEVER_CLOSE;
	} else if (storeLogTarget.contains("stderr")) {
		fileDescriptorLogTargetType = STDERR_TARGET;
		fileDescriptorLogTargetFd = STDERR_FILENO;
		fileDescriptorLogTargetFdClosePolicy = NEVER_CLOSE;
	} else if (!storeLogTarget.contains("fd") || storeLogTarget.at("fd").is_null()) {
		string path = getJsonStringField(storeLogTarget,"path");
		fileDescriptorLogTargetType = FILE_TARGET;
		fileDescriptorLogTargetFd = syscalls::open(path.c_str(),
			O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (fileDescriptorLogTargetFd == -1) {
			int e = errno;
			throw FileSystemException(
				"Cannot open " + path + " for writing",
				e, path);
		}
		fileDescriptorLogTargetFdClosePolicy = ALWAYS_CLOSE;
	} else {
		fileDescriptorLogTargetType = FILE_TARGET;
		fileDescriptorLogTargetFd = getJsonIntField(storeLogTarget,"fd");
		// If anything goes wrong before finalization, then
		// the caller is responsible for cleaning up the fd.
		// See the Context class description.
		fileDescriptorLogTargetFdClosePolicy = CLOSE_WHEN_FINALIZED;
	}
}

ConfigRealization::~ConfigRealization() {
	switch (targetFdClosePolicy) {
	case NEVER_CLOSE:
		// Do nothing.
		break;
	case ALWAYS_CLOSE:
		syscalls::close(targetFd);
		break;
	case CLOSE_WHEN_FINALIZED:
		if (finalized) {
			syscalls::close(targetFd);
		}
		break;
	}

	switch (fileDescriptorLogTargetFdClosePolicy) {
	case NEVER_CLOSE:
		// Do nothing.
		break;
	case ALWAYS_CLOSE:
		syscalls::close(fileDescriptorLogTargetFd);
		break;
	case CLOSE_WHEN_FINALIZED:
		if (finalized) {
			syscalls::close(fileDescriptorLogTargetFd);
		}
		break;
	}
}

void
ConfigRealization::apply(const ConfigKit::Store &config, ConfigRealization *oldConfigRlz)
	BOOST_NOEXCEPT_OR_NOTHROW
{
	if (config["redirect_stderr"].as_bool()) {
		int ret = syscalls::dup2(targetFd, STDERR_FILENO);
		if (ret == -1) {
			int e = errno;
			P_ERROR("Error redirecting logging target to stderr: "
				<< strerror(e) << " (errno=" << e << ")");
		}
	}

	if (oldConfigRlz != NULL) {
		MonotonicTimeUsec monotonicNow = SystemTime::getMonotonicUsecWithGranularity<SystemTime::GRAN_1SEC>();
		context->pushOldConfigAndCreateGcThread(oldConfigRlz, monotonicNow);
	}
}

void
ConfigRealization::finalize() {
	finalized = true;
}


ConfigChangeRequest::ConfigChangeRequest()
	: configRlz(NULL)
{
	// Do nothing.
}

ConfigChangeRequest::~ConfigChangeRequest() {
	delete configRlz;
}


} // namespace LoggingKit
} // namespace Passenger
