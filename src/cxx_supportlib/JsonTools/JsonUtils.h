/*
 *  Phusion Passenger - https://www.phusionpassenger.com/
 *  Copyright (c) 2014-2018 Phusion Holding B.V.
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
#ifndef _PASSENGER_JSON_TOOLS_JSON_UTILS_H_
#define _PASSENGER_JSON_TOOLS_JSON_UTILS_H_

#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <boost/json.hpp>
#include <boost/cstdint.hpp>
#include <StaticString.h>
#include <SystemTools/SystemTime.h>
#include <StrIntTools/StrIntUtils.h>
#include <Utils/VariantMap.h>

namespace Passenger {

using namespace std;


/**************************************************************
 *
 * Methods for querying fields from a JSON document.
 * If the field is missing, thhese methods can either return
 * a default value, or throw an exception.
 *
 **************************************************************/

inline const json::value &
getJsonField(const json::object &json, const char *key) {
	if (json.contains(key)) {
		return json.at(key);
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline json::value &
getJsonField(json::object &json, const char *key) {
	if (json.contains(key)) {
		return json[key];
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline int
getJsonIntField(const json::object &json, const char *key) {
	if (json.contains(key)) {
		return json.at(key).as_int64();
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline int
getJsonIntField(const json::object &json, const json::string &key) {
	if (json.contains(key)) {
		return json.at(key).as_int64();
	} else {
		throw VariantMap::MissingKeyException(key.c_str());
	}
}

inline int
getJsonIntField(const json::object &json, const json::string &key, int defaultValue) {
	if (json.contains(key)) {
		return json.at(key).as_int64();
	} else {
		return defaultValue;
	}
}

inline void
getJsonIntField(const json::object &json, const json::string &key, int *result) {
	if (json.contains(key)) {
		*result = json.at(key).as_int64();
	}
}

inline void
getJsonIntField(const json::object &json, const string &key, int *result) {
	if (json.contains(key)) {
		*result = json.at(key).as_int64();
	}
}


inline unsigned int
getJsonUintField(const json::object &json, const json::string &key) {
	if (json.contains(key)) {
		return json.at(key).as_uint64();
	} else {
		throw VariantMap::MissingKeyException(key.c_str());
	}
}

inline unsigned int
getJsonUintField(const json::object &json, const json::string &key, unsigned int defaultValue) {
	if (json.contains(key)) {
		return json.at(key).as_uint64();
	} else {
		return defaultValue;
	}
}

inline void
getJsonUintField(const json::object &json, const json::string &key, unsigned int *result) {
	if (json.contains(key)) {
		*result = json.at(key).as_uint64();
	}
}

inline void
getJsonUintField(const json::object &json, const string &key, unsigned int *result) {
	if (json.contains(key)) {
		*result = json.at(key).as_uint64();
	}
}

inline boost::uint64_t
getJsonUint64Field(const json::object &json, const char *key) {
	if (json.contains(key)) {
		return json.at(key).as_uint64();
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline boost::uint64_t
getJsonUint64Field(const json::object &json, const char *key, unsigned int defaultValue) {
	if (json.contains(key)) {
		return json.at(key).as_uint64();
	} else {
		return defaultValue;
	}
}


inline bool
getJsonBoolField(const json::object &json, const char *key) {
	if (json.contains(key)) {
		return json.at(key).as_bool();
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline std::string
getJsonStringField(const json::object &json, const char *key) {
	if (json.contains(key)) {
		return json::value_to<std::string>(json.at(key));
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline const char*
getJsonCStringField(const json::object &json, const char *key) {
	if (json.contains(key)) {
		return json.at(key).get_string().c_str();
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline StaticString
getJsonStaticStringField(const json::object &json, const char *key) {
	if (json.contains(key)) {
		return json.at(key).get_string().c_str();
	} else {
		throw VariantMap::MissingKeyException(key);
	}
}

inline StaticString
getJsonStaticStringField(const json::object &json, const json::string &key) {
	if (json.contains(key)) {
		return json.at(key).get_string().c_str();
	} else {
		throw VariantMap::MissingKeyException(key.c_str());
	}
}

inline StaticString
getJsonStaticStringField(const json::object &json, const json::string &key,
	const StaticString &defaultValue)
{
	if (json.contains(key)) {
		return json.at(key).as_string().c_str();
	} else {
		return defaultValue;
	}
}

inline const json::object&
getJsonObjectField(const json::object &json, const json::string &key){
	if (json.contains(key)) {
		return json.at(key).get_object();
	} else {
		throw VariantMap::MissingKeyException(key.c_str());
	}
}

inline const json::value &
getJsonField(const json::value &json, const char *key) {
	return getJsonField(json.get_object(), key);
}

inline json::value &
getJsonField(json::value &json, const char *key) {
	return getJsonField(json.get_object(), key);
}

inline int
getJsonIntField(const json::value &json, const char *key) {
	return getJsonIntField(json.get_object(), key);
}

inline int
getJsonIntField(const json::value &json, const json::string &key) {
	return getJsonIntField(json.get_object(), key);
}

inline int
getJsonIntField(const json::value &json, const json::string &key, int defaultValue) {
	return getJsonIntField(json.get_object(), key);
}

inline void
getJsonIntField(const json::value &json, const json::string &key, int *result) {
	return getJsonIntField(json.get_object(), key, result);
}

inline void
getJsonIntField(const json::value &json, const string &key, int *result) {
	return getJsonIntField(json.get_object(), key, result);
}


inline unsigned int
getJsonUintField(const json::value &json, const json::string &key) {
	return getJsonUintField(json.get_object(), key);
}

inline unsigned int
getJsonUintField(const json::value &json, const json::string &key, unsigned int defaultValue) {
	return getJsonUintField(json.get_object(), key, defaultValue);
}

inline void
getJsonUintField(const json::value &json, const json::string &key, unsigned int *result) {
	return getJsonUintField(json.get_object(), key, result);
}

inline void
getJsonUintField(const json::value &json, const string &key, unsigned int *result) {
	return getJsonUintField(json.get_object(), key, result);
}

inline boost::uint64_t
getJsonUint64Field(const json::value &json, const char *key) {
	return getJsonUintField(json.get_object(), key);
}

inline boost::uint64_t
getJsonUint64Field(const json::value &json, const char *key, unsigned int defaultValue) {
	return getJsonUintField(json.get_object(), key, defaultValue);
}

inline bool
getJsonBoolField(const json::value &json, const char *key) {
	return getJsonBoolField(json.get_object(), key);
}

inline std::string
getJsonStringField(const json::value &json, const char *key) {
	return getJsonStringField(json.get_object(), key);
}

inline const char*
getJsonCStringField(const json::value &json, const char *key) {
	return getJsonCStringField(json.get_object(), key);
}

inline StaticString
getJsonStaticStringField(const json::value &json, const char *key) {
	return getJsonStaticStringField(json.get_object(), key);
}

inline StaticString
getJsonStaticStringField(const json::value &json, const json::string &key) {
	return getJsonStaticStringField(json.get_object(), key);
}

inline StaticString
getJsonStaticStringField(const json::value &json, const json::string &key,
	const StaticString &defaultValue)
{
	return getJsonStaticStringField(json.get_object(), key, defaultValue);
}

inline const json::object&
getJsonObjectField(const json::value &json, const json::string &key)
{
	return getJsonObjectField(json.get_object(), key);
}

inline string
jsonValueToString(const json::value &value) {
		switch (value.kind()) {
		case json::kind::null:
			return "";
		case json::kind::int64:
			return toString(value.as_int64());
		case json::kind::uint64:
			return toString(value.as_uint64());
		case json::kind::double_:
			return toString(value.as_double());
		case json::kind::string:
			return json::value_to<std::string>(value);
		case json::kind::bool_:
			if (value.as_bool()) {
				return "true";
			} else {
				return "false";
			}
		default:
			return json::serialize(value);
		}
}

/**************************************************************
 *
 * Methods for generating JSON.
 *
 **************************************************************/

/**
 * Returns a JSON document as its string representation.
 * This string is not prettified and does not contain a
 * trailing newline.
 *
 *     json::value doc;
 *     doc["foo"] = "bar";
 *     cout << stringifyJson(doc) << endl;
 *     // Prints:
 *     // {"foo": "bar"}
 */
inline string
stringifyJson(const json::value &value) {
	string str = json::serialize(value);
	//str.erase(str.size() - 1, 1);
	return str;
}

/**
 * Encodes the given string as a JSON string. `str` MUST be NULL-terminated!
 *
 *     cout << jsonString("hello \"user\"") << endl;
 *     // Prints:
 *     // "hello \"user\""
 */
inline string
jsonString(const Passenger::StaticString &str) {
	return stringifyJson(json::value(str.data()));
}

/**
 * Encodes the given Unix timestamp (in microseconds) into a JSON object that
 * describes it.
 *
 *     timeToJson((time(NULL) - 10) * 1000000.0);
 *     // {
 *     //   "timestamp": 1424887842,
 *     //   "local": "Wed Feb 25 19:10:34 CET 2015",
 *     //   "relative": "10s ago"
 *     // }
 */
inline json::value
timeToJson(unsigned long long timestamp, unsigned long long now = 0) {
	if (timestamp == 0) {
		return json::value(nullptr);
	}

	json::object doc;
	time_t wallClockTime = (time_t) (timestamp / 1000000ull);
	char wallClockTimeStr[32];
	size_t len;

	if (now == 0) {
		now = SystemTime::getUsec();
	}

	ctime_r(&wallClockTime, wallClockTimeStr);
	len = strlen(wallClockTimeStr);
	if (len > 0) {
		// Get rid of trailing newline
		wallClockTimeStr[len - 1] = '\0';
	}

	doc["timestamp"] = timestamp / 1000000.0;
	doc["local"] = wallClockTimeStr;
	if (timestamp > now) {
		doc["relative_timestamp"] = (timestamp - now) / 1000000.0;
		doc["relative"] = distanceOfTimeInWords(wallClockTime, now / 1000000ull) + " from now";
	} else {
		doc["relative_timestamp"] = (now - timestamp) / -1000000.0;
		doc["relative"] = distanceOfTimeInWords(wallClockTime, now / 1000000ull) + " ago";
	}

	return doc;
}

/**
 * Encodes the given monotonic timestamp into a JSON object that
 * describes it.
 *
 *     MonotonicTimeUsec t = SystemTime::getMonotonicUsec();
 *     monoTimeToJson(t - 10000000, t);
 *     // {
 *     //   "timestamp": 1424887842,
 *     //   "local": "Wed Feb 25 19:10:34 CET 2015",
 *     //   "relative_timestamp": -10,
 *     //   "relative": "10s ago"
 *     // }
 */
inline json::value
monoTimeToJson(MonotonicTimeUsec t, MonotonicTimeUsec monoNow, unsigned long long now = 0) {
	if (t == 0) {
		return json::value(nullptr);
	}

	if (now == 0) {
		now = SystemTime::getUsec();
	}

	unsigned long long wallClockTimeUsec;
	if (monoNow > t) {
		wallClockTimeUsec = now - (monoNow - t);
	} else {
		wallClockTimeUsec = now + (monoNow - t);
	}

	time_t wallClockTime = (time_t) (wallClockTimeUsec / 1000000ull);
	char timeStr[32], *ctimeResult;
	size_t len;
	ctimeResult = ctime_r(&wallClockTime, timeStr);
	if (ctimeResult != NULL) {
		len = strlen(timeStr);
		if (len > 0) {
			// Get rid of trailing newline
			timeStr[len - 1] = '\0';
		}
	}

	json::object doc;
	doc["timestamp"] = wallClockTimeUsec / 1000000.0;
	if (ctimeResult != NULL) {
		doc["local"] = timeStr;
	}
	if (t > monoNow) {
		doc["relative_timestamp"] = (t - monoNow) / 1000000.0;
		doc["relative"] = distanceOfTimeInWords(t / 1000000ull, monoNow / 1000000ull) + " from now";
	} else {
		doc["relative_timestamp"] = (monoNow - t) / -1000000.0;
		doc["relative"] = distanceOfTimeInWords(t / 1000000ull, monoNow / 1000000ull) + " ago";
	}
	return doc;
}

inline json::value
durationToJson(unsigned long long duration) {
	json::object doc;
	char buf[64];

	doc["microseconds"] = duration;
	if (duration >= 10 * 1000000) {
		snprintf(buf, sizeof(buf), "%.1fs", duration / 1000000.0);
	} else {
		snprintf(buf, sizeof(buf), "%.1fms", duration / 1000.0);
	}
	doc["human_readable"] = buf;

	return doc;
}

inline string
formatFloat(double val) {
	char buf[64];
	int size = snprintf(buf, sizeof(buf), "%.1f", val);
	return string(buf, size);
}

inline double
capFloatPrecision(double val) {
	char buf[64];
	snprintf(buf, sizeof(buf), "%.2f", val);
	return atof(buf);
}

inline json::value
speedToJson(double speed, const string &per, double nullValue = -1) {
	json::object doc;
	if (speed == nullValue) {
		doc["value"] = json::value(nullptr);
	} else {
		doc["value"] = speed;
	}
	doc["per"] = per;
	return doc;
}

inline json::value
averageSpeedToJson(double speed, const string &per, const string &averagedOver, double nullValue = -1) {
	json::object doc;
	if (speed == nullValue) {
		doc["value"] = json::value(nullptr);
	} else {
		doc["value"] = speed;
	}
	doc["per"] = per;
	doc["averaged_over"] = averagedOver;
	return doc;
}

inline json::value
byteSizeToJson(size_t size) {
	json::object doc;
	doc["bytes"] = size;
	if (size < 1024) {
		doc["human_readable"] = toString(size) + " bytes";
	} else if (size < 1024 * 1024) {
		doc["human_readable"] = formatFloat(size / 1024.0) + " KB";
	} else {
		doc["human_readable"] = formatFloat(size / 1024.0 / 1024.0) + " MB";
	}
	return doc;
}

inline json::value
signedByteSizeToJson(long long size) {
	json::object doc;
	long long absSize = (size < 0) ? -size : size;
	doc["bytes"] = size;
	if (absSize < 1024) {
		doc["human_readable"] = toString(size) + " bytes";
	} else if (absSize < 1024 * 1024) {
		doc["human_readable"] = formatFloat(size / 1024.0) + " KB";
	} else {
		doc["human_readable"] = formatFloat(size / 1024.0 / 1024.0) + " MB";
	}
	return doc;
}

inline json::value
byteSpeedToJson(double speed, const string &per) {
	json::value doc;
	if (speed >= 0) {
		doc = byteSizeToJson(llround(speed));
	} else {
		doc = signedByteSizeToJson(llround(speed));
	}
	doc.get_object()["per"] = per;
	return doc;
}

inline json::value
byteSpeedToJson(double speed, double nullValue, const string &per) {
	json::value doc;
	if (speed == nullValue) {
		doc = {{"bytes", json::value(nullptr)}};
	} else if (speed >= 0) {
		doc = byteSizeToJson(llround(speed));
	} else {
		doc = signedByteSizeToJson(llround(speed));
	}
	doc.get_object()["per"] = per;
	return doc;
}

inline json::value
byteSizeAndCountToJson(size_t size, unsigned int count) {
	json::value doc = byteSizeToJson(size);
	doc.get_object()["count"] = count;
	return doc;
}


} // namespace Passenger

#endif /* _PASSENGER_JSON_TOOLS_JSON_UTILS_H_ */
