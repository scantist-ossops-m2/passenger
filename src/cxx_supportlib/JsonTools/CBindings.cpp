/*
 *  Phusion Passenger - https://www.phusionpassenger.com/
 *  Copyright (c) 2017 Phusion Holding B.V.
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

#include <JsonTools/CBindings.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <boost/json.hpp>
#include <JsonTools/Autocast.h>
#include <Exceptions.h>

using namespace std;
using namespace Passenger;

extern "C" {


PsgJsonValue *
psg_json_value_new_null() {
	return new json::value();
}

PsgJsonValue *
psg_json_value_new_with_type(PsgJsonValueType type) {
	switch (type) {
	case PSG_JSON_VALUE_TYPE_NULL:
		return new json::value(nullptr);
	case PSG_JSON_VALUE_TYPE_INT:
		return new json::value(0);
	case PSG_JSON_VALUE_TYPE_UINT:
		return new json::value(0U);
	case PSG_JSON_VALUE_TYPE_REAL:
		return new json::value(0.0);
	case PSG_JSON_VALUE_TYPE_BOOLEAN:
		return new json::value(false);
	case PSG_JSON_VALUE_TYPE_STRING:
		return new json::string();
	case PSG_JSON_VALUE_TYPE_ARRAY:
		return new json::array();
	case PSG_JSON_VALUE_TYPE_OBJECT:
		return new json::object();
	default:
		fprintf(stderr, "BUG: Unrecognized PsgJsonValueType %d\n", (int) type);
		abort();
	}
}

PsgJsonValueType
psg_json_type(json::kind type) {
	switch (type) {
	case json::kind::null:
		return PSG_JSON_VALUE_TYPE_NULL;
	case json::kind::int64:
		return PSG_JSON_VALUE_TYPE_INT;
	case json::kind::uint64:
		return PSG_JSON_VALUE_TYPE_UINT;
	case json::kind::double_:
		return PSG_JSON_VALUE_TYPE_REAL;
	case json::kind::bool_:
		return PSG_JSON_VALUE_TYPE_BOOLEAN;
	case json::kind::string:
		return PSG_JSON_VALUE_TYPE_STRING;
	case json::kind::array:
		return PSG_JSON_VALUE_TYPE_ARRAY;
	case json::kind::object:
		return PSG_JSON_VALUE_TYPE_OBJECT;
	default:
		fprintf(stderr, "BUG: Unrecognized json::kind %d\n", (int) type);
		abort();
	}
}

json::kind
boost_json_type(PsgJsonValueType type) {
	switch (type) {
	case PSG_JSON_VALUE_TYPE_NULL:
		return json::kind::null;
	case PSG_JSON_VALUE_TYPE_INT:
		return json::kind::int64;
	case PSG_JSON_VALUE_TYPE_UINT:
		return json::kind::uint64;
	case PSG_JSON_VALUE_TYPE_REAL:
		return json::kind::double_;
	case PSG_JSON_VALUE_TYPE_BOOLEAN:
		return json::kind::bool_;
	case PSG_JSON_VALUE_TYPE_STRING:
		return json::kind::string;
	case PSG_JSON_VALUE_TYPE_ARRAY:
		return json::kind::array;
	case PSG_JSON_VALUE_TYPE_OBJECT:
		return json::kind::object;
	default:
		fprintf(stderr, "BUG: Unrecognized PsgJsonValueType %d\n", (int) type);
		abort();
	}
}


PsgJsonValue *
psg_json_value_new_str(const char *val, size_t size) {
	return new json::string(val, val + size);
}

PsgJsonValue *
psg_json_value_new_int(int val) {
	return new json::value(val);
}

PsgJsonValue *
psg_json_value_new_uint(unsigned int val) {
	return new json::value(val);
}

PsgJsonValue *
psg_json_value_new_real(double val) {
	return new json::value(val);
}

PsgJsonValue *
psg_json_value_new_bool(bool val) {
	return new json::value(val);
}

void
psg_json_value_free(PsgJsonValue *val) {
	delete (json::value *) val;
}


PsgJsonValue *
psg_json_value_get_or_create_null(PsgJsonValue *doc, const char *name, size_t size) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	if (size == (size_t) -1) {
		size = strlen(name);
	}
	return &cxxdoc[string(name, size)];
}

PsgJsonValue *
psg_json_value_get(PsgJsonValue *doc, const char *name, size_t size) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	if (size == (size_t) -1) {
		size = strlen(name);
	}
	if (cxxdoc.contains(json::string_view(name, name + size))) {
		return &cxxdoc[string(name, size)];
	} else {
		return NULL;
	}
}

PsgJsonValue *
psg_json_value_get_at_index(PsgJsonValue *doc, unsigned int index) {
	// if this crashes also handle objects & strings
	json::array &cxxdoc = *static_cast<json::array *>(doc);
	if (index >= cxxdoc.size()) {
		return NULL;
	} else {
		return &cxxdoc[index];
	}
}

PsgJsonValueType
psg_json_value_type(const PsgJsonValue *doc) {
	const json::value &cxxdoc = *static_cast<const json::value *>(doc);
	return psg_json_type(cxxdoc.kind());
}

int
psg_json_value_eq(const PsgJsonValue *doc, const PsgJsonValue *doc2) {
	const json::value &cxxdoc = *static_cast<const json::value *>(doc);
	const json::value &cxxdoc2 = *static_cast<const json::value *>(doc2);
	return cxxdoc == cxxdoc2;
}

int
psg_json_value_is_member(const PsgJsonValue *doc, const char *name, size_t size) {
	const json::object &cxxdoc = *static_cast<const json::object *>(doc);
	if (size == (size_t) -1) {
		size = strlen(name);
	}
	return cxxdoc.contains(json::string_view(name, name + size));
}

unsigned int
psg_json_value_size(const PsgJsonValue *doc) {
	json::kind type = static_cast<const json::value *>(doc)->kind();
	switch (type) {
	case json::kind::string: return static_cast<const json::string *>(doc)->size();
	case json::kind::array: return static_cast<const json::array *>(doc)->size();
	case json::kind::object: return static_cast<const json::object *>(doc)->size();
	default:
		fprintf(stderr, "BUG: attempted to get size of scalar PsgJsonValueType %d\n", (int) type);
		abort();
	}
}

PsgJsonValue *
psg_json_value_set_value(PsgJsonValue *doc, const char *name, size_t name_size, const PsgJsonValue *val) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	if (name_size == (size_t) -1) {
		name_size = strlen(name);
	}
	return &(cxxdoc[json::string_view(name, name_size)] = *static_cast<const json::value *>(val));
}

PsgJsonValue *
psg_json_value_set_str(PsgJsonValue *doc, const char *name, const char *val, size_t size) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	if (size == (size_t) -1) {
		size = strlen(val);
	}
	return &(cxxdoc[name] = json::string_view(val,size));
}

PsgJsonValue *
psg_json_value_set_int(PsgJsonValue *doc, const char *name, int val) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	return &(cxxdoc[name] = val);
}

PsgJsonValue *
psg_json_value_set_uint(PsgJsonValue *doc, const char *name, unsigned int val) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	return &(cxxdoc[name] = val);
}

PsgJsonValue *
psg_json_value_set_real(PsgJsonValue *doc, const char *name, double val) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	return &(cxxdoc[name] = val);
}

PsgJsonValue *
psg_json_value_set_bool(PsgJsonValue *doc, const char *name, bool val) {
	json::object &cxxdoc = *static_cast<json::object *>(doc);
	return &(cxxdoc[name] = val);
}

PsgJsonValue *
psg_json_value_append_val(PsgJsonValue *doc, const PsgJsonValue *val) {
	json::array &cxxdoc = *static_cast<json::array *>(doc);
	return &cxxdoc.emplace_back(*static_cast<const json::value *>(val));
}

void
psg_json_value_swap(PsgJsonValue *doc, PsgJsonValue *doc2) {
	json::value &cxxdoc = *static_cast<json::value *>(doc);
	json::value &cxxdoc2 = *static_cast<json::value *>(doc2);
	cxxdoc.swap(cxxdoc2);
}


int
psg_json_value_is_null(const PsgJsonValue *doc) {
	const json::value &cxxdoc = *static_cast<const json::value *>(doc);
	return cxxdoc.is_null();
}

int
psg_json_value_empty(const PsgJsonValue *doc) {
	json::kind type = static_cast<const json::value *>(doc)->kind();
	switch (type) {
	case json::kind::string: return static_cast<const json::string *>(doc)->empty();
	case json::kind::array:  return static_cast<const json::array *>(doc)->empty();
	case json::kind::object: return static_cast<const json::object *>(doc)->empty();
    default:
        fprintf(stderr, "BUG: attempted to check if scalar PsgJsonValueType %d is empty\n", (int) type);
		abort();
	}
}

const char *
psg_json_value_as_cstr(const PsgJsonValue *doc) {
	const json::value &cxxdoc = *static_cast<const json::value *>(doc);
	return cxxdoc.as_string().c_str();
}

const char *
psg_json_value_get_str(const PsgJsonValue *doc, size_t *size) {
	const json::value &cxxdoc = *static_cast<const json::value *>(doc);
	if (cxxdoc.is_string()) {
		const json::string& s = cxxdoc.as_string();
		*size = s.size();
		return s.c_str();
	} else {
		return NULL;
	}
}

PsgJsonValueType
psg_json_value_begin(PsgJsonValue *doc, PsgJsonValueIterator **it) {
	json::kind type = static_cast<const json::value *>(doc)->kind();

	switch (type) {
    case json::kind::string:
        *it = const_cast<char*>(static_cast<const json::string *>(doc)->begin());
		return psg_json_type(type);
	case json::kind::array:
		*it = const_cast<json::value*>(static_cast<const json::array *>(doc)->begin());
		return psg_json_type(type);
	case json::kind::object:
		*it = const_cast<json::key_value_pair*>(static_cast<const json::object *>(doc)->begin());
		return psg_json_type(type);
	default:
        fprintf(stderr, "BUG: attempted to get iterator of scalar PsgJsonValueType %d\n", (int) type);
		abort();
	}
}

void
psg_json_value_end(PsgJsonValue *doc, PsgJsonValueIterator **it) {
	json::kind type = static_cast<const json::value *>(doc)->kind();

	switch (type) {
    case json::kind::string:
        *it = const_cast<char*>(static_cast<const json::string *>(doc)->end());
		break;
	case json::kind::array:
		*it = const_cast<json::value*>(static_cast<const json::array *>(doc)->end());
		break;
	case json::kind::object:
		*it = const_cast<json::key_value_pair*>(static_cast<const json::object *>(doc)->end());
		break;
	default:
        fprintf(stderr, "BUG: attempted to get iterator of scalar PsgJsonValueType %d\n", (int) type);
		abort();
	}
}


char *
psg_json_value_to_styled_string(const PsgJsonValue *doc) {
	const json::value &cxxdoc = *static_cast<const json::value *>(doc);
	return strdup(json::serialize(cxxdoc).c_str());
}


PsgJsonValue *
psg_autocast_value_to_json(const char *data, size_t size, char **error) {
	return new json::value(autocastValueToJson(StaticString(data, size)));
}

void
psg_json_value_iterator_advance(PsgJsonValueIterator **it, PsgJsonValueType type) {
	switch(type){
	case PSG_JSON_VALUE_TYPE_STRING:
		(*reinterpret_cast<json::string::iterator *>(it))++;
		break;
	case PSG_JSON_VALUE_TYPE_ARRAY:
		(*reinterpret_cast<json::array::iterator *>(it))++;
		break;
	case PSG_JSON_VALUE_TYPE_OBJECT:
		(*reinterpret_cast<json::object::iterator *>(it))++;
		break;
	default:
        fprintf(stderr, "BUG: attempted to use iterator of scalar PsgJsonValueType %d\n", (int) type);
		abort();
	}
}

int
psg_json_value_iterator_eq(PsgJsonValueIterator *it, PsgJsonValueIterator *other, PsgJsonValueType type) {
	json::string::iterator *strit1;
	json::array::iterator *arrit1;
	json::object::iterator *objit1;
	json::string::iterator *strit2;
	json::array::iterator *arrit2;
	json::object::iterator *objit2;

	switch(type){
	case PSG_JSON_VALUE_TYPE_STRING:
		strit1 = static_cast<json::string::iterator *>(it);
		strit2 = static_cast<json::string::iterator *>(other);
		return *strit1 == *strit2;
	case PSG_JSON_VALUE_TYPE_ARRAY:
		arrit1 = static_cast<json::array::iterator *>(it);
		arrit2 = static_cast<json::array::iterator *>(other);
		return *arrit1 == *arrit2;
	case PSG_JSON_VALUE_TYPE_OBJECT:
		objit1 = static_cast<json::object::iterator *>(it);
		objit2 = static_cast<json::object::iterator *>(other);
		return *objit1 == *objit2;
	default:
        fprintf(stderr, "BUG: attempted to use iterator of scalar PsgJsonValueType %d\n", (int) type);
		abort();
	}
}

const char *
psg_json_value_iterator_get_name(PsgJsonValueIterator *it, size_t *size) {
	json::object::iterator &cxxit = *static_cast<json::object::iterator *>(it);
	json::string_view result = cxxit->key();
	*size = result.size();
	return result.data();
}

PsgJsonValue *
psg_json_value_iterator_get_value(PsgJsonValueIterator *it) {
	json::object::iterator &cxxit = *static_cast<json::object::iterator *>(it);
	return &cxxit->value();
}


} // extern "C"
